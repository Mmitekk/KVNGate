# VPN Gate Auto v5 — быстрый перебор адресов SoftEther VPN Gate.
#
# Логика:
#  1. Параллельный TCP-зонд батчами по 48 (было: 200+ одновременных коннектов —
#     не хватало сокетов, «живых» выходило 1 вместо 33).
#  2. Перебор только живых по TCP — SoftEther к каждому подключается за ~15 с.
#  3. known-good имеет приоритет над known-bad (доказанный сервер не выкидывается).
#  4. Профиль НЕ удаляется между попытками (удаление рвёт внутренние ретраи SoftEther).
#  5. Чужие (пользовательские) сессии НЕ трогаем; при живой чужой сессии — выходим.
#  6. -KeepAlive: демон, который переподключает сессию, если её оборвал кто-то
#     извне (SoftEther пишет «code 6 — canceled by user», маршрут падает на
#     провайдера, интернет снова российский).
#
# Примеры:
#   vpn-auto.ps1                      — подобрать рабочий сервер
#   vpn-auto.ps1 -KeepAlive           — подобрать и следить, переподключаться
#   vpn-auto.ps1 -TcpProbeTimeoutMs 3000 -ConnectTimeoutSec 45
#   vpn-auto.ps1 -Country JP,KR
#   vpn-auto.ps1 -Disconnect          — отключиться (только наши профили)
#   vpn-auto.ps1 -Force               — подобрать заново, даже если уже подключено

param(
    [string]$VpncmdPath = '',
    [string]$Country = '',
    [string]$ExcludeCountry = 'RU',
    [string]$ExcludeIp = '219.100.37.*,218.100.37.*',
    [double]$MinSpeedMbps = 1,
    [int]$MaxSessions = 500,
    [string]$Ports = '443,5555,992',
    [int]$ConnectTimeoutSec = 30,   # ждать подключения к одному серверу (SoftEther: 1-я попытка ~15 с, успех с ретрая ~30 с)
    [int]$MaxFallbackMin = 40,      # общий бюджет перебора, минут
    [int]$TcpProbeTimeoutMs = 2500,
    [int]$KeepAliveSec = 20,         # как часто проверять сессию в режиме -KeepAlive
    [switch]$NoTcpProbe,
    [switch]$KeepAlive,               # ВЫКЛЮЧЕН по умолчанию: без него скрипт
                                      # подбирает сервер и выходит, ничего не оставляя
                                      # подключённым и не поднимая демон.
    [switch]$Force,
    [switch]$Disconnect,
    [switch]$Status,
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}
try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}

# ---------- самоповышение прав ----------
#
# Нужно для Protect-AgentRoute: прибить /32-маршруты к API-адресам агента
# на физический интерфейс, чтобы переключение VPN не рвало связь агента.
# New-NetRoute требует прав администратора.
#
# ВАЖНО: при запуске через `-File script.ps1 -Disconnect` PowerShell
# разбирает ключи в блок param, и $args остаётся ПУСТЫМ. Старая версия
# передавала elevated-копии только $args — из-за чего -Disconnect
# терялся, и elevated-копия вместо отключения ПОДКЛЮЧАЛА VPN заново.
# Поэтому параметры собираем явно.
if (-not $env:VPNGATE_NO_ELEVATE -and -not $Status) {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $self = $MyInvocation.MyCommand.Path
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $self + '"'))
        if ($Disconnect)           { $argList += '-Disconnect' }
        if ($Force)                { $argList += '-Force' }
        if ($KeepAlive)            { $argList += '-KeepAlive' }
        if ($NoTcpProbe)           { $argList += '-NoTcpProbe' }
        if ($Quiet)                { $argList += '-Quiet' }
        if ($Country)              { $argList += @('-Country', $Country) }
        if ($ExcludeCountry)       { $argList += @('-ExcludeCountry', $ExcludeCountry) }
        if ($ExcludeIp)            { $argList += @('-ExcludeIp', $ExcludeIp) }
        if ($Ports)                { $argList += @('-Ports', $Ports) }
        if ($ConnectTimeoutSec -ne 30) { $argList += @('-ConnectTimeoutSec', $ConnectTimeoutSec) }
        if ($KeepAliveSec -ne 20)      { $argList += @('-KeepAliveSec', $KeepAliveSec) }
        if ($TcpProbeTimeoutMs -ne 2500) { $argList += @('-TcpProbeTimeoutMs', $TcpProbeTimeoutMs) }
        if ($MaxFallbackMin -ne 40)    { $argList += @('-MaxFallbackMin', $MaxFallbackMin) }
        if ($MinSpeedMbps -ne 1)       { $argList += @('-MinSpeedMbps', $MinSpeedMbps) }
        if ($MaxSessions -ne 500)      { $argList += @('-MaxSessions', $MaxSessions) }
        if ($VpncmdPath)               { $argList += @('-VpncmdPath', ('"' + $VpncmdPath + '"')) }
        try {
            Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -WindowStyle Hidden | Out-Null
            exit 0
        } catch {
            Write-Host "Не удалось повысить права: $($_.Exception.Message)"
            Write-Host 'Без прав скрипт работает, но не сможет защитить канал агента от обрывов.'
        }
    }
}

$AccountName = 'VPNGATE_AUTO'
$Hub         = 'VPNGATE'
$CacheDir    = Join-Path $env:LOCALAPPDATA 'VPNGateAuto'
$CacheFile   = Join-Path $CacheDir 'last-list.csv'
$KnownFile   = Join-Path $CacheDir 'known-good.txt'
$BadFile     = Join-Path $CacheDir 'known-bad.txt'
$LogFile     = Join-Path $CacheDir 'last-run.log'
$Utf8NoBom   = New-Object System.Text.UTF8Encoding($false)

$script:LogLines = New-Object System.Collections.ArrayList
function Msg([string]$s) {
    Write-Host $s
    try {
        [void]$script:LogLines.Add($s)
        [System.IO.File]::AppendAllText($LogFile, $s + "`r`n", $Utf8NoBom)
    } catch {}
}
function Save-Log {
    try { [System.IO.File]::WriteAllText($LogFile, (($script:LogLines -join "`r`n") + "`r`n"), $Utf8NoBom) } catch {}
}

# ---------- vpncmd ----------

function Invoke-VpnCmd([string[]]$Commands) {
    if (-not $Commands -or $Commands.Count -eq 0) { return '' }
    try {
        if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
        $inFile  = Join-Path $CacheDir '_vpnc_in.txt'
        $outFile = Join-Path $CacheDir '_vpnc_out.txt'
        $lines = @()
        foreach ($c in $Commands) {
            if ($null -eq $c) { continue }
            $t = ($c -replace "`r?`n", ' ').Trim()
            if ($t) { $lines += $t }
        }
        if (-not $lines.Count) { return '' }
        [System.IO.File]::WriteAllText($inFile, (($lines -join "`r`n") + "`r`n"), $Utf8NoBom)
        if (Test-Path $outFile) { Remove-Item $outFile -Force -ErrorAction SilentlyContinue }
        $inner  = '"' + $script:Vpncmd + '" localhost /CLIENT /CMD < "' + $inFile + '" > "' + $outFile + '" 2>&1'
        $cmdLine = '"' + $inner + '"'
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $env:ComSpec
        $psi.Arguments = '/c ' + $cmdLine
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        if (-not $proc.WaitForExit(20000)) {
            try { $proc.Kill() } catch {}
            return ''
        }
        $null = $proc.StandardOutput.ReadToEnd()
        $null = $proc.StandardError.ReadToEnd()
        if (Test-Path $outFile) { return [System.IO.File]::ReadAllText($outFile, [System.Text.Encoding]::UTF8) }
        return ''
    } catch { "EXCEPTION: $($_.Exception.Message)" }
}

# ---------- сеть ----------

function Get-HttpText([string]$Url, [int]$TimeoutSec = 20) {
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $text = $sr.ReadToEnd(); $sr.Close(); $resp.Close()
        $text
    } catch { $null }
}

function Get-IpFromText([string]$Text) {
    if (-not $Text) { return $null }
    $m = [regex]::Match($Text, '\b\d{1,3}(?:\.\d{1,3}){3}\b')
    if ($m.Success) { return $m.Value }
    return $null
}

function Get-ExitInfo {
    foreach ($u in @('http://ip-api.com/line/?fields=query,country,isp', 'http://api.ipify.org/')) {
        $r = Get-HttpText $u 10
        if (-not $r) { continue }
        $t = $r.Trim()
        $ip = Get-IpFromText $t
        if (-not $ip) { continue }
        $country = ''
        if ($t -match '\|\s*([A-Za-z]{2})\s*\|') { $country = $Matches[1].Trim() }
        return [pscustomobject]@{ Ip = $ip; Country = $country; Raw = ($t -replace "`r?`n", ' / ') }
    }
    return $null
}

# Параллельный TCP-зонд: батчами по 48 одновременных коннектов.
#
# ВАЖНО 1: используем ConnectAsync + Task.WaitAll, а не BeginConnect +
# WaitHandle.WaitAll — последний падает на коллекции ManualResetEvent
# («Значение не может быть неопределенным») и молча возвращает «0 живых».
#
# ВАЖНО 2: НЕЛЬЗЯ открывать все 200+ коннектов сразу — не хватает сокетов,
# и результат вырождается в 1 «живой» адрес. Батчами по 48 — получаем
# честные ~33 живых адреса за ~25 с.
function Test-TcpMany($Endpoints, [int]$TimeoutMs) {
    $open = New-Object System.Collections.ArrayList
    $batchSize = 48
    $list = @($Endpoints)
    for ($off = 0; $off -lt $list.Count; $off += $batchSize) {
        $end = [Math]::Min($off + $batchSize, $list.Count)
        $chunk = $list[$off..($end - 1)]
        $clients = New-Object System.Collections.ArrayList
        $tasks   = New-Object System.Collections.ArrayList
        $items   = New-Object System.Collections.ArrayList
        foreach ($ep in $chunk) {
            if (-not $ep -or -not $ep.Ip) { continue }
            $t = New-Object System.Net.Sockets.TcpClient
            try {
                $t.NoDelay = $true
                $tk = $t.ConnectAsync($ep.Ip, [int]$ep.Port)
                [void]$clients.Add($t); [void]$tasks.Add($tk); [void]$items.Add($ep)
            } catch { try { $t.Close() } catch {} }
        }
        if ($tasks.Count -gt 0) {
            $arr = [System.Threading.Tasks.Task[]]$tasks.ToArray()
            # ВАЖНО: WaitAll возвращает $true — если не заглушить, он попадёт
            # в выходной поток функции и «разбавит» результат (было: «живых 1»
            # и пустые поля вместо адресов).
            try { [void][System.Threading.Tasks.Task]::WaitAll($arr, $TimeoutMs) } catch {}
            for ($i = 0; $i -lt $arr.Count; $i++) {
                try {
                    if ($arr[$i].Status -eq 'RanToCompletion' -and $clients[$i].Connected) {
                        [void]$open.Add($items[$i])
                    }
                } catch {}
            }
        }
        foreach ($t in $clients) { try { $t.Close() } catch {} }
    }
    return $open
}

# ---------- состояние аккаунтов ----------

function Get-AccountStates {
    $states = @{}
    $out = Invoke-VpnCmd @('AccountList')
    if (-not $out -or $out -match 'Error occurred|EXCEPTION') { return $states }
    $cur = $null
    foreach ($line in ($out -split "`r?`n")) {
        $norm = ($line -replace '^\s+|\s+$', '') -replace '\s*\|\s*', '|'
        if ($norm -match '^VPN Connection Setting Name\|(.+)') { $cur = $Matches[1].Trim(); if (-not $states.ContainsKey($cur)) { $states[$cur] = '' } }
        elseif ($norm -match '^Status\|(.+)' -and $cur) { $states[$cur] = $Matches[1].Trim() }
    }
    return $states
}

function Test-SessionUp([string]$Status) { return ($Status -eq 'Connected' -or $Status -eq 'Online') }

# ---------- known good / bad ----------

function Read-Endpoints([string]$Path) {
    if (-not (Test-Path $Path)) { return @() }
    $out = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($l in @(Get-Content $Path -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        $t = ($l -replace '\s', '')
        if ($t -match '^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):(\d{1,5})$') {
            $ep = "$($Matches[1]):$([int]$Matches[2])"
            if (-not $seen.ContainsKey($ep)) { $seen[$ep] = $true; [void]$out.Add($ep) }
        }
    }
    # порядок файла сохраняем: свежие/рабочие — сверху
    return @($out.ToArray())
}

function Write-Endpoints([string]$Path, $List) {
    try { [System.IO.File]::WriteAllText($Path, ((@($List) -join "`r`n") + "`r`n"), $Utf8NoBom) } catch {}
}

function Add-KnownGood([string]$Ep) {
    $list = @(Read-Endpoints $KnownFile | Where-Object { $_ -ne $Ep })
    $list = @($Ep) + $list
    if ($list.Count -gt 50) { $list = $list[0..49] }
    Write-Endpoints $KnownFile $list
    # сервер доказанно рабочий → убираем его из чёрного списка
    $bad = @(Read-Endpoints $BadFile | Where-Object { $_ -ne $Ep })
    Write-Endpoints $BadFile $bad
}

function Add-KnownBad([string]$Ep) {
    $list = @(Read-Endpoints $BadFile | Where-Object { $_ -ne $Ep })
    $list = @($Ep) + $list
    if ($list.Count -gt 200) { $list = $list[0..199] }
    Write-Endpoints $BadFile $list
}

# ---------- исключения по подсети ----------

$script:Excludes = @($ExcludeIp.Split(',; ') | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('.*') })
function Test-Excluded([string]$Ip) {
    foreach ($e in $script:Excludes) { if ($Ip.StartsWith($e)) { return $true } }
    return $false
}

# ---------- старт ----------

Msg "VPN Gate Auto v5 — перебор SoftEther VPN Gate, $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Msg ''

if (-not $VpncmdPath) {
    $cand = @(
        'I:\Program Files (x86)\SoftEther VPN Client\vpncmd_x64.exe',
        'I:\Program Files (x86)\SoftEther VPN Client\vpncmd.exe',
        "$env:ProgramFiles\SoftEther VPN Client\vpncmd_x64.exe",
        "${env:ProgramFiles(x86)}\SoftEther VPN Client\vpncmd_x64.exe",
        'C:\Program Files\SoftEther VPN Client\vpncmd.exe',
        'C:\Program Files\SoftEther VPN Client\vpncmd_x64.exe'
    )
    $VpncmdPath = $cand | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $VpncmdPath) { Msg 'Не найден vpncmd_x64.exe (SoftEther VPN Client).'; Save-Log; exit 1 }
$script:Vpncmd = $VpncmdPath
Msg "» SoftEther: $VpncmdPath"

$svc = Get-Service | Where-Object { $_.Name -in 'SEVPNCLIENT', 'vpnclient' } | Select-Object -First 1
if ($svc -and $svc.Status -ne 'Running') {
    Msg "» Запускаю службу $($svc.Name)…"
    try { Start-Service $svc.Name -ErrorAction Stop } catch { Msg "  не удалось: $($_.Exception.Message)" }
}

# ---------- список серверов ----------

function Test-ValidCsv([string]$t) { return ($t -and $t -match '\r?\n[^*#\r\n]+,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3},') }

$listTexts = @()
$gotOfficial = $false
foreach ($u in @('https://www.vpngate.net/api/iphone/', 'http://www.vpngate.net/api/iphone/')) {
    $t = Get-HttpText $u 8
    if (Test-ValidCsv $t) { $listTexts += $t; $gotOfficial = $true; break }
}
Msg ("» Официальный API VPN Gate: " + $(if ($gotOfficial) { 'доступен' } else { 'недоступен из РФ — беру зеркало' }))
foreach ($u in @(
    'https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv',
    'https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/data/vpngate.csv'
)) {
    $t = Get-HttpText $u 20
    if (Test-ValidCsv $t) { $listTexts += $t; break }
}
if (-not $listTexts -and (Test-Path $CacheFile)) {
    Msg "! Сеть недоступна — сохранённый список: $CacheFile"
    $t = Get-Content $CacheFile -Raw -Encoding UTF8
    if (Test-ValidCsv $t) { $listTexts += $t }
}
if (-not $listTexts) { Msg 'Не удалось получить список серверов VPN Gate.'; Save-Log; exit 1 }
try {
    if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($CacheFile, ($listTexts -join "`r`n"), [System.Text.Encoding]::UTF8)
} catch {}

# ---------- разбор ----------

$portList = @($Ports.Split(',; ') | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
if (-not $portList) { $portList = @(443, 5555, 992) }

$rows = @()
$seenIp = @{}
foreach ($text in $listTexts) {
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -eq '' -or $line[0] -eq '*' -or $line[0] -eq '#') { continue }
        $f = $line.Split(',')
        if ($f.Count -lt 8) { continue }
        $ip = $f[1].Trim()
        if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { continue }
        if ($seenIp.ContainsKey($ip)) { continue }
        $seenIp[$ip] = $true
        $rows += [pscustomobject]@{
            Host      = $f[0]
            Ip        = $ip
            Score     = [long]($f[2] -as [long])
            SpeedMbps = [math]::Round(($f[4] -as [double]) / 1000000.0, 0)
            CountryL  = $f[5]
            CountryS  = $f[6].ToUpper()
            Sessions  = [int]($f[7] -as [int])
        }
    }
}
Msg "» Уникальных серверов в списке: $($rows.Count)"

if ($script:Excludes.Count -gt 0) {
    $before = $rows.Count
    $rows = @($rows | Where-Object { -not (Test-Excluded $_.Ip) })
    Msg "» Исключены подсети $($ExcludeIp -replace '\*',''): убрано $($before - $rows.Count)"
}
if ($Country) {
    $want = $Country.ToUpper().Split(',; ') | Where-Object { $_ }
    $rows = @($rows | Where-Object { $want -contains $_.CountryS })
    if (-not $rows) { Msg "Нет серверов для стран: $($want -join ', ')"; Save-Log; exit 1 }
    Msg "» Фильтр стран ($($want -join ', ')): $($rows.Count)"
}
if ($ExcludeCountry) {
    $exc = @($ExcludeCountry.ToUpper().Split(',; ') | Where-Object { $_ })
    $before = $rows.Count
    $rows = @($rows | Where-Object { $exc -notcontains $_.CountryS })
    if ($before -gt $rows.Count) { Msg "» Исключены страны ($($exc -join ', ')): убрано $($before - $rows.Count)" }
}

$pool = @($rows | Where-Object { $_.SpeedMbps -ge $MinSpeedMbps -and $_.Sessions -le $MaxSessions })
if (-not $pool) { Msg 'Нет серверов под условия. Ослабьте: -MinSpeedMbps 1 -MaxSessions 999'; Save-Log; exit 1 }

# ---------- защита канала агента ----------
#
# Подключение VPN переключает default-route на адаптер SoftEther. Агент,
# который этим скриптом управляется, ходит в API по тому же интернету —
# и на переключении его соединение рвётся (пользователь наблюдает это как
# «VPN отключает агента»).
#
# Решение — РАЗДЕЛЕНИЕ МАРШРУТОВ:
#   • /32 к API-адресам агента  → Wi-Fi (или Ethernet 2, если Wi-Fi нет).
#     /32 всегда точнее 0.0.0.0/0, поэтому трафик агента идёт напрямую и
#     переживает любые переключения VPN. Пользовательский трафик при этом
#     по-прежнему идёт через VPN — как и задумано.
#   • /32 к IP VPN-сервера     → Ethernet 2 (транспорт туннеля по проводу),
#     чтобы сам туннель не закручивался сам в себя и не уходил на Wi-Fi.

$script:AgentIface = $null
function Get-AgentInterface {
    if ($script:AgentIface) { return $script:AgentIface }
    # приоритет: Wi-Fi (он не задействован в VPN), иначе проводной
    $wifi = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { ($_.InterfaceAlias -match 'Беспроводная|Wireless|Wi-Fi| WLAN') -and $_.IPAddress -notmatch '^169\.254\.' } |
        Select-Object -First 1
    if ($wifi) { $script:AgentIface = $wifi; return $wifi }
    $eth = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -notmatch 'VPN|Radmin|TAP|TUN' -and $_.IPAddress -notmatch '^169\.254\.' } |
        Select-Object -First 1
    $script:AgentIface = $eth
    return $eth
}

function Protect-AgentRoute {
    try {
        $eth = Get-AgentInterface
        if (-not $eth) { return 0 }
        $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $eth.InterfaceIndex } | Select-Object -First 1).NextHop
        if (-not $gw) { return 0 }

        # адреса, куда ходит локальный агент:
        #  - текущие TCP-соединения процессов MiniMax Code / node
        #  - плюс A-records API-хостов (CDN-адреса ротируются, а /32 нужен
        #    именно на тот IP, по которому реально идёт TLS)
        $agentPids = @(Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -match 'MiniMax|node' } | Select-Object -ExpandProperty Id)
        $targets = New-Object System.Collections.ArrayList
        if ($agentPids.Count) {
            Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Where-Object { $agentPids -contains $_.OwningProcess -and $_.RemotePort -eq 443 } |
                Select-Object -ExpandProperty RemoteAddress -Unique |
                ForEach-Object { [void]$targets.Add($_) }
        }
        foreach ($hostName in @('api.minimaxi.com','api.minimax.io','api.minimaxi.chat')) {
            try {
                Resolve-DnsName $hostName -Type A -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique |
                    ForEach-Object { [void]$targets.Add($_) }
            } catch {}
        }
        if (-not $targets.Count) { return 0 }

        $added = 0
        # 1) точные /32 на каждый известный адрес
        foreach ($ip in @($targets | Sort-Object -Unique)) {
            $have = Get-NetRoute -DestinationPrefix "$ip/32" -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $eth.InterfaceIndex }
            if (-not $have) {
                New-NetRoute -DestinationPrefix "$ip/32" -InterfaceIndex $eth.InterfaceIndex -NextHop $gw -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                $added++
            }
        }
        # 2) плюс /24 вокруг каждого — CDN-адреса ротируются, и без этого
        #    новый IP из той же сети успевает уехать в туннель (и сменить
        #    мой внешний IP прямо посреди TLS-сессии → обрыв связи)
        #
        #    /16 целиком НЕ вешаем: Akamai/Alibaba — это YouTube, Telegram,
        #    Discord и почти весь интернет. Перехват /16 уводил
        #    пользовательский трафик мимо VPN.
        foreach ($ip in @($targets | Sort-Object -Unique)) {
            if ($ip -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') { continue }
            $net = "$($Matches[1]).0/24"
            $have = Get-NetRoute -DestinationPrefix $net -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $eth.InterfaceIndex }
            if (-not $have) {
                New-NetRoute -DestinationPrefix $net -InterfaceIndex $eth.InterfaceIndex -NextHop $gw -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                $added++
            }
        }
        return $added
    } catch { return 0 }
}

# DNS на туннельном адаптере — приравниваем к физическому.
#
# ГЛАВНАЯ ПРИЧИНА ОБРЫВА СЕССИИ АГЕНТА. SoftEther прописывает на
# виртуальный адаптер DNS-сервер VPN-сервера. Адаптер VPN2 имеет
# InterfaceMetric 1 (ниже физических), поэтому Windows отправляет через
# него ВЕСЬ DNS системы. Резолв api.minimaxi.com начинает идти к CDN в
# стране VPN → агент подключается к другому адресу → его исходящий IP
# меняется → сервер рвёт сессию.
#
# Решение: DNS туннеля = DNS физического адаптера (роутер провайдера).
# Тогда ответы DNS одинаковы при любом пути, CDN-IP не меняется, и
# исходящий IP агента остаётся российским.
function Protect-TunnelDns {
    try {
        $phys = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -match 'Беспроводная|Wireless|Wi-Fi|^Ethernet' -and
                           $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 })
        if (-not $phys) { return 0 }
        $want = @($phys[0].ServerAddresses)
        $fixed = 0
        $tunnels = @(Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$' })
        foreach ($t in $tunnels) {
            $cur = @(Get-DnsClientServerAddress -InterfaceIndex $t.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
            $same = ($cur.Count -eq $want.Count)
            if ($same) {
                for ($i = 0; $i -lt $want.Count; $i++) {
                    if ($cur[$i] -ne $want[$i]) { $same = $false; break }
                }
            }
            if ($same) { continue }
            Set-DnsClientServerAddress -InterfaceIndex $t.ifIndex -ServerAddresses $want -ErrorAction SilentlyContinue
            $fixed++
        }
        return $fixed
    } catch { return 0 }
}

# Транспорт VPN-сервера — по проводному (Ethernet 2), чтобы туннель не ушёл
# на Wi-Fi и не закручивался сам в себя.
function Pin-VpnTransport([string]$ServerIp) {
    try {
        if (-not $ServerIp) { return 0 }
        # запоминаем текущий сервер: route-guard.ps1 не должен снести /32
        # к нему (иначе туннель уйдёт сам в себя)
        try { [System.IO.File]::WriteAllText((Join-Path $CacheDir 'current-server.txt'), $ServerIp, $Utf8NoBom) } catch {}
        $wire = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -match '^Ethernet' -and $_.IPAddress -notmatch '^169\.254\.' } |
            Select-Object -First 1
        if (-not $wire) { return 0 }
        $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $wire.InterfaceIndex } | Select-Object -First 1).NextHop
        if (-not $gw) { return 0 }
        $have = Get-NetRoute -DestinationPrefix "$ServerIp/32" -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $wire.InterfaceIndex }
        if ($have) { return 0 }
        New-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceIndex $wire.InterfaceIndex -NextHop $gw -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
        return 1
    } catch { return 0 }
}

# ---------- route-guard ----------
#
# Основной «починитель» схемы «агент → Wi-Fi, VPN → Ethernet 2»:
#   • убирает дубли маршрутов агента с провода (Ethernet 2 с метрикой 25
#     всегда выигрывал у Wi-Fi с метрикой 35),
#   • прибивает живые адреса агента на Wi-Fi (новый CDN-IP иначе уезжал
#     в туннель → менялся исходящий IP → рвалась сессия агента),
#   • снимает DNS с туннельного адаптера (иначе весь резолв идёт через
#     VPN и CDN-адреса агента меняются),
#   • чинит мёртвые default-route через отключённые SoftEther-адаптеры.
#
# Никаких подключений VPN он не делает — только маршруты.
$script:GuardPath = Join-Path $PSScriptRoot 'route-guard.ps1'
function Invoke-RouteGuard {
    try {
        if (-not (Test-Path $script:GuardPath)) { return '' }
        $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script:GuardPath -NoElevate 2>&1
        $last = ($out | Where-Object { $_ -match '^\[\d\d:\d\d:\d\d\]' } | Select-Object -Last 1)
        if ($last) { return ($last -replace '^\[\d\d:\d\d:\d\d\]\s*', '') }
        return ''
    } catch { return '' }
}

# Запуск watchdog'а маршрутов в фоне.
#
# Он работает, пока поднят VPN, и сам останавливается, когда VPN выключен
# (три проверки подряд без туннеля). Ничего не подключает и не трогает
# сессии SoftEther — только чинит таблицу маршрутов.
function Start-RouteGuardDaemon {
    try {
        if (-not (Test-Path $script:GuardPath)) { return 0 }
        # не плодим копии: если watchdog уже есть — второй не нужен
        $running = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like '*route-guard*' })
        if ($running.Count) { return 0 }
        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $script:GuardPath + '"'),
                  '-Watch', '-IntervalSec', '2', '-NoElevate')
        Start-Process -FilePath 'powershell.exe' -ArgumentList $args -WindowStyle Hidden | Out-Null
        return 1
    } catch { return 0 }
}

# Остановка watchdog'а (нужен при отключении VPN — он сам бы гас, но
# процесс мог остаться висеть на пару секунд).
function Stop-RouteGuardDaemon {
    try {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -like '*route-guard*' })
        foreach ($p in $procs) {
            try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch {}
        }
        return $procs.Count
    } catch { return 0 }
}
Protect-AgentRoute | Out-Null

# ---------- починка маршрутов ----------
#
# ГЛАВНАЯ ПРИЧИНА «VPN ОТКЛЮЧАЕТ АГЕНТА/ПОЛЬЗОВАТЕЛЯ»:
# SoftEther при разрыве сессии оставляет в таблице default-route через
# отключённый адаптер (например «VPN - VPN Client», RouteMetric 1,
# InterfaceMetric 1 → эффективная метрика 2). У физического Ethernet 2
# эффективная метрика 25. То есть МЁРТВЫЙ маршрут перебивает рабочий, и
# весь трафик (интернет пользователя и связь с агентом) уходит в никуда.
#
# Лечится: убрать default-route через отключённые SoftEther-адаптеры и
# гарантировать рабочий маршрут через физический интерфейс. Нужны права
# администратора — скрипт сам повышается (UAC).
function Repair-Routes {
    $fixed = 0
    try {
        # 1) убрать мёртвые маршруты через отключённые SoftEther-адаптеры
        $softIfaces = @(Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$' })
        foreach ($ad in $softIfaces) {
            if ($ad.Status -eq 'Up') { continue }
            $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $ad.ifIndex })
            foreach ($r in $routes) {
                Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -Confirm:$false -ErrorAction SilentlyContinue
                $fixed++
            }
        }
        # 2) гарантировать рабочий default через физический интерфейс
        $phys = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -notmatch 'VPN|Radmin|TAP|TUN' -and $_.IPAddress -notmatch '^169\.254\.' } |
            Select-Object -First 1
        if ($phys) {
            $have = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $phys.InterfaceIndex })
            if (-not $have) {
                $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceAlias -eq $phys.InterfaceAlias } | Select-Object -First 1).NextHop
                if (-not $gw) { $gw = $phys.PrefixOrigin }
                New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $phys.InterfaceIndex -NextHop $gw -RouteMetric 0 -ErrorAction SilentlyContinue | Out-Null
                $fixed++
            }
        }
    } catch {}
    return $fixed
}

# ---------- отключение (только свои профили) ----------

if ($Disconnect) {
    $states = Get-AccountStates
    $mine = @($states.Keys | Where-Object { $_ -eq $AccountName -or $_ -like 'VPNGATE_AUTO_*' })
    $mineUp = @($mine | Where-Object { Test-SessionUp $states[$_] })
    if ($mineUp.Count -gt 0) {
        Msg "» Отключаю свои профили: $($mineUp -join ', ')"
        Invoke-VpnCmd ($mineUp | ForEach-Object { "AccountDisconnect $_" }) | Out-Null
    } else { Msg '» Активных профилей VPNGATE_AUTO нет.' }
    # гасим адаптер и убираем его default-route: отключённый адаптер с
    # метрикой 1 перебивает рабочий маршрут и уводит весь трафик в никуда
    Start-Sleep -Seconds 2
    $nics = @()
    foreach ($line in ((Invoke-VpnCmd @('NicList')) -split "`r?`n")) {
        $norm = ($line -replace '^\s+|\s+$', '') -replace '\s*\|\s*', '|'
        if ($norm -match '^Virtual Network Adapter Name\|(.+)') { $nics += $Matches[1].Trim() }
    }
    foreach ($n in $nics) {
        if ($n -eq 'VPN') { continue }   # первый адаптер не трогаем (GUI)
        Invoke-VpnCmd "NicDisable $n" | Out-Null
    }
    Repair-Routes | Out-Null
    Protect-AgentRoute | Out-Null
    Invoke-RouteGuard | Out-Null
    Stop-RouteGuardDaemon | Out-Null
    Msg 'Отключено (пользовательские профили не тронуты).'
    Save-Log; exit 0
}

# ---------- режим -Status ----------
#
# Показывает текущее состояние без изменений: поднят ли VPN, какой внешний
# IP, через какой интерфейс реально идёт трафик агента и в порядке ли
# таблица маршрутов. Нужен, чтобы за секунду понять «VPN работает? агент
# в туннеле или нет?» — без гадания по логам.
if ($Status) {
    Write-Host ''
    Write-Host '════ Состояние VPN Gate Auto ════'
    Write-Host ''

    # 1) сессия SoftEther
    $vpncmd = $VpncmdPath
    if (-not $vpncmd) { $vpncmd = 'I:\Program Files (x86)\SoftEther VPN Client\vpncmd_x64.exe' }
    $acctState = 'нет клиента SoftEther'
    if (Test-Path $vpncmd) {
        $out = & $vpncmd localhost /CLIENT /CMD AccountList 2>&1 | Out-String
        $cur = ''
        foreach ($line in ($out -split "`r?`n")) {
            $norm = ($line -replace '^\s+|\s+$', '') -replace '\s*\|\s*', '|'
            if ($norm -match '^VPN Connection Setting Name\|(.+)') { $cur = $Matches[1].Trim() }
            elseif ($norm -match '^Status\|(.+)') { if ($cur -eq $AccountName) { $acctState = $Matches[1].Trim() } }
        }
    }
    Write-Host ("Сессия SoftEther : {0} ({1})" -f $AccountName, $acctState)

    # 2) внешний IP
    $ext = Get-ExitInfo
    if ($ext) { Write-Host ("Внешний IP        : {0} {1}" -f $ext.Ip, $ext.Country) }
    else { Write-Host 'Внешний IP        : не определился' }

    # 3) интерфейсы
    Write-Host ''
    Write-Host 'Интерфейсы:'
    foreach ($a in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
        if ($a.Status -ne 'Up') { continue }
        $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1).IPAddress
        $metric = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue).InterfaceMetric
        Write-Host ("  [{0,3}] {1,-24} {2,-16} метрика {3}" -f $a.ifIndex, $a.Name, $ip, $metric)
    }

    # 4) default-route — кто сейчас забирает весь трафик
    Write-Host ''
    Write-Host 'Маршрут по умолчанию:'
    foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
        $m = (Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceMetric
        $eff = $r.RouteMetric + $m
        Write-Host ("  {0,-24} шлюз {1,-14} эффективная метрика {2}" -f $r.InterfaceAlias, $r.NextHop, $eff)
    }

    # 5) где реально сидит трафик агента
    Write-Host ''
    $agentPids = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match 'MiniMax|node' } | Select-Object -ExpandProperty Id)
    $conns = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $agentPids -contains $_.OwningProcess })
    $tunnel = @{}
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -match ' - VPN Client$|VPN Client Adapter|TAP|TUN' } |
        ForEach-Object { $tunnel[$_.IPAddress] = $_.InterfaceAlias }

    $byLocal = @{}
    foreach ($c in $conns) {
        $k = $c.LocalAddress
        if (-not $byLocal.ContainsKey($k)) { $byLocal[$k] = 0 }
        $byLocal[$k]++
    }
    Write-Host 'Соединения агента (MiniMax Code):'
    $leak = 0
    foreach ($k in ($byLocal.Keys | Sort-Object)) {
        $n = $byLocal[$k]
        if ($tunnel.ContainsKey($k)) {
            $leak += $n
            Write-Host ("  {0,-16} {1,3} соедин.  ⚠ ЧЕРЕЗ ТУННЕЛЬ ({2})" -f $k, $n, $tunnel[$k]) -ForegroundColor Red
        } else {
            $alias = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -eq $k } | Select-Object -First 1).InterfaceAlias
            Write-Host ("  {0,-16} {1,3} соедин.  через {2}" -f $k, $n, $alias) -ForegroundColor Green
        }
    }
    if ($byLocal.Count -eq 0) { Write-Host '  (соединений сейчас нет)' }

    Write-Host ''
    if ($leak -gt 0) {
        Write-Host '⚠ Часть трафика агента идёт через туннель — сессия может оборваться.' -ForegroundColor Red
        Write-Host '  Исправить: запустите route-guard.ps1 (он поднимет права через UAC).' -ForegroundColor Yellow
    } else {
        Write-Host '✔ Агент полностью вне туннеля — сессия стабильна.' -ForegroundColor Green
    }
    exit 0
}

# ---------- состояние сейчас ----------

$states = Get-AccountStates
$mine   = @($states.Keys | Where-Object { $_ -eq $AccountName -or $_ -like 'VPNGATE_AUTO_*' })
$mineUp = @($mine | Where-Object { Test-SessionUp $states[$_] })
$foreignUp = @($states.Keys | Where-Object { $_ -notin $mine -and (Test-SessionUp $states[$_]) })

# ищем, не идёт ли сейчас трафик через SoftEther-адаптер (может быть GUI-сессия,
# которой нет в AccountList — например, подключение через плагин VPN Gate)
$defRoute = $null
try {
    $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
} catch {}
$softEtherUp = $false
if ($defRoute -and $defRoute.InterfaceAlias -match ' - VPN Client$') { $softEtherUp = $true }

# ---------- прямой IP (без VPN) ----------
#
# Нужен, чтобы отличать «интернет через VPN» от «интернет мимо VPN».
# Кэшируем: когда default-route НЕ через SoftEther — текущий внешний IP и есть
# прямой. Иначе берём из кэша (под VPN прямой IP узнать нельзя).

$DirectIpFile = Join-Path $CacheDir 'direct-ip.txt'
function Get-DirectIp {
    $cached = $null
    if (Test-Path $DirectIpFile) { $cached = (Get-Content $DirectIpFile -Raw -Encoding UTF8).Trim() }
    $def = $null
    try {
        $def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    } catch {}
    $viaVpn = $def -and ($def.InterfaceAlias -match ' - VPN Client$')
    if (-not $viaVpn) {
        $cur = Get-ExitInfo
        if ($cur -and $cur.Ip) {
            try { [System.IO.File]::WriteAllText($DirectIpFile, $cur.Ip, $Utf8NoBom) } catch {}
            return $cur.Ip
        }
    }
    return $cached
}
$directIpGuess = Get-DirectIp

if ($foreignUp.Count -gt 0) {
    Msg "» У вас работает чужая сессия SoftEther: $($foreignUp -join ', ')"
    Msg '  Я её не трогаю. Подбор нового сервера её оборвёт — выходите.'
    Save-Log; exit 2
}

# Моя сессия уже поднята? Тогда SoftEther-маршрут в default-route — это
# мой собственный VPN, а не чужая сессия. Раньше здесь скрипт путал одно с
# другим и выходил с кодом 2, не запуская KeepAlive.
if ($mineUp.Count -gt 0 -and -not $Force) {
    $info = Get-ExitInfo
    $mineAlive = $info -and (-not $directIpGuess) -and ($info.Ip -ne $directIpGuess)
    if ($mineAlive) {
        Msg "» Моё подключение уже активно: $($mineUp -join ', ')"
        Msg "  Внешний адрес: $($info.Ip) $($info.Country)"
        if ($KeepAlive) {
            Msg '  Перехожу в режим KeepAlive.'
            # переходим вниз к циклу KeepAlive, не переподключаясь заново
            $script:ReuseExisting = $true
        } else {
            Msg '  Сменить сервер: -Force. Отключить: -Disconnect.'
            Save-Log; exit 0
        }
    } else {
        Msg "» Моя сессия поднята, но интернет через неё не идёт — переподключаюсь."
        Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
    }
}
if (-not $script:ReuseExisting -and $softEtherUp -and -not $Force) {
    Msg "» Трафик сейчас идёт через SoftEther-адаптер ($($defRoute.InterfaceAlias))."
    Msg '  Подбор нового сервера перехватит маршрут. Для замены укажите -Force.'
    Save-Log; exit 2
}

# ---------- базовый IP ----------

Msg ''
$base = Get-ExitInfo
$directIp = if ($base) { $base.Ip } else { $null }
Msg "» Прямой IP до подключения: $(if ($directIp) { $directIp } else { 'неизвестен' })"

# ---------- порядок перебора ----------

$goodList = @(Read-Endpoints $KnownFile)
$badList  = @(Read-Endpoints $BadFile)
$badSet   = @{}
foreach ($b in $badList) { $badSet[$b] = $true }
$goodSet  = @{}
foreach ($g in $goodList) { $goodSet[$g] = $true }

$byIp = @{}
foreach ($r in $rows) { $byIp[$r.Ip] = $r }

# 1) доказанно рабочие — вперёд (known-good важнее known-bad)
$ranked = New-Object System.Collections.ArrayList
$addedEp = @{}
foreach ($g in $goodList) {
    $ip   = $g.Split(':')[0]
    $port = [int]$g.Split(':')[1]
    $row = $byIp[$ip]
    if (-not $row) {
        $row = [pscustomobject]@{ Host = 'known-good'; Ip = $ip; Score = 0; SpeedMbps = 0; CountryL = '?'; CountryS = '??'; Sessions = 0 }
    }
    $addedEp[$g] = $true
    [void]$ranked.Add([pscustomobject]@{ Srv = $row; Ip = $ip; Port = $port; Known = $true })
}

# 2) остальные — страны чередуются, внутри страны по score
$queues = @{}
foreach ($s in ($pool | Sort-Object -Property Score -Descending)) {
    if (-not $queues.ContainsKey($s.CountryS)) { $queues[$s.CountryS] = New-Object System.Collections.ArrayList }
    [void]$queues[$s.CountryS].Add($s)
}
$inter = New-Object System.Collections.ArrayList
$remaining = $pool.Count
while ($remaining -gt 0) {
    $added = $false
    foreach ($key in @($queues.Keys)) {
        $q = $queues[$key]
        if ($q.Count -gt 0) { [void]$inter.Add($q[0]); $q.RemoveAt(0); $remaining--; $added = $true }
    }
    if (-not $added) { break }
}
foreach ($s in $inter) {
    foreach ($p in $portList) {
        $ep = "$($s.Ip):$p"
        if ($badSet.ContainsKey($ep) -and -not $goodSet.ContainsKey($ep)) { continue }
        # дедупликация: known-good уже добавил этот endpoint
        if ($addedEp.ContainsKey($ep)) { continue }
        $addedEp[$ep] = $true
        [void]$ranked.Add([pscustomobject]@{ Srv = $s; Ip = $s.Ip; Port = $p; Known = $false })
    }
}

Msg ''
Msg "══ Кандидатов: $($ranked.Count) (из них известно-рабочих: $(@($ranked | Where-Object { $_.Known }).Count)) ══"

# ---------- параллельный TCP-зонд ----------

$candidates = @($ranked)
if (-not $NoTcpProbe) {
    $t0 = Get-Date
    $alive = @(Test-TcpMany $candidates $TcpProbeTimeoutMs)
    $el = [int]((Get-Date) - $t0).TotalSeconds
    Msg "» TCP-зонд ($($candidates.Count) адресов, ${el} с): живых $((@($alive)).Count)"
    if ($alive.Count) {
        $candidates = @($alive)
    } else {
        Msg '  Ни один порт не отвечает — пробую без фильтра.'
    }
    # known-good всегда идём первыми, даже если TCP-зонд их не увидел
    $candidates = @(@($candidates | Where-Object { $_.Known }) + @($candidates | Where-Object { -not $_.Known }))
}

# ---------- подготовка профиля ----------

# Один профиль, один адаптер, строго последовательно.
# Параллельные сессии SoftEther конфликтуют за default-route и рвут
# пользовательские соединения — поэтому никакого параллелизма тут.
# SoftEther принимает только имена адаптеров вида VPN / VPN2 / VPN3 …
# «VPN» (первый) не трогаем — на нём может висеть GUI-сессия.

$acct = $AccountName
$states = Get-AccountStates

if ($script:ReuseExisting) {
    # моя сессия уже жива — профиль НЕ трогаем (пересоздание оборвало бы её)
    $nic = $null
    $srvLine = (Invoke-VpnCmd @('AccountList')) -split "`r?`n" |
        Where-Object { $_ -match 'VPN Server Hostname' } | Select-Object -First 1
    $acct = $AccountName
    $nic = 'VPN2'
    foreach ($line in ((Invoke-VpnCmd @('AccountList')) -split "`r?`n")) {
        $norm = ($line -replace '^\s+|\s+$', '') -replace '\s*\|\s*', '|'
        if ($norm -match '^Virtual Network Adapter Name\|(.+)') { $nic = $Matches[1].Trim() -replace ' - VPN Client$','' }
    }
    Msg "» Использую уже поднятую сессию $acct (адаптер $nic)"
} else {

# удаляем наши старые профили (чужие не трогаем)
$cleanup = New-Object System.Collections.ArrayList
foreach ($n in @($states.Keys | Where-Object { $_ -eq $AccountName -or $_ -like 'VPNGATE_AUTO_*' })) {
    [void]$cleanup.Add("AccountDisconnect $n")
    [void]$cleanup.Add("AccountDelete $n")
}
if ($cleanup.Count) { Invoke-VpnCmd ($cleanup.ToArray()) | Out-Null }

# выбираем адаптер: переиспользуем VPN2/VPN3… если они есть, иначе создаём
$nicListOut = Invoke-VpnCmd @('NicList')
$allNics = @()
foreach ($line in ($nicListOut -split "`r?`n")) {
    $norm = ($line -replace '^\s+|\s+$', '') -replace '\s*\|\s*', '|'
    if ($norm -match '^Virtual Network Adapter Name\|(.+)') { $allNics += $Matches[1].Trim() }
}
$nic = $null
for ($i = 2; $i -le 40; $i++) {
    $c = "VPN$i"
    if ($allNics -contains $c) { $nic = $c; break }
}
if (-not $nic) {
    for ($i = 2; $i -le 40; $i++) { $c = "VPN$i"; if ($allNics -notcontains $c) { $nic = $c; break } }
    if ($nic) { Invoke-VpnCmd "NicCreate $nic" | Out-Null }
}
if (-not $nic) { $nic = 'VPN2'; Invoke-VpnCmd "NicCreate $nic" | Out-Null }

# ВАЖНО: адаптер должен быть включён. После отключения VPN (или после
# ручного выключения в «Сетевых подключениях») он остаётся Disabled, и
# SoftEther не может поднять на нём сессию — Status навсегда Offline.
Invoke-VpnCmd "NicEnable $nic" | Out-Null

Invoke-VpnCmd "AccountCreate $acct /SERVER:1.1.1.1:443 /HUB:$Hub /USERNAME:vpn /NICNAME:$nic" | Out-Null
Invoke-VpnCmd "AccountNicSet $acct /NICNAME:$nic" | Out-Null
Invoke-VpnCmd "AccountAnonymousSet $acct" | Out-Null
Invoke-VpnCmd "AccountServerCertDisable $acct" | Out-Null
Invoke-VpnCmd "AccountStatusHide $acct" | Out-Null
Invoke-VpnCmd "AccountRetrySet $acct /NUM:999 /INTERVAL:1" | Out-Null
Invoke-VpnCmd "AccountDetailSet $acct /NOQOS:yes /MAXTCP:1 /INTERVAL:1" | Out-Null

$vfy = Invoke-VpnCmd @('AccountList')
$curAcct = ''; $nicOfAcct = ''
foreach ($line in ($vfy -split "`r?`n")) {
    $norm = ($line -replace '^\s+|\s+$', '') -replace '\s*\|\s*', '|'
    if ($norm -match '^VPN Connection Setting Name\|(.+)') { $curAcct = $Matches[1].Trim() }
    elseif ($norm -match '^Virtual Network Adapter Name\|(.+)' -and $curAcct -eq $acct) { $nicOfAcct = $Matches[1].Trim() }
}
if ($nicOfAcct -ne $nic) {
    Msg "  ⚠ профиль на адаптере '$nicOfAcct' вместо '$nic' — исправляю…"
    Invoke-VpnCmd "AccountNicSet $acct /NICNAME:$nic" | Out-Null
}
Msg "» Профиль $acct на адаптере $nic"
}   # конец блока «иначе» (не ReuseExisting)

# ---------- перебор ----------

function Test-Exit([string]$DirectIp) {
    $info = $null
    foreach ($d in @(2, 3, 4)) {
        Start-Sleep -Seconds $d
        $info = Get-ExitInfo
        if ($info) { break }
    }
    if (-not $info) { return $null }
    if ($DirectIp -and $info.Ip -eq $DirectIp) { return $null }
    return $info
}

$timeBudget = (Get-Date).AddMinutes($MaxFallbackMin)
$attempt = 0
$ok = $null; $okPort = 0; $ext = $null

if ($script:ReuseExisting) {
    # сессия уже поднята — перебор не нужен, сразу в KeepAlive
    $ok = [pscustomobject]@{ Host = 'текущий'; Ip = '?'; CountryL = '?'; SpeedMbps = 0 }
    $ext = Get-ExitInfo
    $okPort = 443
}

foreach ($ep in $candidates) {
    if ($ok) { break }
    if ((Get-Date) -gt $timeBudget) { Msg "  бюджет ${MaxFallbackMin} мин исчерпан"; break }

    $s = $ep.Srv
    $label = if ($ep.Known) { "$($s.Host) [проверен]" } else { "$($s.Host) ($($s.CountryL))" }
    $attempt++
    Msg ("[{0}/{1}] {2} {3}:{4}" -f $attempt, $candidates.Count, $label, $ep.Ip, $ep.Port)

    # мягко гасим предыдущую попытку, затем переключаем сервер
    Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
    # транспорт VPN-сервера — по проводному (Ethernet 2), чтобы туннель не ушёл
    # на Wi-Fi и не закрутился сам в себя. Делаем ДО подключения.
    Pin-VpnTransport $ep.Ip | Out-Null
    Invoke-VpnCmd "AccountSet $acct /SERVER:$($ep.Ip):$($ep.Port) /HUB:$Hub" | Out-Null
    Invoke-VpnCmd "AccountConnect $acct" | Out-Null

    $online = $false
    $deadline = (Get-Date).AddSeconds($ConnectTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 1000
        $st = Get-AccountStates
        if ($st.ContainsKey($acct) -and (Test-SessionUp $st[$acct])) { $online = $true; break }
    }

    if (-not $online) {
        Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
        Add-KnownBad "$($ep.Ip):$($ep.Port)"
        Msg '  ✖ не поднялся — следующий'
        continue
    }

    # Ждём реальный адрес на адаптере. Сразу после Connected DHCP ещё не
    # выдал адрес (адаптер остаётся 169.254.x.x) — ждём до 20 с.
    # Раньше проверка была мгновенной, и живые серверы отбрасывались как
    # «пустые сессии».
    #
    # ВАЖНО: в Windows адаптер называется «VPN2 - VPN Client», а не «VPN2» —
    # точное сравнение InterfaceAlias -eq 'VPN2' никогда не срабатывало.
    $hasRealIp = $false
    $vpnIp = ''
    $ipDeadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $ipDeadline) {
        try {
            $ipObj = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceAlias -like "$nic *" -and $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -ne '0.0.0.0' } |
                Select-Object -First 1
            if ($ipObj) { $hasRealIp = $true; $vpnIp = $ipObj.IPAddress; break }
        } catch {}
        Start-Sleep -Milliseconds 800
    }

    if (-not $hasRealIp) {
        Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
        Add-KnownBad "$($ep.Ip):$($ep.Port)"
        Msg '  ✖ пустая сессия (адаптер без адреса) — следующий'
        continue
    }

    # ---- СРАЗУ чиним DNS туннеля ----
    #
    # SoftEther прописывает на туннельный адаптер DNS VPN-сервера, а его
    # InterfaceMetric = 1 (ниже физических) → весь DNS системы уходит в
    # туннель. Тогда резолв api.minimaxi.com возвращает CDN-IP страны VPN,
    # агент открывает к нему новое соединение, его исходящий IP меняется —
    # и сервер рвёт сессию («The model connection was interrupted»).
    #
    # Здесь важна скорость: окно между подключением SoftEther и этим
    # проходом — секунды, и именно в него успевал произойти «плохой»
    # резолв. Поэтому чиним ДО проверки выхода, а не после.
    Protect-TunnelDns | Out-Null

    $info = Test-Exit $directIp
    if (-not $info) {
        Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
        Add-KnownBad "$($ep.Ip):$($ep.Port)"
        Msg '  ✖ интернет не идёт через VPN — следующий'
        continue
    }

    Add-KnownGood "$($ep.Ip):$($ep.Port)"
    $ok = $s; $okPort = $ep.Port; $ext = $info
    # после подключения маршруты агента надо прибить заново — VPN только что
    # перехватил default-route
    $fixed = Protect-AgentRoute
    if ($fixed) { Msg "  защита канала агента: прибито $fixed маршрут(ов)" }
    # полный проход route-guard: снимает дубли с Ethernet 2, чинит
    # мёртвые маршруты, приравнивает DNS туннеля к физическому
    $guard = Invoke-RouteGuard
    if ($guard) { Msg "  route-guard: $guard" }
    # запускаем watchdog маршрутов: пока VPN поднят, он каждые 2 секунды
    # ловит новые CDN-адреса агента и прибивает их на Wi-Fi. Без него
    # новый адрес (ротация Akamai/Alibaba) успевал уехать в туннель —
    # и сессия агента рвалась.
    Start-RouteGuardDaemon | Out-Null
    Msg "  ✔ интернет через VPN: $($info.Ip) $($info.Country)"
    break
}

# ---------- итог ----------

if ($ok) {
    Msg ''
    Msg "Подключено к VPN Gate"
    Msg "Сервер:      $($ok.Host) ($($ok.CountryL))"
    Msg "Адрес:       $($ok.Ip):$okPort"
    Msg "Внешний IP:  $($ext.Ip) $($ext.Country)"
    Msg "Профиль:     $acct (адаптер $nic)"
    Msg "Сменить сервер: -Force. Отключить: -Disconnect."
    Save-Log

    # ---------- режим -KeepAlive ----------
    #
    # Сессию может оборвать кто-то извне (SoftEther в логе пишет
    # «Disconnecting … code 6 — canceled by user»): GUI-менеджер, другой
    # VPN-клиент, переключение сети. Тогда маршрут падает обратно на
    # провайдера, а интернет снова российский. Демон это чинит: раз в
    # $KeepAliveSec секунд проверяет сессию и переподключает, если её нет.
    #
    # Чужие (пользовательские) профили не трогаем никогда.
    if ($KeepAlive) {
        Msg ''
        Msg "Режим KeepAlive: слежу за сессией, переподключаюсь при обрыве. Ctrl+C — выход."
        $lastGood = "$($ok.Ip):$okPort"
        $reconnects = 0
        $missed = 0
        while ($true) {
            Start-Sleep -Seconds $KeepAliveSec
            try {
                # 1) чиним мёртвые маршруты: если SoftEther оставил default-route
                #    через отключённый адаптер, весь трафик уходит в никуда
                #    (эфф. метрика 2 против 25 у Ethernet) — и интернет, и связь
                #    с агентом пропадают.
                $rf = Repair-Routes
                if ($rf) { Msg "[keepalive] починено маршрутов: $rf" }

                # 2) прибиваем канал агента к физическому интерфейсу
                $fixed = Protect-AgentRoute
                if ($fixed) { Msg "[keepalive] защита канала: прибито $fixed маршрут(ов)" }

                # 2a) полный проход route-guard: дубли с провода, DNS туннеля,
                #     мёртвые маршруты. Без этого агент уезжает в туннель.
                $g = Invoke-RouteGuard
                if ($g) { Msg "[keepalive] route-guard: $g" }

                $st = Get-AccountStates
                $up = $st.ContainsKey($acct) -and (Test-SessionUp $st[$acct])

                # ГЛАВНОЕ ПРАВИЛО: если SoftEther говорит «Connected» — сессия
                # жива, и НИЧЕГО делать нельзя. Раньше проверка внешнего IP
                # решала, жив ли туннель; но ip-api.com rate-limit и отдавал
                # null → скрипт считал это обрывом и вызывал AccountConnect
                # поверх работающей сессии. SoftEther при этом гасил её
                # («code 6 — canceled by user»), рвался default-route, и весь
                # трафик (включая связь с этим агентом) пропадал на минуту.
                if ($up) { $missed = 0; continue }

                # сессия реально Offline. Два пропуска подряд — чтобы не
                # реагировать на секундное «Connecting».
                $missed++
                if ($missed -lt 2) { continue }
                $missed = 0

                $reconnects++
                Msg "[keepalive] сессия Offline — переподключаюсь (попытка $reconnects)…"
                Invoke-VpnCmd "AccountConnect $acct" | Out-Null

                $up2 = $false
                $dl = (Get-Date).AddSeconds($ConnectTimeoutSec)
                while ((Get-Date) -lt $dl) {
                    Start-Sleep -Milliseconds 1000
                    $st2 = Get-AccountStates
                    if ($st2.ContainsKey($acct) -and (Test-SessionUp $st2[$acct])) { $up2 = $true; break }
                }
                if ($up2) {
                    $inf2 = $null
                    for ($d = 0; $d -lt 4; $d++) { Start-Sleep -Seconds 2; $inf2 = Get-ExitInfo; if ($inf2) { break } }
                    $desc = if ($inf2) { "$($inf2.Ip) $($inf2.Country)" } else { 'сессия поднята' }
                    Msg "[keepalive] ✔ восстановлено: $desc"
                    Save-Log
                    continue
                }
                Msg '[keepalive] не восстановилось, пробую другой сервер…'
                Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
                Invoke-VpnCmd "AccountSet $acct /SERVER:$lastGood /HUB:$Hub" | Out-Null
                Invoke-VpnCmd "AccountConnect $acct" | Out-Null
            } catch {
                Msg "[keepalive] ошибка: $($_.Exception.Message)"
            }
        }
    }
    exit 0
} else {
    Invoke-VpnCmd "AccountDisconnect $acct" | Out-Null
    Msg ''
    Msg "Не удалось подключиться. Проверено: $attempt"
    Msg 'Попробуйте позже (фильтрация меняется), -Country JP,KR,US или -ConnectTimeoutSec 60.'
    Save-Log
    exit 1
}
