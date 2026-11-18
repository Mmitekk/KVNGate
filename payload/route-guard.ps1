<#
    route-guard.ps1 — watchdog маршрутов: раздельная политика для агентов.

    ЗАЧЕМ:
    1) Агент, которому нужен ПРЯМОЙ интернет (мимо VPN), не должен рваться
       при переключении. Для него маршруты к его API прибиваются на Wi-Fi.
    2) Агент, которому нужен VPN, должен ходить через туннель.
    3) Никто из агентов не должен «уезжать» в туннель случайно.

    КАК ЭТО РАБОТАЕТ:
    Windows маршрутизирует по адресу назначения, а не по процессу. Скрипт
    смотрит живые TCP-соединения защищаемых процессов, узнаёт реальные
    адреса назначения и вешает на них маршруты согласно политике:
        direct → /32 и /24 (плюс /16 сетей CDN агента) на Wi-Fi
        vpn    → /32 на туннельный адаптер, но ТОЛЬКО если этот адрес
                 перекрыт Wi-Fi-маршрутом direct-агента (иначе конфликта
                 нет и хватает обычного default-route через туннель)

    ЖЕЛЕЗНЫЕ ПРАВИЛА (нарушение = падение туннеля):
    • Адрес самого VPN-сервера (транспорт SoftEther) НИКОГДА не прибивается
      на туннель — иначе туннель уходит сам в себя и умирает.
    • На Wi-Fi не трогаются маршруты, созданные не этим скриптом: всё, что
      скрипт создал, он записывает в managed-routes.txt и чистит только там.

    ПОЛИТИКА (файл %LOCALAPPDATA%\VPNGateAuto\agent-policies.txt):
        <шаблон>   <режим>
    Шаблон — подстрока имени процесса (без .exe) ИЛИ его полного пути,
    либо суффикс домена. Режим — direct (Wi-Fi) или vpn (через туннель).
    Агент, не упомянутый в файле, получает режим по умолчанию (DEFAULT_MODE).

    Использование:
      powershell -ExecutionPolicy Bypass -File route-guard.ps1              # один проход
      powershell -ExecutionPolicy Bypass -File route-guard.ps1 -Watch        # демон
#>
[CmdletBinding()]
param(
    [switch]$Watch,
    [int]$IntervalSec = 5,
    [switch]$NoElevate,
    # Разделение программ по адаптерам делает TrafikRuler. С этим ключом
    # watchdog чинит только DNS и мёртвые default-маршруты, а маршруты
    # по IP не создаёт.
    [switch]$NoAppSplit
)

$ErrorActionPreference = 'Continue'
$Utf8 = New-Object System.Text.UTF8Encoding($false)

# ---------- защита от дублей ----------
#
# У повышенных процессов CommandLine в WMI пустой, поэтому определить
# дубль по нему нельзя. Используем PID-файл: если в нём живой процесс —
# второй экземпляр не нужен.
$script:PidFile = Join-Path $env:LOCALAPPDATA 'VPNGateAuto\route-guard.pid'
function Test-GuardRunning {
    try {
        if (-not (Test-Path $script:PidFile)) { return $false }
        $pidTxt = (Get-Content $script:PidFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($pidTxt -notmatch '^\d+$') { return $false }
        if (Get-Process -Id ([int]$pidTxt) -ErrorAction SilentlyContinue) { return $true }
        return $false
    } catch { return $false }
}

# ---------- самоповышение ----------
if (-not $NoElevate) {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $env:VPNGATE_NO_ELEVATE = '1'
        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'), '-NoElevate')
        if ($Watch) { $argList += '-Watch' }
        if ($IntervalSec -ne 5) { $argList += @('-IntervalSec', "$IntervalSec") }
        try {
            Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop
            exit 0
        } catch {
            Write-Host "Не удалось получить права администратора: $($_.Exception.Message)"
            exit 1
        }
    }
}

$CacheDir = Join-Path $env:LOCALAPPDATA 'VPNGateAuto'
if (-not (Test-Path $CacheDir)) { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null }
$LogFile     = Join-Path $CacheDir 'route-guard.log'
$PolicyFile  = Join-Path $CacheDir 'agent-policies.txt'
$ManagedFile = Join-Path $CacheDir 'managed-routes.txt'

function Write-GuardLog([string]$Text) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text
    Write-Host $line
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch {}
}

# ---------- управляемые маршруты ----------
#
# Скрипт ведёт список созданных им маршрутов, чтобы:
#   • чистить только свои (чужие маршруты пользователя не трогаем),
#   • знать, какой Wi-Fi-маршрут перекрывает адрес vpn-агента.
$script:Managed = @{}   # "prefix|ifIndex" -> $true

function Load-Managed {
    $script:Managed = @{}
    if (-not (Test-Path $ManagedFile)) { return }
    foreach ($l in @(Get-Content $ManagedFile -Encoding UTF8 -ErrorAction SilentlyContinue)) {
        $t = $l.Trim()
        if (-not $t) { continue }
        if ($t -match '^(.+?)\|(\d+)$') { $script:Managed["$($Matches[1])|$($Matches[2])"] = $true }
    }
}

function Save-Managed {
    try {
        $lines = @($script:Managed.Keys | Sort-Object)
        [System.IO.File]::WriteAllText($ManagedFile, (($lines -join "`r`n") + "`r`n"), $Utf8)
    } catch {}
}

# ---------- политика ----------
#
# Встроенные значения:
#   • MiniMax Code (этот агент) → direct: его нельзя рвать, ему нужен
#     стабильный российский исходящий IP.
#   • Всё остальное → vpn (режим по умолчанию).

# Политик по умолчанию больше нет: приложения без VPN задаются правилами
# TrafikRuler. Файл agent-policies.txt остаётся только для совместимости
# и явного DEFAULT_MODE.
$script:DefaultPolicy = @()
$script:DefaultMode = 'vpn'

function Get-Policies {
    $list = New-Object System.Collections.ArrayList
    foreach ($p in $script:DefaultPolicy) { [void]$list.Add($p) }

    if (Test-Path $PolicyFile) {
        foreach ($l in @(Get-Content $PolicyFile -Encoding UTF8 -ErrorAction SilentlyContinue)) {
            $t = ($l -replace '#.*$', '').Trim()
            if (-not $t) { continue }
            if ($t -match '^(?i)DEFAULT_MODE\s+(\w+)\s*$') { $script:DefaultMode = $Matches[1].ToLower(); continue }
            if ($t -match '^(.+?)\s+(direct|vpn)\s*$') {
                [void]$list.Add(@{ Pattern = $Matches[1].Trim(); Mode = $Matches[2].ToLower() })
            }
        }
    }
    return @($list)
}

function Get-ModeForText([string]$Text, $Policies) {
    if (-not $Text) { return '' }
    $t = $Text.ToLower()
    foreach ($p in $Policies) {
        $pat = $p.Pattern.ToLower()
        if (-not $pat) { continue }
        if ($pat.Contains('.')) {
            if ($t -eq $pat -or $t.EndsWith('.' + $pat)) { return $p.Mode }
        } else {
            if ($t -eq $pat -or $t.Contains($pat)) { return $p.Mode }
        }
    }
    return ''
}

# ---------- интерфейсы ----------
function Get-InterfaceByKind([string]$Kind) {
    $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -ne '0.0.0.0' })
    if ($Kind -eq 'Agent') {
        $wifi = $ips | Where-Object { $_.InterfaceAlias -match 'Беспроводная|Wireless|Wi-Fi|WLAN' } | Select-Object -First 1
        if ($wifi) { return $wifi }
        return ($ips | Where-Object { $_.InterfaceAlias -notmatch 'VPN|Radmin|TAP|TUN' } | Select-Object -First 1)
    }
    $eth = $ips | Where-Object { $_.InterfaceAlias -match '^Ethernet' } | Select-Object -First 1
    if ($eth) { return $eth }
    return ($ips | Where-Object { $_.InterfaceAlias -notmatch 'VPN|Radmin|TAP|TUN' } | Select-Object -First 1)
}

function Get-Gateway([int]$IfIndex) {
    # Default-route на интерфейсе может отсутствовать (SoftEther его вытеснил).
    # Шлюз тогда виден по уже существующим /32. 0.0.0.0 в качестве NextHop
    # нельзя: такой маршрут становится on-link и глушит сеть.
    $own = @(Get-NetRoute -InterfaceIndex $IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -notmatch '^(10\.211\.|127\.)' })
    $def = $own | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Sort-Object RouteMetric | Select-Object -First 1
    if ($def) { return [string]$def.NextHop }
    $alt = $own | Select-Object -First 1
    if ($alt) { return [string]$alt.NextHop }
    $neigh = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -match '^192\.168\.\d+\.\d+$' } | Select-Object -First 1
    if ($neigh) { return [string]$neigh.NextHop }
    return $null
}

function Test-PublicPrefix([string]$Prefix) {
    if ($Prefix -notmatch '^(\d{1,3})\.') { return $false }
    $a = [int]$Matches[1]
    if ($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224) { return $false }
    if ($Prefix -match '^172\.(\d{1,3})\.') {
        $b = [int]$Matches[1]
        if ($b -ge 16 -and $b -le 31) { return $false }
    }
    if ($Prefix -match '^192\.168\.') { return $false }
    if ($Prefix -match '^169\.254\.') { return $false }
    return $true
}

function Remove-RouteSafe($Route) {
    try {
        Remove-NetRoute -DestinationPrefix $Route.DestinationPrefix -InterfaceIndex $Route.InterfaceIndex `
            -NextHop $Route.NextHop -Confirm:$false -ErrorAction Stop | Out-Null
    } catch {
        return $false
    }
    [void]$script:Managed.Remove("$($Route.DestinationPrefix)|$($Route.InterfaceIndex)")
    return $true
}

# Туннельный адаптер SoftEther (тот, что сейчас Up) + его шлюз
function Get-TunnelInterface {
    try {
        $ad = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { ($_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$') -and
                           $_.Status -eq 'Up' } | Select-Object -First 1
        if (-not $ad) { return $null }
        # Не через Get-Gateway: тот отбрасывает next hop 10.211.x и иначе
        # подставит шлюз LAN, хотя у туннеля свой шлюз.
        $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $ad.ifIndex -and $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
            Sort-Object RouteMetric | Select-Object -First 1
        if (-not $r) { return $null }
        return [pscustomobject]@{ Index = $ad.ifIndex; Alias = $ad.Name; Gateway = [string]$r.NextHop }
    } catch { return $null }
}

# Адреса туннелей SoftEther — по ним видно, кто уехал в VPN
function Get-TunnelAddresses {
    $set = @{}
    try {
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -match ' - VPN Client$|VPN Client Adapter|TAP|TUN' } |
            ForEach-Object { $set[$_.IPAddress] = $true }
    } catch {}
    return $set
}

# ТРАНСПОРТ SoftEther — адреса, к которым сам клиент подключён.
# Эти адреса нельзя прибивать на туннель: туннель уйдёт сам в себя и упадёт.
function Get-TransportIps {
    $set = @{}
    $pids = @(Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -match 'vpnclient|vpncmd' } | Select-Object -ExpandProperty Id)
    if ($pids.Count) {
        $pidset = @{}
        foreach ($id in $pids) { $pidset[[int]$id] = $true }
        # Не только Established: сессия GUI может быть в FIN_WAIT, и этот
        # адрес всё равно нельзя снимать с провода — туннель уйдёт в себя.
        Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Where-Object { $pidset.ContainsKey([int]$_.OwningProcess) } |
            Select-Object -ExpandProperty RemoteAddress -Unique |
            Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $_ -notmatch '^(127\.|0\.0\.0\.0)' } |
            ForEach-Object { $set[$_] = $true }
    }
    $srvFile = Join-Path $CacheDir 'current-server.txt'
    if (Test-Path $srvFile) {
        $v = (Get-Content $srvFile -Raw -ErrorAction SilentlyContinue).Trim()
        if ($v -match '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') { $set[$Matches[1]] = $true }
    }
    return $set
}

# Сети CDN/edge, где живут адреса direct-агента (Alibaba Cloud + Akamai).
# Ротация идёт внутри этих /16 — прибиваем целиком, иначе новый адрес
# уедет в туннель и исходящий IP агента сменится (сессия рвётся).
$script:DirectRanges = @(
    '121.41.0.0/16', '2.21.0.0/16', '23.73.0.0/16', '23.215.0.0/16',
    '47.79.0.0/16', '47.252.0.0/16', '47.253.0.0/16', '184.51.0.0/16'
)

# ---------- сбор целей по политике ----------
function Get-TargetsByPolicy($Policies) {
    $direct = @{}
    $vpn    = @{}
    $leaked = @()
    $matched = @{}
    $tunnel  = Get-TunnelAddresses

    $procs = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = ''
        try { $path = $p.Path } catch {}
        # ключ приводим к [int]: OwningProcess у Get-NetTCPConnection — UInt32,
        # а Id у Get-Process — Int32. Хеш-таблица различает типы ключей,
        # и без приведения поиск по PID всегда проваливался.
        $procs[[int]$p.Id] = [pscustomobject]@{ Name = $p.ProcessName; Path = $path }
    }

    foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
        $ra = $c.RemoteAddress
        if (-not $ra -or $ra -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { continue }
        # приватные/служебные адреса (loopback, LAN, RFC1918) в цели не
        # берём вообще: их нельзя ни прибивать на Wi-Fi, ни тем более
        # на туннель — уход локальной связи в VPN рвёт всё живое
        if (Test-PrivateIp $ra) { continue }
        $pr = $procs[[int]$c.OwningProcess]
        if (-not $pr) { continue }

        $mode = Get-ModeForText $pr.Name $Policies
        if (-not $mode) { $mode = Get-ModeForText $pr.Path $Policies }
        if (-not $mode) { $mode = $script:DefaultMode }
        $key = "$($pr.Name) [$mode]"
        if (-not $matched.ContainsKey($key)) { $matched[$key] = 0 }
        $matched[$key]++

        if ($mode -eq 'direct') {
            $direct[$ra] = $true
            if ($tunnel.ContainsKey($c.LocalAddress)) { $leaked += $ra }
        } else {
            $vpn[$ra] = $true
        }
    }

    # домены из политики — резолв, чтобы поймать адреса до первого коннекта
    foreach ($p in $Policies) {
        $pat = $p.Pattern
        if (-not $pat.Contains('.')) { continue }
        try {
            Resolve-DnsName $pat -Type A -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique |
                Where-Object { -not (Test-PrivateIp $_) } |
                ForEach-Object {
                    if ($p.Mode -eq 'direct') { $direct[$_] = $true } else { $vpn[$_] = $true }
                }
        } catch {}
    }

    return [pscustomobject]@{
        Direct  = @($direct.Keys)
        Vpn     = @($vpn.Keys)
        Leaked  = @($leaked | Sort-Object -Unique)
        Matched = $matched
    }
}

# --- DNS на туннельном адаптере ---
#
# ГЛАВНАЯ ПРИЧИНА ОБРЫВА СЕССИИ АГЕНТА.
#
# SoftEther при подключении прописывает на виртуальный адаптер DNS-сервер
# VPN-сервера. Адаптер VPN2 имеет InterfaceMetric 1 (ниже физических), и
# Windows отправляет через него ВЕСЬ DNS. Тогда резолв api.minimaxi.com
# возвращает CDN-IP страны VPN, агент открывает к нему новое соединение —
# и исходящий IP агента меняется с российского на зарубежный. Сервер API
# видит, что та же сессия пришла с другого адреса, и рвёт её
# («The model connection was interrupted. Retrying»).
#
# Раньше DNS просто снимался (ResetServerAddresses) — но в окне между
# подключением SoftEther и следующим проходом guard успевал произойти
# резолв через туннель, и обрыв происходил именно тогда.
#
# Теперь DNS туннеля принудительно ставится РАВНЫМ физическому (роутер
# провайдера). Ответы DNS от обоих адаптеров совпадают → CDN-IP не
# меняется → исходящий IP агента не меняется → сессия жива.
function Set-TunnelDnsToPhysical {
    $changed = 0
    try {
        $phys = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceAlias -match 'Беспроводная|Wireless|Wi-Fi|^Ethernet' -and
                           $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 })
        if (-not $phys) { return 0 }
        $want = @($phys[0].ServerAddresses)

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
            $changed++
        }
    } catch {}
    return $changed
}

function Test-VpnSessionUp { return ($null -ne (Get-TunnelInterface)) }

# Покрывается ли адрес управляемым Wi-Fi-маршрутом?
#
# ВАЖНО: $Matches здесь нельзя переиспользовать в связке с -and — при
# неудачном -match он сохраняет значения от ПРЕДЫДУЩЕГО вызова, и адрес
# ошибочно считался покрытым. Поэтому каждый префикс разбирается в
# отдельные переменные.
function Test-CoveredByManaged([string]$Ip, [int]$IfIndex) {
    foreach ($key in $script:Managed.Keys) {
        $sep = $key.LastIndexOf('|')
        if ($sep -lt 1) { continue }
        $prefix = $key.Substring(0, $sep)
        $idx = 0
        if (-not [int]::TryParse($key.Substring($sep + 1), [ref]$idx)) { continue }
        if ($idx -ne $IfIndex) { continue }

        if ($prefix -eq "$Ip/32") { return $true }

        $pm = [regex]::Match($prefix, '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/32$')
        if ($pm.Success -and $pm.Groups[1].Value -eq $Ip) { return $true }

        $pm = [regex]::Match($prefix, '^(\d{1,3}\.\d{1,3})\.0\.0/24$')
        if ($pm.Success -and $Ip.StartsWith($pm.Groups[1].Value + '.')) { return $true }

        $pm = [regex]::Match($prefix, '^(\d{1,3}\.\d{1,3})\.0\.0/16$')
        if ($pm.Success -and $Ip.StartsWith($pm.Groups[1].Value + '.')) { return $true }
    }
    return $false
}

# Приватные/служебные адреса (loopback, LAN, RFC1918) НИКОГДА не вешаются
# на туннель: уход локальной связи приложений в VPN рвёт и сам туннель,
# и агента. Windows вообще не даёт удалить 127.0.0.1/32 через
# Remove-NetRoute («Default loopback route cannot be deleted»).
function Test-PrivateIp([string]$Ip) {
    if (-not $Ip -or $Ip -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { return $true }
    $p = $Ip.Split('.')
    $a = [int]$p[0]; $b = [int]$p[1]
    if ($a -eq 127) { return $true }                               # loopback
    if ($a -eq 10) { return $true }                                # RFC1918
    if ($a -eq 172 -and $b -ge 16 -and $b -le 31) { return $true } # RFC1918
    if ($a -eq 192 -and $b -eq 168) { return $true }               # RFC1918
    if ($a -eq 169 -and $b -eq 254) { return $true }               # link-local
    if ($a -eq 0 -or $a -ge 224) { return $true }                 # служебные
    return $false
}

# ---------- основной проход ----------
function Invoke-GuardPass {
    $result = [ordered]@{ Removed = 0; Added = 0; NewTargets = @(); Leaked = @(); DnsCleared = 0; Matched = @{}; Conflicts = 0 }

    $agent = Get-InterfaceByKind 'Agent'
    $wire  = Get-InterfaceByKind 'Wire'
    $tun   = Get-TunnelInterface
    if (-not $agent) { Write-GuardLog 'нет физического интерфейса агента'; return $result }

    if ($NoAppSplit) {
        # Per-app split выполняет TrafikRuler. Здесь оставляем только
        # служебную часть: DNS, мёртвые default-маршруты, on-link мусор.
        $info = [pscustomobject]@{ Direct = @(); Vpn = @(); Leaked = @(); Matched = @{} }
    } else {
        $policies = Get-Policies
        $info = Get-TargetsByPolicy $policies
    }
    $result.Leaked  = @($info.Leaked)
    $result.Matched = $info.Matched

    $transport = Get-TransportIps
    $gwA = Get-Gateway $agent.InterfaceIndex
    if (-not $gwA -or $gwA -eq '0.0.0.0') {
        Write-GuardLog 'нет шлюза на интерфейсе агента — новые маршруты не добавляю'
        $gwA = $null
    }

    # On-link (next hop 0.0.0.0) на публичных префиксах — чёрные дыры.
    # Дубль того же префикса на проводе проигрывает Wi-Fi по метрике интерфейса
    # (25 < 35) и уводит direct-агента с Wi-Fi. Транспорт VPN (/32 сервера) не трогаем.
    $scanIf = @($agent.InterfaceIndex)
    if ($wire) { $scanIf += $wire.InterfaceIndex }
    foreach ($idx in $scanIf) {
        foreach ($r in @(Get-NetRoute -InterfaceIndex $idx -AddressFamily IPv4 -Protocol NetMgmt -ErrorAction SilentlyContinue)) {
            if (-not (Test-PublicPrefix $r.DestinationPrefix)) { continue }
            $isTransport = $false
            if ($r.DestinationPrefix -match '^(\d{1,3}(?:\.\d{1,3}){3})/32$' -and $transport.ContainsKey($Matches[1])) {
                $isTransport = $true
            }
            if ($isTransport) { continue }
            $onLink = (-not $r.NextHop -or $r.NextHop -eq '0.0.0.0')
            $shadow = $false
            if ($wire -and $idx -eq $wire.InterfaceIndex) {
                $shadow = $null -ne (Get-NetRoute -DestinationPrefix $r.DestinationPrefix -ErrorAction SilentlyContinue |
                    Where-Object { $_.InterfaceIndex -eq $agent.InterfaceIndex } | Select-Object -First 1)
            }
            if (-not $onLink -and -not $shadow) { continue }
            Remove-NetRoute -DestinationPrefix $r.DestinationPrefix -InterfaceIndex $r.InterfaceIndex `
                -NextHop $r.NextHop -Confirm:$false -ErrorAction SilentlyContinue
            [void]$script:Managed.Remove("$($r.DestinationPrefix)|$idx")
            $result.Removed++
        }
    }

    # --- 1) direct-цели: прибить на Wi-Fi ---
    foreach ($ip in @($info.Direct)) {
        # транспорт SoftEther не трогаем никогда
        if ($transport.ContainsKey($ip)) { continue }
        if (-not $gwA) { continue }

        $prefix32 = "$ip/32"
        $have = @(Get-NetRoute -DestinationPrefix $prefix32 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -eq $agent.InterfaceIndex -and $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
        if (-not $have) {
            New-NetRoute -DestinationPrefix $prefix32 -InterfaceIndex $agent.InterfaceIndex `
                -NextHop $gwA -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
            $script:Managed["$prefix32|$($agent.InterfaceIndex)"] = $true
            $result.Added++
            $result.NewTargets += $ip
        }
        # Настоящая /24 вокруг адреса (a.b.c.0/24). Прежняя a.b.0.0/24
        # покрывала только третий октет 0 и не держала ротацию CDN.
        $net = $null
        if ($ip -match '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$') {
            $net = "$($Matches[1]).0/24"
            $haveNet = @(Get-NetRoute -DestinationPrefix $net -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $agent.InterfaceIndex -and $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
            if (-not $haveNet) {
                New-NetRoute -DestinationPrefix $net -InterfaceIndex $agent.InterfaceIndex `
                    -NextHop $gwA -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null
                $script:Managed["$net|$($agent.InterfaceIndex)"] = $true
                $result.Added++
            }
        }
        # Дубль на проводе снимаем всегда, не только если он записан в managed:
        # после перезагрузки ifIndex меняется, и старый ключ больше не совпадает.
        if ($wire) {
            foreach ($pfx in @($prefix32, $net)) {
                if (-not $pfx) { continue }
                foreach ($r in @(Get-NetRoute -DestinationPrefix $pfx -ErrorAction SilentlyContinue |
                        Where-Object { $_.InterfaceIndex -eq $wire.InterfaceIndex })) {
                    Remove-NetRoute -DestinationPrefix $r.DestinationPrefix -InterfaceIndex $r.InterfaceIndex `
                        -NextHop $r.NextHop -Confirm:$false -ErrorAction SilentlyContinue
                    [void]$script:Managed.Remove("$pfx|$($wire.InterfaceIndex)")
                    $result.Removed++
                }
            }
        }
    }

    # --- 1a) /16 сетей CDN НЕ прибиваем ---
    #
    # Раньше здесь вешались целые /16 (121.41, 2.21, 23.73, 23.215, 47.79,
    # 47.252, 47.253, 184.51). Это давало стабильность агенту, но
    # перехватывало ОЧЕНЬ много чужого трафика: Akamai и Alibaba — это
    # YouTube, Telegram, Discord, VK, Яндекс и почти всё в интернете.
    # Пользовательский трафик переставал идти через VPN.
    #
    # Вместо этого watchdog каждые несколько секунд ловит живые адреса
    # агента и прибивает точечные /32 + /24. Агент держит соединение
    # постоянно, поэтому его актуальные адреса всегда в списке.
    # Ротация CDN покрывается тем, что /24 ставится вокруг каждого нового
    # адреса, а /32 — точно на него.

    # --- 2) vpn-цели: НИЧЕГО на туннель не вешаем ---
    #
    # Раньше здесь для агентов в режиме vpn создавались /32 на туннельном
    # адаптере. Это было ошибкой: туннель — единственный интерфейс, через
    # который идёт сам VPN, и лишние маршруты на нём рвали сессию
    # (включая 127.0.0.1/32, из-за чего служебная связь приложений
    # уходила в VPN — и падал туннель, и рвался агент).
    #
    # Правило простое: туннельный адаптер не трогаем вообще, кроме
    # снятия DNS. Маршрут по умолчанию через туннель и так отправляет
    # весь трафик агентов в режиме vpn через VPN.

    # --- 3) чинить мёртвые default-route через отключённые SoftEther-адаптеры ---
    $soft = @(Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$' })
    foreach ($ad in $soft) {
        if ($ad.Status -eq 'Up') { continue }
        foreach ($r in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $ad.ifIndex })) {
            Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $r.InterfaceIndex `
                -NextHop $r.NextHop -Confirm:$false -ErrorAction SilentlyContinue
            $result.Removed++
        }
    }

    # --- 4) физический default — только когда туннель погашен ---
    # Пока SoftEther поднят, он сам сносит чужие 0.0.0.0/0. Добавлять их
    # в этом окне бесполезно: маршрут живёт меньше секунды. Когда туннеля
    # нет — возвращаем default на провод и Wi-Fi.
    if (-not $tun) {
        foreach ($iface in @($wire, $agent)) {
            if (-not $iface) { continue }
            $gwP = Get-Gateway $iface.InterfaceIndex
            if (-not $gwP -or $gwP -eq '0.0.0.0') { continue }
            $hasActive = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                Where-Object { $_.InterfaceIndex -eq $iface.InterfaceIndex -and $_.NextHop -eq $gwP })
            if ($hasActive) { continue }
            try {
                New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $iface.InterfaceIndex `
                    -NextHop $gwP -RouteMetric 30 -ErrorAction Stop | Out-Null
                $result.Added++
            } catch {
                Write-GuardLog "default на $($iface.InterfaceAlias) не записался: $($_.Exception.Message)"
            }
        }
    }

    # --- 5) DNS туннеля приравнять к физическому ---
    $result.DnsCleared = Set-TunnelDnsToPhysical

    return $result
}

# ---------- прогон ----------
if (Test-GuardRunning) {
    Write-GuardLog 'Watchdog уже работает — второй экземпляр не запускаю.'
    exit 0
}
try { [System.IO.File]::WriteAllText($script:PidFile, "$PID", $Utf8) } catch {}

Load-Managed
if ($NoAppSplit) { Write-GuardLog 'per-app: TrafikRuler; маршруты по IP не создаются' }
$r = Invoke-GuardPass
Save-Managed
$msg = "добавлено $($r.Added); удалено $($r.Removed)"
if ($r.Conflicts) { $msg += "; конфликт→туннель: $($r.Conflicts)" }
if ($r.NewTargets.Count) { $msg += "; новые адреса: $($r.NewTargets -join ', ')" }
if ($r.DnsCleared) { $msg += "; DNS снят с туннеля" }
if ($r.Matched.Count) {
    $parts = @()
    foreach ($k in ($r.Matched.Keys | Sort-Object)) { $parts += "${k}: $($r.Matched[$k])" }
    $msg += "; процессы — " + ($parts -join ', ')
}
if ($r.Leaked.Count) { $msg += "; ВНИМАНИЕ уехал в туннель: $($r.Leaked -join ', ')" }
Write-GuardLog $msg

if ($Watch) {
    Write-GuardLog "Watchdog запущен (интервал ${IntervalSec}с). Выход: закрыть процесс или VPN отключат 3 раза подряд."
    $idle = 0
    while ($true) {
        Start-Sleep -Seconds $IntervalSec
        try {
            $r2 = Invoke-GuardPass
            Save-Managed
            if ($r2.Added -or $r2.Removed -or $r2.NewTargets.Count -or $r2.DnsCleared) {
                $m2 = "добавлено $($r2.Added); удалено $($r2.Removed)"
                if ($r2.Conflicts) { $m2 += "; конфликт→туннель: $($r2.Conflicts)" }
                if ($r2.NewTargets.Count) { $m2 += "; новые адреса: $($r2.NewTargets -join ', ')" }
                if ($r2.DnsCleared) { $m2 += "; DNS снят с туннеля" }
                Write-GuardLog $m2
            }
            if ($r2.Leaked.Count) {
                Write-GuardLog "ВНИМАНИЕ: соединения direct-агента идут через туннель: $($r2.Leaked -join ', ')"
            }
            if (Test-VpnSessionUp) { $idle = 0 } else { $idle++ }
            if ($idle -ge 3) {
                Write-GuardLog 'VPN не активен — watchdog останавливается.'
                break
            }
        } catch {
            Write-GuardLog "ошибка: $($_.Exception.Message)"
        }
    }
}
# убираем PID-файл, чтобы следующий запуск не решил, что watchdog уже работает
try { Remove-Item $script:PidFile -Force -ErrorAction SilentlyContinue } catch {}
exit 0
