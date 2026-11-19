# Управление разделением программ между VPN и обычным интернетом.
#
# Разделение делает TrafikRuler: правило «exe -> адаптер» перехватывает
# пакеты выбранной программы и выпускает их через Wi-Fi или кабель.
# Этот скрипт:
#   • читает и правит %APPDATA%\TrafikRuler\settings.json;
#   • перезапускает TrafikRuler, чтобы он применил правила;
#   • держит default-шлюз на физических адаптерах (keep-gateways.ps1);
#   • убирает старую схему route-guard с маршрутами по IP;
#   • показывает, что реально работает (doctor).
#
# Примеры:
#   .\split-tunnel.ps1 -Status
#   .\split-tunnel.ps1 -Doctor
#   .\split-tunnel.ps1 -AddApp "C:\Apps\Opera.exe" -Adapter "Беспроводная сеть" -EnableNew
#   .\split-tunnel.ps1 -EnableRule "Opera GX" -RestartRuler
#   .\split-tunnel.ps1 -Bootstrap -AddApps "path1;path2" -Adapter "Беспроводная сеть" -EnableNew
#   .\split-tunnel.ps1 -Status -Json
[CmdletBinding()]
param(
    [switch]$List,
    [switch]$Status,
    [switch]$Doctor,
    [switch]$Json,
    [switch]$NoElevate,

    [string]$EnableRule = '',
    [string]$DisableRule = '',
    [string]$AddApp = '',
    [string]$AddApps = '',
    [string]$RemoveRule = '',
    [string]$SetAdapterFor = '',
    [string]$Adapter = '',
    [string]$DisplayName = '',
    [switch]$EnableNew,

    [switch]$StartGateways,
    [switch]$StopGateways,
    [switch]$InstallGatewaysTask,
    [switch]$RemoveGatewaysTask,
    [switch]$InstallRulerTask,
    [switch]$CleanupLegacy,
    [switch]$EnsureRuler,
    [switch]$RestartRuler,
    [switch]$Bootstrap
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$script:Self = $MyInvocation.MyCommand.Path
$script:SettingsPath = Join-Path $env:APPDATA 'TrafikRuler\settings.json'
$script:LogPath = Join-Path $env:APPDATA 'TrafikRuler\log.txt'
$script:StateDir = Join-Path $env:LOCALAPPDATA 'VPNGateAuto'
$script:ManagedFile = Join-Path $script:StateDir 'managed-routes.txt'
$script:PolicyFile = Join-Path $script:StateDir 'agent-policies.txt'
$script:GatewayPid = Join-Path $script:StateDir 'keep-gateways.pid'
$script:GatewayScript = Join-Path $PSScriptRoot 'keep-gateways.ps1'

# Сеть читается через netutil.ps1 (сначала WMI, при заклинившем WMI — netsh).
# Без этого панель «Приложения без VPN» и правила не работали, когда WMI
# зависал (18.11.2026).
$NetUtilPath = Join-Path $PSScriptRoot 'netutil.ps1'
if (Test-Path $NetUtilPath) { . $NetUtilPath }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$mutating = [bool]($EnableRule -or $DisableRule -or $AddApp -or $AddApps -or $RemoveRule -or $SetAdapterFor -or
    $StartGateways -or $StopGateways -or $InstallGatewaysTask -or $RemoveGatewaysTask -or $InstallRulerTask -or
    $CleanupLegacy -or $EnsureRuler -or $RestartRuler -or $Bootstrap)

if ($mutating -and -not $NoElevate -and -not (Test-Admin)) {
    $forward = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $script:Self + '"'), '-NoElevate')
    foreach ($k in $PSBoundParameters.Keys) {
        if ($k -eq 'NoElevate') { continue }
        $v = $PSBoundParameters[$k]
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $forward += "-$k" }
        } elseif ($null -ne $v -and "$v" -ne '') {
            $forward += "-$k"
            $forward += ('"' + ("$v" -replace '"', '\"') + '"')
        }
    }
    try {
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList $forward -Verb RunAs -Wait -PassThru
        exit $p.ExitCode
    } catch {
        Write-Host "Не удалось получить права администратора: $($_.Exception.Message)"
        exit 1
    }
}

# ---------- настройки TrafikRuler ----------

function Read-Settings {
    if (-not (Test-Path $script:SettingsPath)) {
        throw "Нет файла TrafikRuler: $script:SettingsPath"
    }
    $raw = Get-Content -Raw -Encoding UTF8 $script:SettingsPath
    $obj = $raw | ConvertFrom-Json
    if (-not $obj.PSObject.Properties.Name.Contains('Rules')) {
        $obj | Add-Member -NotePropertyName Rules -NotePropertyValue @()
    }
    return $obj
}

function Save-Settings($Settings) {
    $dir = Split-Path -Parent $script:SettingsPath
    $tmp = Join-Path $dir 'settings.json.tmp'
    if (Test-Path $script:SettingsPath) {
        Copy-Item $script:SettingsPath (Join-Path $dir 'settings.json.bak') -Force -ErrorAction SilentlyContinue
    }
    $json = $Settings | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($tmp, $json, (New-Object System.Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $tmp -Destination $script:SettingsPath -Force
}

function Get-RuleLeaf([string]$Path) {
    if (-not $Path) { return '' }
    return [System.IO.Path]::GetFileName($Path)
}

function Test-RuleMatch($Rule, [string]$Pattern) {
    if (-not $Pattern) { return $false }
    if ([string]$Rule.Id -ieq $Pattern) { return $true }
    if ([string]$Rule.DisplayName -ieq $Pattern) { return $true }
    if ((Get-RuleLeaf ([string]$Rule.ProgramPath)) -ieq $Pattern) { return $true }
    if ([string]$Rule.ProgramPath -and ([string]$Rule.ProgramPath).IndexOf($Pattern, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    return $false
}

function Find-Rule($Settings, [string]$Pattern) {
    foreach ($r in @($Settings.Rules)) {
        if (Test-RuleMatch $r $Pattern) { return $r }
    }
    return $null
}

function Get-AdapterList {
    if (Get-Command Get-NuAdapters -ErrorAction SilentlyContinue) {
        return @(Get-NuAdapters)
    }
    return @(Get-NetAdapter -ErrorAction SilentlyContinue)
}

function Get-DefaultAdapter {
    $all = Get-AdapterList
    $wifi = @($all | Where-Object {
        ($_.Name -match 'Беспроводная|Wireless|Wi-Fi|WLAN' -or $_.InterfaceDescription -match 'Wireless|802\.11') -and
        $_.IsUp
    } | Select-Object -First 1)
    if ($wifi) { return $wifi[0] }
    $eth = @($all | Where-Object {
        $_.Name -match '^Ethernet' -and $_.IsUp -and $_.InterfaceDescription -notmatch 'TAP|TUN|Virtual'
    } | Select-Object -First 1)
    if ($eth) { return $eth[0] }
    return $null
}

function Resolve-Adapter([string]$Name) {
    $all = Get-AdapterList
    if (-not $Name) { return Get-DefaultAdapter }
    $exact = @($all | Where-Object { $_.Name -ieq $Name -or ([string]$_.InterfaceGuid) -ieq $Name })
    if (-not $exact) {
        $exact = @($all | Where-Object { $_.Name -like "*$Name*" -or $_.InterfaceDescription -like "*$Name*" })
    }
    $up = @($exact | Where-Object { $_.IsUp } | Select-Object -First 1)
    if ($up) { return $up[0] }
    if ($exact.Count) { return $exact[0] }
    return $null
}

function Get-AdapterIPv4($Adapter) {
    if (-not $Adapter) { return '' }
    if (Get-Command Get-NuAdapterIp -ErrorAction SilentlyContinue) {
        $ip = Get-NuAdapterIp $Adapter.ifIndex
        if ($ip) { return [string]$ip }
        return ''
    }
    $ip = @(Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1)
    if ($ip) { return [string]$ip[0].IPAddress }
    return ''
}

function Get-RulerExe {
    $candidates = @(
        (Join-Path $env:ProgramData 'VPNGateSetup\TrafikRuler\TrafikRuler.exe'),
        (Join-Path $PSScriptRoot 'TrafikRuler\TrafikRuler.exe'),
        (Join-Path $env:LOCALAPPDATA 'Programs\TrafikRuler\TrafikRuler.exe'),
        'G:\Мой диск\Прочее\Install\TrafikRuler-1.1.0\TrafikRuler.exe',
        'C:\Program Files\TrafikRuler\TrafikRuler.exe'
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    $task = $null
    try { $task = Get-ScheduledTask -TaskName 'TrafikRuler' -ErrorAction Stop } catch { $task = $null }
    if ($task -and $task.Actions.Count) {
        $exe = [string]$task.Actions[0].Execute
        $exe = $exe.Trim('"').Trim("'")
        if ($exe -and (Split-Path -Leaf $exe) -ieq 'TrafikRuler.exe' -and (Test-Path -LiteralPath $exe)) { return $exe }
        $argText = [string]$task.Actions[0].Arguments
        $m = [regex]::Match($argText, '"([^"]*TrafikRuler\.exe)"')
        if (-not $m.Success) { $m = [regex]::Match($argText, '(?i)([A-Z]:\\[^\"]*TrafikRuler\.exe)') }
        if ($m.Success -and (Test-Path -LiteralPath $m.Groups[1].Value)) { return $m.Groups[1].Value }
    }
    # WMI недоступен — читаем задачу через schtasks.
    try {
        $q = & schtasks.exe /Query /TN 'TrafikRuler' /FO LIST /V 2>$null | Out-String
        $m2 = [regex]::Match($q, '(?i)([A-Z]:\\[^\r\n"]*TrafikRuler\.exe)')
        if ($m2.Success -and (Test-Path -LiteralPath $m2.Groups[1].Value)) { return $m2.Groups[1].Value }
    } catch {}
    return $null
}

function Get-RulerProcess {
    return @(Get-Process -Name 'TrafikRuler' -ErrorAction SilentlyContinue | Select-Object -First 1)
}

function Test-RulerTask {
    & schtasks.exe /Query /TN 'TrafikRuler' 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Wait-NewRuler {
    param([int[]]$OldIds, [int]$Seconds = 8)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 350
        $now = @(Get-RulerProcess)
        if (-not $now.Count) { continue }
        $new = @($now | Where-Object { $OldIds -notcontains [int]$_.Id })
        if ($new.Count) {
            Start-Sleep -Milliseconds 900
            return $true
        }
    }
    return $false
}

function Stop-Ruler {
    $procs = @(Get-Process -Name 'TrafikRuler' -ErrorAction SilentlyContinue)
    foreach ($p in $procs) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch {}
    }
    if ($procs.Count) { Start-Sleep -Milliseconds 800 }
    return $procs.Count
}

function Start-RulerTask {
    if (-not (Test-RulerTask)) { return $false }
    $old = @(Get-RulerProcess | ForEach-Object { [int]$_.Id })
    & schtasks.exe /Run /TN 'TrafikRuler' 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { return $false }
    return (Wait-NewRuler -OldIds $old)
}

function Start-Ruler {
    if (Get-RulerProcess) { return $false }
    if (Start-RulerTask) { return $true }
    $exe = Get-RulerExe
    if (-not $exe) { throw 'TrafikRuler.exe не найден (нет задачи TrafikRuler и известных путей).' }
    Start-Process -FilePath $exe -ArgumentList '--minimized' -WindowStyle Hidden | Out-Null
    Start-Sleep -Milliseconds 900
    return $true
}

function Restart-Ruler {
    $old = @(Get-RulerProcess | ForEach-Object { [int]$_.Id })
    if (Test-RulerTask) {
        & schtasks.exe /Run /TN 'TrafikRuler' 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0 -and (Wait-NewRuler -OldIds $old)) { return $old.Count }
    }
    $stopped = Stop-Ruler
    Start-Ruler | Out-Null
    return $stopped
}

function Get-RulerLogState {
    $lines = @(Get-Content -Tail 150 -Encoding UTF8 -ErrorAction SilentlyContinue $script:LogPath)
    $start = -1
    $stop = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Перехват трафика запущен') { $start = $i }
        if ($lines[$i] -match 'Перехват трафика остановлен') { $stop = $i }
    }
    $lastRule = @($lines | Where-Object { $_ -match 'Правило .*активно|правило включено|правило выключено' } | Select-Object -Last 1)
    return [pscustomobject]@{
        Active = ($start -ge 0 -and $start -gt $stop)
        LastRule = if ($lastRule.Count) { [string]$lastRule[0] } else { '' }
    }
}

function Add-RuleToSettings($Settings, [string]$Path, [string]$Name, $AdapterObj, [bool]$Enable) {
    $full = [System.IO.Path]::GetFullPath($Path)
    foreach ($r in @($Settings.Rules)) {
        if ([string]$r.ProgramPath -ieq $full) {
            $r.DisplayName = if ($Name) { $Name } else { Get-RuleLeaf $full }
            if ($AdapterObj) {
                $r.AdapterId = [string]$AdapterObj.InterfaceGuid
                $r.AdapterName = [string]$AdapterObj.Name
            }
            if ($Enable) { $r.Enabled = $true }
            return $r
        }
    }
    $rule = [pscustomobject]@{
        Id = [guid]::NewGuid().ToString()
        ProgramPath = $full
        AdapterId = if ($AdapterObj) { [string]$AdapterObj.InterfaceGuid } else { '' }
        AdapterName = if ($AdapterObj) { [string]$AdapterObj.Name } else { '' }
        KillSwitch = $false
        Enabled = $Enable
        DisplayName = if ($Name) { $Name } else { Get-RuleLeaf $full }
        MatchesByNameOnly = $false
    }
    $Settings.Rules = @(@($Settings.Rules) + $rule)
    return $rule
}

function Apply-RuleChange([scriptblock]$Mutation) {
    $settings = Read-Settings
    $result = & $Mutation $settings
    $wasRunning = [bool](Get-RulerProcess)
    Save-Settings $settings
    $enabled = @($settings.Rules | Where-Object { $_.Enabled }).Count
    if ($wasRunning) {
        $old = @(Get-RulerProcess | ForEach-Object { [int]$_.Id })
        $restarted = $false
        if (Test-RulerTask) {
            & schtasks.exe /Run /TN 'TrafikRuler' 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $restarted = Wait-NewRuler -OldIds $old }
        }
        if (-not $restarted) {
            $stopped = Stop-Ruler
            Start-Ruler | Out-Null
            if ($stopped -eq 0) { throw 'TrafikRuler не перезапустился: задача TrafikRuler недоступна.' }
        }
    } elseif ($enabled -gt 0) {
        Start-Ruler | Out-Null
    }
    return $result
}

# ---------- шлюзы ----------

function Test-GatewaysDaemon {
    if (Test-Path $script:GatewayPid) {
        $txt = (Get-Content -Raw -ErrorAction SilentlyContinue $script:GatewayPid).Trim()
        if ($txt -match '^\d+$') {
            if (Get-Process -Id ([int]$txt) -ErrorAction SilentlyContinue) { return $true }
        }
    }
    return $false
}

function Start-GatewaysDaemon {
    if (Test-GatewaysDaemon) { return $false }
    if (-not (Test-Path $script:GatewayScript)) { throw "Нет $script:GatewayScript" }
    & schtasks.exe /Query /TN 'VPNGateKeepGateways' 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        & schtasks.exe /Run /TN 'VPNGateKeepGateways' 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Start-Sleep -Milliseconds 900
            return $true
        }
    }
    Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
        '-File', ('"' + $script:GatewayScript + '"')
    ) | Out-Null
    Start-Sleep -Milliseconds 700
    return $true
}

function Stop-GatewaysDaemon {
    $n = 0
    if (Test-Path $script:GatewayPid) {
        $txt = (Get-Content -Raw -ErrorAction SilentlyContinue $script:GatewayPid).Trim()
        if ($txt -match '^\d+$') {
            $p = Get-Process -Id ([int]$txt) -ErrorAction SilentlyContinue
            if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue; $n++ }
        }
    }
    Remove-Item $script:GatewayPid -Force -ErrorAction SilentlyContinue
    return $n
}

function Install-GatewaysTask {
    if (-not (Test-Path $script:GatewayScript)) { throw "Нет $script:GatewayScript" }
    Stop-GatewaysDaemon | Out-Null
    & schtasks.exe /End /TN 'VPNGateKeepGateways' 2>$null | Out-Null
    Start-Sleep -Milliseconds 500
    $tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script:GatewayScript`""
    & schtasks.exe /Create /TN 'VPNGateKeepGateways' /SC ONLOGON /RL HIGHEST /F /TR $tr | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать задачу VPNGateKeepGateways.' }
    Start-GatewaysDaemon | Out-Null
}

function Install-RulerTask {
    $exe = Get-RulerExe
    if (-not $exe) { throw 'TrafikRuler.exe не найден.' }
    $name = 'TrafikRuler'
    $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $arg = '/c taskkill /IM TrafikRuler.exe /F >nul 2>&1 & start "" "' + $exe + '" --minimized'

    # Задачи Windows живут в WMI. Если WMI заклинил, Register-ScheduledTask
    # не сработает — тогда создаём задачу через schtasks (он WMI не нужен).
    $wmiOk = $false
    try {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument $arg
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $who
        $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        $wmiOk = $true
    } catch {
        Write-Host "WMI недоступен ($($_.Exception.Message)) — задача создаётся через schtasks."
    }
    if (-not $wmiOk) {
        & schtasks.exe /End /TN $name 2>$null | Out-Null
        & schtasks.exe /Delete /TN $name /F 2>$null | Out-Null
        $tr = 'cmd.exe /c ' + $arg
        & schtasks.exe /Create /TN $name /SC ONLOGON /RL HIGHEST /RU $who /F /TR $tr | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать задачу TrafikRuler.' }
    }
    & schtasks.exe /Run /TN $name 2>&1 | Out-Null
    Start-Sleep -Milliseconds 1400
}

function Remove-GatewaysTask {
    Stop-GatewaysDaemon | Out-Null
    & schtasks.exe /Delete /TN 'VPNGateKeepGateways' /F 2>$null | Out-Null
}

function Get-ManagedRouteCount {
    if (-not (Test-Path $script:ManagedFile)) { return 0 }
    return @(Get-Content $script:ManagedFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() }).Count
}

function Stop-LegacyGuard {
    $n = 0
    $pidFile = Join-Path $script:StateDir 'route-guard.pid'
    if (Test-Path $pidFile) {
        $txt = (Get-Content -Raw -ErrorAction SilentlyContinue $pidFile).Trim()
        if ($txt -match '^\d+$') {
            $p = Get-Process -Id ([int]$txt) -ErrorAction SilentlyContinue
            if ($p) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $n++ } catch {} }
        }
    }
    Remove-Item (Join-Path $script:StateDir 'route-guard.pid') -Force -ErrorAction SilentlyContinue
    return $n
}

function Test-PrivateOrServicePrefix([string]$Prefix) {
    if ($Prefix -match '^0\.0\.0\.0/0$') { return $true }
    if ($Prefix -match '^(10\.|127\.|169\.254\.|192\.168\.)') { return $true }
    if ($Prefix -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
    if ($Prefix -match '^22[4-9]\.|^23\d\.|^24\d\.|^25[0-5]\.') { return $true }
    return $false
}

function Get-TransportIps {
    $set = @{}
    $pids = @(Get-Process -Name 'vpnclient_x64', 'vpnclient' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    if ($pids.Count) {
        $conns = if (Get-Command Get-NuTcpConnections -ErrorAction SilentlyContinue) {
            @(Get-NuTcpConnections)
        } else {
            @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
        }
        $conns |
            Where-Object { $pids -contains [int]$_.Pid } |
            Select-Object -ExpandProperty RemoteAddress -Unique |
            Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notmatch '^(127\.|0\.0\.0\.0)' } |
            ForEach-Object { $set[$_] = $true }
    }
    $srv = Join-Path $script:StateDir 'current-server.txt'
    if (Test-Path $srv) {
        $v = (Get-Content -Raw -ErrorAction SilentlyContinue $srv).Trim()
        if ($v -match '^\d{1,3}(\.\d{1,3}){3}$') { $set[$v] = $true }
    }
    return $set
}

function Cleanup-LegacySplit {
    $stopped = Stop-LegacyGuard
    $transport = Get-TransportIps
    $removed = 0
    $prefixes = @()
    if (Test-Path $script:ManagedFile) {
        foreach ($line in @(Get-Content $script:ManagedFile -ErrorAction SilentlyContinue)) {
            $p = ($line -split '\|')[0].Trim()
            if ($p -and ($prefixes -notcontains $p)) { $prefixes += $p }
        }
    }
    foreach ($prefix in $prefixes) {
        if (Test-PrivateOrServicePrefix $prefix) { continue }
        if ($prefix -match '^(\d{1,3}(?:\.\d{1,3}){3})/32$' -and $transport.ContainsKey($Matches[1])) { continue }
        foreach ($r in @(Get-NuRoutes | Where-Object { $_.DestinationPrefix -eq $prefix })) {
            if ($r.InterfaceAlias -match 'VPN|Radmin') { continue }
            if ($r.NextHop -eq '0.0.0.0') { continue }
            try {
                Remove-NuRoute -DestinationPrefix $r.DestinationPrefix -Index $r.ifIndex -NextHop $r.NextHop | Out-Null
                $removed++
            } catch {}
        }
    }
    try { [System.IO.File]::WriteAllText($script:ManagedFile, '') } catch {}

    $legacyPolicy = Join-Path $script:StateDir 'agent-policies.legacy.txt'
    if (Test-Path $script:PolicyFile) {
        Copy-Item $script:PolicyFile $legacyPolicy -Force -ErrorAction SilentlyContinue
    }
    $policy = @(
        '# Приложения без VPN настраиваются в TrafikRuler:',
        '# окно VPN Gate -> раздел «Приложения без VPN» (split-tunnel.ps1).',
        '# route-guard больше не вешает маршруты по IP: они конфликтуют',
        '# с перехватом по имени exe и уводят чужой трафик мимо VPN.',
        'DEFAULT_MODE vpn'
    )
    [System.IO.File]::WriteAllLines($script:PolicyFile, $policy, (New-Object System.Text.UTF8Encoding($false)))

    return [pscustomobject]@{ GuardStopped = $stopped; RoutesRemoved = $removed; Prefixes = $prefixes.Count }
}

# ---------- статус ----------

function Get-RulesRuntime($Rules) {
    $allConns = if (Get-Command Get-NuTcpConnections -ErrorAction SilentlyContinue) {
        @(Get-NuTcpConnections)
    } else {
        @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
    }
    $procs = @(Get-Process -ErrorAction SilentlyContinue)
    $adapters = Get-AdapterList
    $tunnel = @($adapters | Where-Object {
        ($_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$') -and $_.IsUp
    } | Select-Object -First 1)
    $tunnelIp = if ($tunnel.Count) { Get-AdapterIPv4 $tunnel[0] } else { '' }

    $result = @()
    foreach ($rule in @($Rules)) {
        $path = [string]$rule.ProgramPath
        $leaf = Get-RuleLeaf $path
        $nameOnly = $false
        if ($rule.PSObject.Properties.Name -contains 'MatchesByNameOnly') { $nameOnly = [bool]$rule.MatchesByNameOnly }

        $adapter = $null
        if ($rule.AdapterId -or $rule.AdapterName) {
            $adapter = @($adapters | Where-Object {
                ([string]$_.InterfaceGuid) -ieq [string]$rule.AdapterId -or $_.Name -ieq [string]$rule.AdapterName
            } | Select-Object -First 1)
            if ($adapter) { $adapter = $adapter[0] }
        }
        $adapterIp = if ($adapter) { Get-AdapterIPv4 $adapter } else { '' }

        $ruleProcs = @()
        foreach ($p in $procs) {
            $procPath = ''
            try { $procPath = [string]$p.Path } catch {}
            $match = $false
            if (-not $nameOnly -and $path -and $procPath) { $match = ($procPath -ieq $path) }
            if (-not $match -and $leaf) { $match = (($p.ProcessName + '.exe') -ieq $leaf) }
            if ($match) { $ruleProcs += $p }
        }

        $pids = @($ruleProcs | Select-Object -ExpandProperty Id)
        $conns = @($allConns | Where-Object { $pids -contains [int]$_.OwningProcess })
        $local = @($conns | Select-Object -ExpandProperty LocalAddress -Unique)
        $direct = 0
        $vpn = 0
        foreach ($c in $conns) {
            if ($adapterIp -and $c.LocalAddress -eq $adapterIp) { $direct++ }
            elseif ($tunnelIp -and $c.LocalAddress -eq $tunnelIp) { $vpn++ }
        }

        $result += [pscustomobject]@{
            Id = [string]$rule.Id
            Name = [string]$rule.DisplayName
            Path = $path
            PathExists = [bool]($path -and (Test-Path -LiteralPath $path))
            Enabled = [bool]$rule.Enabled
            AdapterName = [string]$rule.AdapterName
            AdapterId = [string]$rule.AdapterId
            AdapterOk = [bool]($adapter -and $adapter.IsUp -and $adapterIp)
            ProcessCount = $ruleProcs.Count
            ConnectionCount = $conns.Count
            DirectConnections = $direct
            VpnConnections = $vpn
            LocalAddresses = @($local)
        }
    }
    return @($result)
}

function Get-StatusObject {
    $settings = Read-Settings
    $rules = @($settings.Rules)
    $adapters = Get-AdapterList
    $defaults = @(Get-NuDefaultRoutes | Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' })

    $wifi = @($adapters | Where-Object {
        ($_.Name -match 'Беспроводная|Wireless|Wi-Fi|WLAN' -or $_.InterfaceDescription -match 'Wireless|802\.11')
    } | Sort-Object @{ Expression = { if ($_.IsUp) { 0 } else { 1 } } } | Select-Object -First 1)
    if ($wifi) { $wifi = $wifi[0] }
    $wire = @($adapters | Where-Object {
        $_.Name -match '^Ethernet' -and $_.InterfaceDescription -notmatch 'TAP|TUN|Virtual'
    } | Sort-Object @{ Expression = { if ($_.IsUp) { 0 } else { 1 } } } | Select-Object -First 1)
    if ($wire) { $wire = $wire[0] }
    $vpn = @($adapters | Where-Object {
        ($_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$') -and $_.IsUp
    } | Select-Object -First 1)
    if ($vpn) { $vpn = $vpn[0] }

    function New-AdapterInfo($ad) {
        if (-not $ad) { return [pscustomobject]@{ Name = ''; Ip = ''; Up = $false; Gateway = ''; HasDefault = $false; Metric = 0 } }
        $r = @($defaults | Where-Object { $_.ifIndex -eq $ad.ifIndex } | Sort-Object Metric | Select-Object -First 1)
        $gw = if ($r.Count) { [string]$r[0].NextHop } else { '' }
        return [pscustomobject]@{
            Name = [string]$ad.Name
            Ip = (Get-AdapterIPv4 $ad)
            Up = [bool]$ad.IsUp
            Gateway = $gw
            HasDefault = [bool]$r.Count
            Metric = if ($r.Count) { [int]$r[0].Metric } else { 0 }
        }
    }

    $ruler = Get-RulerProcess
    $logState = Get-RulerLogState
    $runtime = Get-RulesRuntime $rules
    $enabledCount = @($runtime | Where-Object { $_.Enabled }).Count
    $guardPid = Join-Path $script:StateDir 'route-guard.pid'
    $guard = @()
    if (Test-Path $guardPid) {
        $gtxt = (Get-Content -Raw -ErrorAction SilentlyContinue $guardPid).Trim()
        if ($gtxt -match '^\d+$' -and (Get-Process -Id ([int]$gtxt) -ErrorAction SilentlyContinue)) {
            $guard = @([pscustomobject]@{ ProcessId = [int]$gtxt })
        }
    }

    return [pscustomobject]@{
        Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Admin = (Test-Admin)
        SettingsPath = $script:SettingsPath
        Ruler = [pscustomobject]@{
            Exe = (Get-RulerExe)
            Running = [bool]$ruler
            Pid = if ($ruler) { [int]$ruler.Id } else { 0 }
            Active = [bool]($ruler -and $logState.Active -and $enabledCount -gt 0)
            EnabledRules = $enabledCount
            TotalRules = $runtime.Count
            LastLog = $logState.LastRule
        }
        Wifi = (New-AdapterInfo $wifi)
        Wire = (New-AdapterInfo $wire)
        Vpn = (New-AdapterInfo $vpn)
        GatewaysDaemon = (Test-GatewaysDaemon)
        Legacy = [pscustomobject]@{
            GuardRunning = [bool]$guard.Count
            ManagedRoutes = (Get-ManagedRouteCount)
        }
        Rules = $runtime
    }
}

function Show-Status($S, [switch]$VerboseDoctor) {
    Write-Host ''
    Write-Host '════ VPN + TrafikRuler ════'
    Write-Host ''
    $trState = if (-not $S.Ruler.Running) { 'не запущен' } elseif ($S.Ruler.Active) { 'работает, перехват активен' } else { 'работает, перехват остановлен' }
    Write-Host ("TrafikRuler : {0}{1}" -f $trState, $(if ($S.Ruler.Pid) { " (pid $($S.Ruler.Pid))" } else { '' }))
    Write-Host ("Правила     : включено {0} из {1}" -f $S.Ruler.EnabledRules, $S.Ruler.TotalRules)
    Write-Host ''
    foreach ($item in @(@('Wi-Fi', $S.Wifi), @('Ethernet', $S.Wire), @('VPN', $S.Vpn))) {
        $label = $item[0]; $a = $item[1]
        if (-not $a.Name) { Write-Host ("{0,-10} : нет" -f $label); continue }
        $def = if ($a.HasDefault) { "default $($a.Gateway), метрика $($a.Metric)" } else { 'default НЕТ' }
        $up = if ($a.Up) { 'up' } else { 'down' }
        Write-Host ("{0,-10} : {1} · {2} · {3} · {4}" -f $label, $a.Name, $(if ($a.Ip) { $a.Ip } else { 'без IP' }), $up, $def)
    }
    $gwState = if ($S.GatewaysDaemon) { 'работает' } else { 'не запущен' }
    Write-Host ("Шлюзы      : keep-gateways {0}" -f $gwState)
    if ($S.Legacy.GuardRunning -or $S.Legacy.ManagedRoutes) {
        Write-Host ("Legacy     : route-guard {0}, маршрутов по IP {1}" -f $(if ($S.Legacy.GuardRunning) { 'работает' } else { 'нет' }), $S.Legacy.ManagedRoutes)
    }
    Write-Host ''
    Write-Host 'Правила TrafikRuler:'
    if (-not $S.Rules.Count) { Write-Host '  (правил нет)'; return }
    foreach ($r in $S.Rules) {
        $mark = if ($r.Enabled) { '[x]' } else { '[ ]' }
        $ad = if ($r.AdapterName) { $r.AdapterName } else { 'адаптер не задан' }
        $extra = ''
        if ($r.Enabled -and $r.ProcessCount -gt 0) {
            $extra = " · процессов $($r.ProcessCount), direct $($r.DirectConnections), vpn $($r.VpnConnections)"
        } elseif ($r.Enabled) {
            $extra = ' · процессов сейчас нет'
        }
        Write-Host ("  {0} {1} → {2}{3}" -f $mark, $r.Name, $ad, $extra)
        Write-Host ("      {0}" -f $r.Path)
        if ($VerboseDoctor) {
            if (-not $r.PathExists) { Write-Host '      !! файл программы не найден' }
            if ($r.Enabled -and -not $r.AdapterOk) { Write-Host '      !! выбранный адаптер не поднят или без IPv4' }
            if ($r.Enabled -and $r.ProcessCount -gt 0 -and $r.DirectConnections -eq 0 -and $r.AdapterOk) {
                Write-Host '      !! соединения ещё в туннеле — перезапустите программу'
            }
        }
    }

    if ($VerboseDoctor) {
        Write-Host ''
        $warn = @()
        if ($S.Ruler.EnabledRules -gt 0 -and -not $S.Ruler.Running) { $warn += 'TrafikRuler не запущен, хотя есть включённые правила.' }
        if ($S.Ruler.EnabledRules -gt 0 -and -not $S.Ruler.Active -and $S.Ruler.Running) { $warn += 'Перехват не активен — проверьте log.txt TrafikRuler.' }
        if ($S.Wifi.Name -and -not $S.Wifi.HasDefault) { $warn += 'У Wi-Fi нет default-маршрута: правило «→ Wi-Fi» останется без интернета.' }
        if ($S.Wifi.Name -and -not $S.GatewaysDaemon) { $warn += 'keep-gateways не запущен: SoftEther снова срежет шлюз Wi-Fi.' }
        if ($S.Legacy.GuardRunning -or $S.Legacy.ManagedRoutes) { $warn += 'Осталась старая схема route-guard (маршруты по IP). Выполните -CleanupLegacy.' }
        if ($warn.Count) {
            foreach ($w in $warn) { Write-Host ("!! {0}" -f $w) -ForegroundColor Yellow }
        } else {
            Write-Host '✔ Схема в порядке.' -ForegroundColor Green
        }
    }
}

# ---------- действия ----------

if ($Bootstrap) {
    $c = Cleanup-LegacySplit
    Write-Host ("Legacy: остановлен guard {0}, удалено маршрутов {1}" -f $c.GuardStopped, $c.RoutesRemoved)
    Install-GatewaysTask
    Write-Host 'Шлюзы: задача VPNGateKeepGateways установлена, демон запущен.'
    if (Get-RulerExe) {
        try {
            Install-RulerTask
            Write-Host 'TrafikRuler: задача установлена, перехват запущен.'
        } catch {
            Write-Host ("TrafikRuler: задача не установлена — {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    } else {
        Write-Host 'TrafikRuler.exe не найден: пропускаю задачу.'
    }
}

if ($CleanupLegacy) {
    $c = Cleanup-LegacySplit
    Write-Host ("Legacy: остановлен guard {0}, удалено маршрутов {1}" -f $c.GuardStopped, $c.RoutesRemoved)
}

if ($StartGateways) { Start-GatewaysDaemon | Out-Null; Write-Host 'keep-gateways запущен.' }
if ($StopGateways) { $n = Stop-GatewaysDaemon; Write-Host "keep-gateways остановлен (процессов: $n)." }
if ($InstallGatewaysTask) { Install-GatewaysTask; Write-Host 'Задача VPNGateKeepGateways установлена.' }
if ($RemoveGatewaysTask) { Remove-GatewaysTask; Write-Host 'Задача VPNGateKeepGateways удалена.' }
if ($InstallRulerTask) { Install-RulerTask; Write-Host 'Задача TrafikRuler установлена.' }

if ($AddApp -or $AddApps) {
    $paths = @()
    if ($AddApp) { $paths += $AddApp }
    if ($AddApps) { $paths += @($AddApps -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $adapterObj = Resolve-Adapter $Adapter
    if (-not $adapterObj) { throw "Адаптер не найден: $Adapter" }
    $added = @()
    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) { throw "Файл не найден: $p" }
        $name = if ($DisplayName -and $paths.Count -eq 1) { $DisplayName } else { Get-RuleLeaf $p }
        $rule = Apply-RuleChange { param($s) Add-RuleToSettings $s $p $name $adapterObj ([bool]$EnableNew) }
        $added += $rule.DisplayName
    }
    Write-Host ("Добавлено/обновлено: {0} → {1}" -f ($added -join ', '), $adapterObj.Name)
}

if ($EnableRule -or $DisableRule) {
    $enable = [bool]$EnableRule
    $raw = if ($EnableRule) { $EnableRule } else { $DisableRule }
    $patterns = @($raw -split '\s*;\s*' | Where-Object { $_ })
    $changed = Apply-RuleChange {
        param($s)
        $out = @()
        foreach ($pat in $patterns) {
            $r = Find-Rule $s $pat
            if (-not $r) { throw "Правило не найдено: $pat" }
            $r.Enabled = $enable
            $out += $r
        }
        return $out
    }
    foreach ($r in @($changed)) {
        Write-Host ("{0}: {1}" -f $(if ($enable) { 'Включено' } else { 'Выключено' }), $r.DisplayName)
    }
}

if ($SetAdapterFor) {
    if (-not $Adapter) { throw 'Укажите -Adapter "Беспроводная сеть".' }
    $adapterObj = Resolve-Adapter $Adapter
    if (-not $adapterObj) { throw "Адаптер не найден: $Adapter" }
    $res = Apply-RuleChange {
        param($s)
        $r = Find-Rule $s $SetAdapterFor
        if (-not $r) { throw "Правило не найдено: $SetAdapterFor" }
        $r.AdapterId = [string]$adapterObj.InterfaceGuid
        $r.AdapterName = [string]$adapterObj.Name
        return $r
    }
    Write-Host ("{0} → {1}" -f $res.DisplayName, $adapterObj.Name)
}

if ($RemoveRule) {
    $res = Apply-RuleChange {
        param($s)
        $r = Find-Rule $s $RemoveRule
        if (-not $r) { throw "Правило не найдено: $RemoveRule" }
        $s.Rules = @(@($s.Rules) | Where-Object { $_.Id -ne $r.Id })
        return $r
    }
    Write-Host ("Удалено правило: {0}" -f $res.DisplayName)
}

if ($RestartRuler) { $n = Restart-Ruler; Write-Host "TrafikRuler перезапущен (было процессов: $n)." }
if ($EnsureRuler) { $started = Start-Ruler; Write-Host $(if ($started) { 'TrafikRuler запущен.' } else { 'TrafikRuler уже работает.' }) }

# ---------- вывод ----------

if ($Json) {
    $obj = Get-StatusObject
    $obj | ConvertTo-Json -Depth 8
    exit 0
}

if ($Doctor) {
    Show-Status (Get-StatusObject) -VerboseDoctor
    exit 0
}

if ($List) {
    $s = Get-StatusObject
    foreach ($r in $s.Rules) {
        $mark = if ($r.Enabled) { '[x]' } else { '[ ]' }
        $ad = if ($r.AdapterName) { $r.AdapterName } else { 'адаптер не задан' }
        Write-Host ("{0} {1} → {2}" -f $mark, $r.Name, $ad)
        Write-Host ("     {0}" -f $r.Path)
        if (-not $r.PathExists) { Write-Host '     !! файл не найден' }
    }
    exit 0
}

if ($Status -or $mutating -or $PSBoundParameters.Count -eq 0) {
    Show-Status (Get-StatusObject)
    exit 0
}

exit 0
