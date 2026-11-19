# Держит default-шлюз на физических адаптерах, пока SoftEther его срезает.
#
# Зачем: TrafikRuler умеет отправить программу на Wi-Fi или кабель только
# тогда, когда у этого адаптера есть маршрут по умолчанию. VPN Gate раз в
# пару секунд удаляет чужие 0.0.0.0/0, поэтому шлюз возвращается циклом.
#
# Метрика 30 хуже маршрута VPN (у него эффективная метрика около 2),
# поэтому программы без правила TrafikRuler остаются в туннеле.
#
# ВАЖНО: состояние сети берётся через netutil.ps1, а не через Net*-командлеты.
# Те идут через WMI, а WMI на Windows умеет заклинить (18.11.2026 так и было:
# провайдер перестал отвечать, демон завис, и маршрут в туннель перестал
# появляться — VPN был «подключён», но трафик шёл мимо). netutil работает
# через netsh/route.exe и не зависит от WMI.
#
# Запуск:
#   powershell -ExecutionPolicy Bypass -File keep-gateways.ps1        # демон
#   powershell -ExecutionPolicy Bypass -File keep-gateways.ps1 -Once  # один проход
[CmdletBinding()]
param(
    [switch]$Once
)

$ErrorActionPreference = 'SilentlyContinue'

$StateDir = Join-Path $env:LOCALAPPDATA 'VPNGateAuto'
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
$StateFile = Join-Path $StateDir 'physical-gateways.txt'
$VpnStateFile = Join-Path $StateDir 'vpn-gateway.txt'
$PidFile   = Join-Path $StateDir 'keep-gateways.pid'
$LogFile   = Join-Path $StateDir 'keep-gateways.log'
$RestartFlag = Join-Path $StateDir 'keep-gateways.restart'

$NetUtil = Join-Path $PSScriptRoot 'netutil.ps1'
if (Test-Path $NetUtil) { . $NetUtil }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin) -and -not $env:VPNGATE_NO_ELEVATE) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'))
    if ($Once) { $argList += '-Once' }
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -WindowStyle Hidden -Wait | Out-Null
        exit 0
    } catch {
        Write-Host "Не удалось получить права администратора: $($_.Exception.Message)"
        exit 1
    }
}

function Write-GwLog([string]$Text) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text
    try {
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 200KB)) {
            $tail = @(Get-Content $LogFile -Tail 200 -Encoding UTF8 -ErrorAction SilentlyContinue)
            [System.IO.File]::WriteAllLines($LogFile, $tail, (New-Object System.Text.UTF8Encoding($false)))
        }
        Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
}

function Get-DaemonPid {
    if (-not (Test-Path $PidFile)) { return 0 }
    $txt = (Get-Content $PidFile -Raw -ErrorAction SilentlyContinue).Trim()
    if ($txt -notmatch '^\d+$') { return 0 }
    $proc = Get-Process -Id ([int]$txt) -ErrorAction SilentlyContinue
    if ($proc) { return [int]$txt }
    return 0
}

if (-not $Once) {
    $runningPid = Get-DaemonPid
    if ($runningPid -and (Test-Path $RestartFlag)) {
        try {
            Stop-Process -Id $runningPid -Force -ErrorAction Stop
            Start-Sleep -Milliseconds 700
        } catch {}
    } elseif ($runningPid) {
        exit 0
    }
    Remove-Item $RestartFlag -Force -ErrorAction SilentlyContinue
    try { [System.IO.File]::WriteAllText($PidFile, "$PID") } catch {}
}

function Read-Saved {
    $map = @{}
    if (-not (Test-Path $StateFile)) { return $map }
    foreach ($line in @(Get-Content $StateFile -ErrorAction SilentlyContinue)) {
        $parts = $line -split '\|', 2
        if ($parts.Count -eq 2 -and $parts[1] -match '^\d{1,3}(\.\d{1,3}){3}$') {
            $map[$parts[0]] = $parts[1]
        }
    }
    return $map
}

function Write-Saved($Map) {
    $lines = @($Map.Keys | Sort-Object | ForEach-Object { "$_|$($Map[$_])" })
    try { [System.IO.File]::WriteAllLines($StateFile, $lines) } catch {}
}

function Get-GatewayFor($Adapter, [string]$Saved) {
    $idx = [int]$Adapter.ifIndex

    # 1. Живой default-маршрут на этом адаптере.
    $live = @(Get-NuDefaultRoutes | Where-Object {
        $_.ifIndex -eq $idx -and $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -notmatch '^10\.2\d\d\.'
    } | Sort-Object Metric | Select-Object -First 1)
    if ($live) { return [string]$live[0].NextHop }

    # 2. Шлюз из настройки адаптера (DHCP или статический).
    if ($Adapter.Gateway -and $Adapter.Gateway.Count) {
        foreach ($g in $Adapter.Gateway) {
            if ($g -and $g -ne '0.0.0.0') { return [string]$g }
        }
    }

    # 3. DHCP-шлюз остаётся в реестре даже после того, как SoftEther удалил
    #    маршрут из активной таблицы.
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($Adapter.InterfaceGuid)"
    if ($Adapter.InterfaceGuid) {
        foreach ($name in @('DhcpDefaultGateway', 'DefaultGateway')) {
            $val = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).$name
            if ($val) {
                $first = @($val) | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -ne '0.0.0.0' } | Select-Object -First 1
                if ($first) { return [string]$first }
            }
        }
    }

    # 4. Сохранённый ранее шлюз.
    if ($Saved -and $Saved -match '^\d{1,3}(\.\d{1,3}){3}$') { return $Saved }

    # 5. Любой next hop этого адаптера из таблицы маршрутов.
    $alt = @(Get-NuRoutes | Where-Object {
        $_.ifIndex -eq $idx -and $_.NextHop -match '^(192\.168|10)\.\d{1,3}\.\d{1,3}$' -and $_.NextHop -notmatch '^10\.2\d\d\.'
    } | Select-Object -First 1)
    if ($alt) { return [string]$alt[0].NextHop }

    return $null
}

function Get-VpnAdapter {
    $ad = Get-NuVpnAdapter
    if ($ad) { return $ad }
    return $null
}

function Get-VpnGateway($Adapter) {
    if (-not $Adapter) { return $null }
    $live = @(Get-NuDefaultRoutes | Where-Object {
        $_.ifIndex -eq $Adapter.ifIndex -and $_.NextHop -and $_.NextHop -ne '0.0.0.0'
    } | Sort-Object Metric | Select-Object -First 1)
    if ($live) {
        try { [System.IO.File]::WriteAllText($VpnStateFile, [string]$live[0].NextHop) } catch {}
        return [string]$live[0].NextHop
    }

    if (Test-Path $VpnStateFile) {
        $saved = (Get-Content -Raw $VpnStateFile -ErrorAction SilentlyContinue).Trim()
        if ($saved -match '^\d{1,3}(\.\d{1,3}){3}$') { return $saved }
    }

    if ($Adapter.Gateway -and $Adapter.Gateway.Count) {
        $g = @($Adapter.Gateway | Where-Object { $_ -and $_ -ne '0.0.0.0' } | Select-Object -First 1)
        if ($g) {
            try { [System.IO.File]::WriteAllText($VpnStateFile, [string]$g[0]) } catch {}
            return [string]$g[0]
        }
    }

    # VPN Gate всегда выдаёт один и тот же шлюз виртуального хаба.
    $ip = @(Get-NuAdapterIp $Adapter.ifIndex)
    if ($ip -and $ip -match '^10\.2\d\d\.') { return '10.211.254.254' }
    return $null
}

function Invoke-Pass {
    $saved = Read-Saved
    $next = @{}
    $changed = 0
    $defaults = @(Get-NuDefaultRoutes)
    $adapters = @(Get-NuPhysicalAdapters)
    foreach ($ad in $adapters) {
        $gw = Get-GatewayFor $ad $saved[$ad.Name]
        if (-not $gw -or $gw -eq '0.0.0.0') { continue }
        $next[$ad.Name] = $gw

        $has = @($defaults | Where-Object { $_.ifIndex -eq $ad.ifIndex -and $_.NextHop -eq $gw })
        if ($has.Count -eq 0) {
            if (Add-NuRoute -Prefix '0.0.0.0/0' -Index $ad.ifIndex -NextHop $gw -Metric 30) {
                Write-GwLog "default $($ad.Name): $gw (метрика 30)"
                $changed++
            }
        }
    }
    if ($next.Count) { Write-Saved $next }

    # NOTRACK у SoftEther выключает правку таблицы маршрутов, поэтому
    # default в туннель после переподключения возвращаем сами.
    $vpn = Get-VpnAdapter
    if ($vpn) {
        $vip = Get-NuAdapterIp $vpn.ifIndex
        if ($vip) {
            $vgw = Get-VpnGateway $vpn
            if ($vgw) {
                $hasVpn = @($defaults | Where-Object { $_.ifIndex -eq $vpn.ifIndex -and $_.NextHop -eq $vgw })
                if ($hasVpn.Count -eq 0) {
                    if (Add-NuRoute -Prefix '0.0.0.0/0' -Index $vpn.ifIndex -NextHop $vgw -Metric 1) {
                        Write-GwLog "default VPN ($($vpn.Name)): $vgw (метрика 1)"
                        $changed++
                    }
                }
            }
        }
    }
    return $changed
}

if ($Once) {
    $n = Invoke-Pass
    Write-Output $n
    exit 0
}

Write-GwLog "keep-gateways запущен (pid $PID)"
$fails = 0
try {
    while ($true) {
        try {
            $null = Invoke-Pass
            $fails = 0
        } catch {
            $fails++
            if ($fails -le 5 -or ($fails % 20) -eq 0) {
                Write-GwLog "ошибка прохода: $($_.Exception.Message)"
            }
        }
        Start-Sleep -Milliseconds 1000
    }
} finally {
    try { Remove-Item $PidFile -Force -ErrorAction SilentlyContinue } catch {}
    Write-GwLog 'keep-gateways остановлен'
}
