# Держит default-шлюз на физических адаптерах, пока SoftEther его срезает.
#
# Зачем: TrafikRuler умеет отправить программу на Wi-Fi или кабель только
# тогда, когда у этого адаптера есть маршрут по умолчанию. VPN Gate раз в
# пару секунд удаляет чужие 0.0.0.0/0, поэтому шлюз возвращается циклом.
#
# Метрика 30 хуже маршрута VPN (у него эффективная метрика около 2),
# поэтому программы без правила TrafikRuler остаются в туннеле.
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
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$txt)" -ErrorAction SilentlyContinue
    if ($proc -and $proc.CommandLine -like '*keep-gateways.ps1*') { return [int]$txt }
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

function Get-PhysicalAdapters {
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and
        $_.Name -notmatch 'VPN|Radmin|TAP|TUN|vEthernet|WSL|Hyper-V|Loopback' -and
        $_.InterfaceDescription -notmatch 'VPN Client Adapter|TAP|TUN|Hyper-V|Virtual Adapter'
    })
    $result = @()
    foreach ($ad in $adapters) {
        $ip = @(Get-NetIPAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1)
        if ($ip) { $result += $ad }
    }
    return @($result)
}

function Get-GatewayFor($Adapter, [string]$Saved) {
    $idx = [int]$Adapter.ifIndex
    $live = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $idx -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -notmatch '^10\.211\.' } |
        Sort-Object RouteMetric | Select-Object -First 1)
    if ($live) { return [string]$live[0].NextHop }

    $cfg = Get-NetIPConfiguration -InterfaceIndex $idx -ErrorAction SilentlyContinue
    $gw = @($cfg.IPv4DefaultGateway | Where-Object { $_.NextHop } | Select-Object -First 1)
    if ($gw) { return [string]$gw[0].NextHop }

    # DHCP-шлюз остаётся в реестре даже после того, как SoftEther удалил
    # маршрут из активной таблицы.
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($Adapter.InterfaceGuid)"
    foreach ($name in @('DhcpDefaultGateway', 'DefaultGateway')) {
        $val = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction SilentlyContinue).$name
        if ($val) {
            $first = @($val) | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -ne '0.0.0.0' } | Select-Object -First 1
            if ($first) { return [string]$first }
        }
    }

    if ($Saved -and $Saved -match '^\d{1,3}(\.\d{1,3}){3}$') { return $Saved }

    $alt = @(Get-NetRoute -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -match '^(192\.168|10)\.\d{1,3}\.\d{1,3}$' -and $_.NextHop -notmatch '^10\.211\.' } |
        Select-Object -First 1)
    if ($alt) { return [string]$alt[0].NextHop }
    return $null
}

function Get-VpnAdapter {
    return @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and
        ($_.InterfaceDescription -match 'VPN Client Adapter' -or $_.Name -match ' - VPN Client$')
    } | Select-Object -First 1)
}

function Get-VpnGateway($Adapter) {
    if (-not $Adapter) { return $null }
    $live = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $Adapter.ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
        Sort-Object RouteMetric | Select-Object -First 1)
    if ($live) {
        try { [System.IO.File]::WriteAllText($VpnStateFile, [string]$live[0].NextHop) } catch {}
        return [string]$live[0].NextHop
    }

    if (Test-Path $VpnStateFile) {
        $saved = (Get-Content -Raw $VpnStateFile -ErrorAction SilentlyContinue).Trim()
        if ($saved -match '^\d{1,3}(\.\d{1,3}){3}$') { return $saved }
    }

    $cfg = Get-NetIPConfiguration -InterfaceIndex $Adapter.ifIndex -ErrorAction SilentlyContinue
    $gw = @($cfg.IPv4DefaultGateway | Where-Object { $_.NextHop } | Select-Object -First 1)
    if ($gw) {
        try { [System.IO.File]::WriteAllText($VpnStateFile, [string]$gw[0].NextHop) } catch {}
        return [string]$gw[0].NextHop
    }

    # VPN Gate всегда выдаёт один и тот же шлюз виртуального хаба.
    $ip = @(Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1)
    if ($ip -and ([string]$ip[0].IPAddress) -match '^10\.211\.') { return '10.211.254.254' }
    return $null
}

function Invoke-Pass {
    $saved = Read-Saved
    $next = @{}
    $changed = 0
    foreach ($ad in Get-PhysicalAdapters) {
        $guid = [string]$ad.InterfaceGuid
        $gw = Get-GatewayFor $ad $saved[$guid]
        if (-not $gw -or $gw -eq '0.0.0.0') { continue }
        $next[$guid] = $gw

        $has = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ad.ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $gw })
        if ($has.Count -eq 0) {
            New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ad.ifIndex -NextHop $gw `
                -RouteMetric 30 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
            Write-GwLog "default $($ad.Name): $gw (метрика 30)"
            $changed++
        }
    }
    if ($next.Count) { Write-Saved $next }

    # NOTRACK у SoftEther выключает правку таблицы маршрутов, поэтому
    # default в туннель после переподключения возвращаем сами.
    $vpn = Get-VpnAdapter
    if ($vpn) {
        $vip = @(Get-NetIPAddress -InterfaceIndex $vpn.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\.254\.' } | Select-Object -First 1)
        if ($vip) {
            $vgw = Get-VpnGateway $vpn
            if ($vgw) {
                $hasVpn = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $vpn.ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
                    Where-Object { $_.NextHop -eq $vgw })
                if ($hasVpn.Count -eq 0) {
                    New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $vpn.ifIndex -NextHop $vgw `
                        -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
                    Write-GwLog "default VPN ($($vpn.Name)): $vgw (метрика 1)"
                    $changed++
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
try {
    while ($true) {
        Invoke-Pass | Out-Null
        Start-Sleep -Milliseconds 300
    }
} finally {
    try { Remove-Item $PidFile -Force -ErrorAction SilentlyContinue } catch {}
    Write-GwLog 'keep-gateways остановлен'
}
