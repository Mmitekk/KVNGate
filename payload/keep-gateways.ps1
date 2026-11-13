# Держит шлюз по умолчанию на физических адаптерах, пока включён SoftEther.
# VPN Gate раз в пару секунд удаляет чужие 0.0.0.0/0. Без шлюза TrafikRuler
# не может отправить программу на Wi-Fi или кабель.
# Метрика 30 хуже маршрута VPN, поэтому программы без правила остаются в туннеле.
$ErrorActionPreference = 'SilentlyContinue'
$StateDir = Join-Path $env:LOCALAPPDATA 'VPNGateAuto'
if (-not (Test-Path $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
$StateFile = Join-Path $StateDir 'physical-gateways.txt'

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
    [System.IO.File]::WriteAllLines($StateFile, $lines)
}

function Get-Hop([int]$IfIndex, [string]$Saved) {
    $live = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $IfIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.NextHop -notmatch '^10\.211\.' })
    if ($live) { return [string]$live[0].NextHop }
    if ($Saved) { return $Saved }
    $cfg = Get-NetIPConfiguration -InterfaceIndex $IfIndex -ErrorAction SilentlyContinue
    $gw = @($cfg.IPv4DefaultGateway | Where-Object { $_.NextHop })
    if ($gw) { return [string]$gw[0].NextHop }
    $alt = @(Get-NetRoute -InterfaceIndex $IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -match '^(192\.168|10)\.\d{1,3}\.\d{1,3}$' })
    if ($alt) { return [string]$alt[0].NextHop }
    return $null
}

$saved = Read-Saved
while ($true) {
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq 'Up' -and
        $_.Name -notmatch 'VPN|Radmin|TAP|TUN|vEthernet|WSL|Hyper-V|Loopback' -and
        $_.InterfaceDescription -notmatch 'VPN Client Adapter|TAP|TUN|Hyper-V'
    })
    $next = @{}
    foreach ($ad in $adapters) {
        $guid = [string]$ad.InterfaceGuid
        $hop = Get-Hop -IfIndex $ad.ifIndex -Saved $saved[$guid]
        if (-not $hop) { continue }
        $next[$guid] = $hop
        $has = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ad.ifIndex -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $hop })
        if ($has.Count -eq 0) {
            New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ad.ifIndex -NextHop $hop -RouteMetric 30 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
        }
    }
    if ($next.Count) { Write-Saved $next; $saved = $next }
    Start-Sleep -Milliseconds 300
}
