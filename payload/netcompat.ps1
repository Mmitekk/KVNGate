# Слой совместимости: те же имена, что у WMI-командлетов Net*, но источник —
# netsh/route.exe. Нужен там, где скрипт уже написан под cmdlet'ы и переписывать
# его целиком не хочется (route-guard.ps1).
#
# PowerShell отдаёт предпочтение функции cmdlet'у, поэтому после подключения
# этого файла Get-NetRoute и прочие идут мимо WMI.
#
# Подключать ПОСЛЕ netutil.ps1:
#   . (Join-Path $PSScriptRoot 'netutil.ps1')
#   . (Join-Path $PSScriptRoot 'netcompat.ps1')
#
# Поддерживается только тот набор параметров, который реально используется
# в скриптах VPN Gate.

function Get-NetAdapter {
    [CmdletBinding()]
    param()
    return @(Get-NuAdapters)
}

function Get-NetIPAddress {
    [CmdletBinding()]
    param(
        [int]$InterfaceIndex = 0,
        [string]$AddressFamily = 'IPv4'
    )
    $out = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-NuAdapters)) {
        if ($InterfaceIndex -gt 0 -and $a.ifIndex -ne $InterfaceIndex) { continue }
        foreach ($ip in $a.IPv4) {
            [void]$out.Add([pscustomobject]@{
                IPAddress = [string]$ip
                InterfaceAlias = [string]$a.Name
                InterfaceIndex = [int]$a.ifIndex
                PrefixLength = 24
                AddressFamily = 'IPv4'
            })
        }
    }
    return @($out.ToArray())
}

function Get-NetIPInterface {
    [CmdletBinding()]
    param(
        [int]$InterfaceIndex = 0,
        [string]$AddressFamily = 'IPv4'
    )
    $out = New-Object System.Collections.ArrayList
    $table = @(Get-NuInterfaceTable)
    foreach ($a in @(Get-NuAdapters)) {
        if ($InterfaceIndex -gt 0 -and $a.ifIndex -ne $InterfaceIndex) { continue }
        $metric = 0
        foreach ($row in $table) {
            if ($row.ifIndex -eq $a.ifIndex) { $metric = [int]$row.Metric; break }
        }
        [void]$out.Add([pscustomobject]@{
            InterfaceIndex = [int]$a.ifIndex
            InterfaceAlias = [string]$a.Name
            InterfaceMetric = $metric
            AddressFamily = 'IPv4'
        })
    }
    return @($out.ToArray())
}

function Get-NetRoute {
    [CmdletBinding()]
    param(
        [string[]]$DestinationPrefix = @(),
        [int]$InterfaceIndex = 0,
        [string]$AddressFamily = 'IPv4',
        [string]$PolicyStore = 'ActiveStore',
        [string]$Protocol = ''
    )
    $routes = @(Get-NuRoutes)
    if ($DestinationPrefix -and $DestinationPrefix.Count) {
        $routes = @($routes | Where-Object { $DestinationPrefix -contains $_.DestinationPrefix })
    }
    if ($InterfaceIndex -gt 0) {
        $routes = @($routes | Where-Object { $_.ifIndex -eq $InterfaceIndex })
    }
    if ($Protocol) {
        $routes = @($routes | Where-Object { $_.Protocol -eq $Protocol })
    }
    return @($routes)
}

function New-NetRoute {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$DestinationPrefix = '',
        [int]$InterfaceIndex = 0,
        [string]$NextHop = '0.0.0.0',
        [int]$RouteMetric = 0,
        [string]$PolicyStore = 'ActiveStore'
    )
    if (-not $DestinationPrefix -or $InterfaceIndex -le 0) { return }
    if ($PSCmdlet.ShouldProcess("route $DestinationPrefix via $NextHop")) {
        Add-NuRoute -Prefix $DestinationPrefix -Index $InterfaceIndex -NextHop $NextHop -Metric $RouteMetric | Out-Null
    }
}

function Remove-NetRoute {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$DestinationPrefix = '',
        [int]$InterfaceIndex = 0,
        [string]$NextHop = '0.0.0.0',
        [string]$PolicyStore = 'ActiveStore'
    )
    if (-not $DestinationPrefix -or $InterfaceIndex -le 0) { return }
    if ($PSCmdlet.ShouldProcess("route $DestinationPrefix via $NextHop")) {
        Remove-NuRoute -Prefix $DestinationPrefix -Index $InterfaceIndex -NextHop $NextHop | Out-Null
    }
}

function Get-NetTCPConnection {
    [CmdletBinding()]
    param(
        [string]$State = ''
    )
    $conns = @(Get-NuTcpConnections)
    if ($State) {
        $conns = @($conns | Where-Object { $_.State -eq $State })
    }
    return @($conns)
}

function Get-DnsClientServerAddress {
    [CmdletBinding()]
    param(
        [int]$InterfaceIndex = 0,
        [string]$AddressFamily = 'IPv4'
    )
    $out = New-Object System.Collections.ArrayList
    foreach ($a in @(Get-NuAdapters)) {
        if ($InterfaceIndex -gt 0 -and $a.ifIndex -ne $InterfaceIndex) { continue }
        [void]$out.Add([pscustomobject]@{
            InterfaceAlias = [string]$a.Name
            InterfaceIndex = [int]$a.ifIndex
            ServerAddresses = @(Get-NuDnsServers $a.ifIndex)
        })
    }
    return @($out.ToArray())
}

function Set-DnsClientServerAddress {
    [CmdletBinding()]
    param(
        [int]$InterfaceIndex = 0,
        [string[]]$ServerAddresses = @()
    )
    if ($InterfaceIndex -le 0 -or -not $ServerAddresses) { return }
    Set-NuDnsServers -Index $InterfaceIndex -Servers $ServerAddresses | Out-Null
}
