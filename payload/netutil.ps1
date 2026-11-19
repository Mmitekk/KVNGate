# Общие сетевые помощники для скриптов VPN Gate.
#
# ЗАЧЕМ ЭТОТ ФАЙЛ
#
# Скрипты VPN Gate раньше опирались только на Net*-командлеты
# (Get-NetAdapter, Get-NetRoute, Get-NetIPAddress). Они работают через WMI,
# а WMI на Windows умеет заклинить: провайдер сети перестаёт отвечать, все
# вызовы виснут или отменяются с RPC_E_CALL_CANCELED. 18.11.2026 так и было:
# демон шлюзов умер, автоподключение VPN считало живые шлюзы мёртвыми, а
# панель «Приложения без VPN» не отвечала.
#
# Здесь тот же набор данных берётся без WMI:
#   • адаптеры, адреса, шлюзы, DNS  — System.Net.NetworkInformation;
#   • таблица маршрутов             — route print -4;
#   • соединения                    — netstat -ano;
#   • правка маршрутов и DNS        — netsh (нужен только код возврата).
#
# ВАЖНО про язык: netsh, ipconfig и route print печатают заголовки на языке
# системы, поэтому их вывод НЕ парсится по названиям колонок — только по
# позициям и значениям. Иначе на русской Windows разбор ломался.
#
# Подключение:  . (Join-Path $PSScriptRoot 'netutil.ps1')

# ---------- запуск внешних утилит ----------

function Invoke-NuTool {
    # Запуск утилиты с жёстким таймаутом.
    #
    # Зачем: netsh/route.exe умеют зависать намертво (например, когда
    # SoftEther в этот же момент перестраивает таблицу маршрутов). Раньше
    # такой вызов блокировал демон шлюзов и автоподключение. Теперь утилита
    # убивается по таймауту, и работа продолжается.
    param(
        [string]$Exe,
        [string[]]$ArgList = @(),
        [int]$TimeoutMs = 8000
    )
    $text = ''
    $code = -1
    $proc = $null
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Exe
        $psi.Arguments = ($ArgList | ForEach-Object {
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        }) -join ' '
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        # Утилиты Windows печатают в OEM-кодировке консоли.
        try { $psi.StandardOutputEncoding = [System.Text.Encoding]::GetEncoding(866) } catch {}
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        $null = $proc.Start()
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        if (-not $proc.WaitForExit($TimeoutMs)) {
            try { $proc.Kill() } catch {}
            try { $null = $proc.WaitForExit(3000) } catch {}
        } else {
            $code = $proc.ExitCode
        }
        try { $text = $outTask.Result } catch { $text = '' }
        try { $null = $errTask.Result } catch {}
    } catch {
        $text = ''
        $code = -1
    } finally {
        if ($proc) { try { $proc.Dispose() } catch {} }
    }
    return [pscustomobject]@{ Text = $text; Exit = $code }
}

function Invoke-NuText([string]$Exe, [string[]]$ArgList) {
    return (Invoke-NuTool -Exe $Exe -ArgList $ArgList -TimeoutMs 8000).Text
}

# ---------- маски и префиксы ----------

function ConvertFrom-NuMask([string]$Mask) {
    if ($Mask -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return -1 }
    $b = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    $bits = 0
    foreach ($v in $b) {
        if ($v -lt 0 -or $v -gt 255) { return -1 }
        for ($i = 7; $i -ge 0; $i--) {
            if ($v -band (1 -shl $i)) { $bits++ } else { break }
        }
    }
    return $bits
}

function ConvertTo-NuPrefix([string]$Address, [int]$Bits = 32) {
    return "$Address/$Bits"
}

# ---------- адаптеры (без WMI, без разбора локализованного текста) ----------

function Get-NuAdapterList {
    # Name, Description, Status, IsUp, ifIndex, IPv4[], Gateway[], Dns[]
    $out = New-Object System.Collections.ArrayList
    try {
        $all = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
    } catch {
        return @()
    }
    foreach ($ni in $all) {
        $props = $null
        try { $props = $ni.GetIPProperties() } catch { continue }
        $idx = 0
        try { $idx = [int]$props.GetIPv4Properties().Index } catch { $idx = 0 }
        $ips = @()
        $gws = @()
        $dns = @()
        try {
            foreach ($u in $props.UnicastAddresses) {
                if ($u.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $ips += [string]$u.Address
                }
            }
            foreach ($g in $props.GatewayAddresses) {
                if ($g.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $gws += [string]$g.Address
                }
            }
            foreach ($d in $props.DnsAddresses) {
                if ($d.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                    $dns += [string]$d
                }
            }
        } catch {}
        $status = ''
        try { $status = [string]$ni.OperationalStatus } catch {}
        $up = ($status -eq 'Up')
        [void]$out.Add([pscustomobject]@{
            Name = [string]$ni.Name
            Description = [string]$ni.Description
            Status = $(if ($up) { 'Up' } else { 'Down' })
            IsUp = $up
            RawStatus = $status
            ifIndex = $idx
            InterfaceIndex = $idx
            InterfaceGuid = [string]$ni.Id
            IPv4 = @($ips)
            Gateway = @($gws)
            Dns = @($dns)
            Metric = 0
        })
    }
    return @($out.ToArray())
}

function Get-NuAdapters {
    return @(Get-NuAdapterList)
}

function Get-NuPhysicalAdapters {
    # Адаптеры «домашней» сети: поднятые, с адресом и шлюзом, без виртуальных.
    return @(Get-NuAdapterList | Where-Object {
        $_.IsUp -and
        $_.IPv4.Count -gt 0 -and
        $_.Gateway.Count -gt 0 -and
        $_.Name -notmatch 'VPN|Radmin|TAP|TUN|vEthernet|WSL|Hyper-V|Loopback|Подключение по локальной сети' -and
        $_.Description -notmatch 'VPN Client Adapter|TAP|TUN|Hyper-V|Virtual Adapter'
    })
}

function Get-NuVpnAdapter {
    # Адаптер SoftEther: имя вида «VPN2 - VPN Client».
    return @(Get-NuAdapterList | Where-Object {
        $_.Name -match ' - VPN Client$' -or $_.Description -match 'VPN Client Adapter'
    } | Select-Object -First 1)
}

function Get-NuAdapterIp([int]$Index) {
    $ad = @(Get-NuAdapterList | Where-Object { $_.ifIndex -eq $Index } | Select-Object -First 1)
    if (-not $ad) { return $null }
    $ip = @($ad[0].IPv4 | Where-Object { $_ -and $_ -notmatch '^169\.254\.' -and $_ -ne '0.0.0.0' })
    if ($ip.Count) { return [string]$ip[0] }
    return $null
}

function Get-NuAdapterByName([string]$Name) {
    return @(Get-NuAdapterList | Where-Object { $_.Name -eq $Name } | Select-Object -First 1)
}

function Get-NuInterfaceMetric([int]$Index) {
    # Метрика интерфейса нужна только для показа в панели.
    foreach ($row in (Get-NuInterfaceTable)) {
        if ($row.ifIndex -eq $Index) { return [int]$row.Metric }
    }
    return 0
}

function Get-NuInterfaceTable {
    # Idx / Met / Name из netsh. Строки разбираются по позициям: заголовки
    # утилиты локализованы, а данные — нет.
    $list = New-Object System.Collections.ArrayList
    $text = Invoke-NuText 'netsh.exe' @('interface','ipv4','show','interfaces')
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*(\d{1,3})\s+(\d{1,6})\s+(\d{1,12})\s+(\S+)\s+(.+)$') {
            $idx = [int]$Matches[1]
            $met = [int]$Matches[2]
            $nm = $Matches[5].Trim()
            [void]$list.Add([pscustomobject]@{
                ifIndex = $idx
                Metric = $met
                State = $Matches[4]
                Name = $nm
            })
        }
    }
    return @($list.ToArray())
}

# ---------- маршруты ----------

function Get-NuRoutes {
    # Все активные маршруты IPv4: Prefix, NextHop, ifIndex, Metric, InterfaceAlias.
    #
    # Источник — route print -4. У route.exe колонки: адрес, маска, шлюз,
    # интерфейс, метрика. Заголовки локализованы, данные — нет, поэтому
    # строки разбираются по позициям. Метрика в route print уже итоговая
    # (метрика маршрута + метрика интерфейса).
    $rows = New-Object System.Collections.ArrayList
    $text = Invoke-NuText 'route.exe' @('print','-4')
    $seen = $false
    foreach ($line in ($text -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        if ($t -match '^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s+(\d+)\s*$') {
            $dest = $Matches[1]
            $mask = $Matches[2]
            $gw = $Matches[3]
            $ifIp = $Matches[4]
            $met = [int]$Matches[5]
            $bits = ConvertFrom-NuMask $mask
            if ($bits -lt 0) { continue }
            $idx = 0
            $alias = ''
            foreach ($a in (Get-NuAdapterList)) {
                if ($a.IPv4 -contains $ifIp) { $idx = $a.ifIndex; $alias = $a.Name; break }
            }
            [void]$rows.Add([pscustomobject]@{
                DestinationPrefix = "$dest/$bits"
                NextHop = $gw
                ifIndex = $idx
                InterfaceIndex = $idx
                Metric = $met
                RouteMetric = $met
                InterfaceMetric = 0
                InterfaceAlias = $alias
                Protocol = 'NetMgmt'
                Store = 'Active'
            })
            $seen = $true
        } elseif ($seen) {
            # Дальше идёт раздел постоянных маршрутов — активные закончились.
            break
        }
    }
    return @($rows.ToArray())
}

function Get-NuDefaultRoutes {
    return @(Get-NuRoutes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' })
}

function Add-NuRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][int]$Index,
        [string]$NextHop = '0.0.0.0',
        [int]$Metric = 1,
        [switch]$Persistent
    )
    $r = Invoke-NuTool 'netsh.exe' @('interface','ipv4','add','route',("prefix=$Prefix"),("interface=$Index"),("nexthop=$NextHop"),("metric=$Metric"),'store=active')
    return ($r.Exit -eq 0)
}

function Remove-NuRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][int]$Index,
        [string]$NextHop = '0.0.0.0'
    )
    $r = Invoke-NuTool 'netsh.exe' @('interface','ipv4','delete','route',("prefix=$Prefix"),("interface=$Index"),("nexthop=$NextHop"))
    return ($r.Exit -eq 0)
}

function Get-NuRouteExists {
    param([string]$Prefix, [int]$Index, [string]$NextHop)
    foreach ($r in (Get-NuRoutes)) {
        if ($r.DestinationPrefix -ne $Prefix) { continue }
        if ($Index -gt 0 -and $r.ifIndex -ne $Index) { continue }
        if ($NextHop -and $r.NextHop -ne $NextHop) { continue }
        return $true
    }
    return $false
}

# ---------- DNS ----------

function Get-NuDnsServers([int]$Index) {
    $ad = @(Get-NuAdapterList | Where-Object { $_.ifIndex -eq $Index } | Select-Object -First 1)
    if (-not $ad) { return @() }
    return @($ad[0].Dns)
}

function Set-NuDnsServers([int]$Index, [string[]]$Servers) {
    $ad = @(Get-NuAdapterList | Where-Object { $_.ifIndex -eq $Index } | Select-Object -First 1)
    if (-not $ad -or -not $Servers -or -not $Servers.Count) { return $false }
    $list = ($Servers -join ',')
    $r = Invoke-NuTool 'netsh.exe' @('interface','ipv4','set','dnsservers',("name=$($ad[0].Name)"),'source=static',("address=$list"),'validate=no')
    return ($r.Exit -eq 0)
}

# ---------- соединения ----------

function Get-NuTcpConnections {
    # Established-соединения: LocalAddress, LocalPort, RemoteAddress, RemotePort, Pid.
    $rows = New-Object System.Collections.ArrayList
    $text = Invoke-NuText 'netstat.exe' @('-ano')
    foreach ($line in ($text -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        if ($t -notmatch '^TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$') { continue }
        if ($Matches[5] -ne 'ESTABLISHED') { continue }
        $la = $Matches[1]; $lp = [int]$Matches[2]
        $ra = $Matches[3]; $rp = [int]$Matches[4]
        $pid2 = [int]$Matches[6]
        if ($la -match '^\[?(\d{1,3}(?:\.\d{1,3}){3})\]?$') { $la = $Matches[1] }
        if ($ra -match '^\[?(\d{1,3}(?:\.\d{1,3}){3})\]?$') { $ra = $Matches[1] }
        [void]$rows.Add([pscustomobject]@{
            LocalAddress = $la
            LocalPort = $lp
            RemoteAddress = $ra
            RemotePort = $rp
            Pid = $pid2
            OwningProcess = $pid2
            State = 'Established'
        })
    }
    return @($rows.ToArray())
}
