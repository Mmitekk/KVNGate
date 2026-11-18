# Окно VPN Gate: скорость текущего шлюза и кнопки оставить / пропустить / отключить.
# Само подключение делает соседний vpn-auto.ps1. Закрытие окна туннель не рвёт.

$ErrorActionPreference = 'Stop'
if (-not ('Win32Tray' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win32Tray {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
    [DllImport("kernel32.dll")] public static extern bool FreeConsole();
}
'@
}
$script:allowHide = $true
try {
    [Win32Tray]::ShowWindow([Win32Tray]::GetConsoleWindow(), 0) | Out-Null
    [Win32Tray]::FreeConsole() | Out-Null
} catch {}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$auto = Join-Path $here 'vpn-auto.ps1'
if (-not (Test-Path $auto)) { throw "Рядом нет vpn-auto.ps1: $auto" }

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:busy = $false
$script:proc = $null
$script:reportPath = $null
$script:current = $null
$script:appRules = @()
$script:appsLoading = $false
$script:appsBusy = $false
$script:appsRefresh = $null
$script:lines = New-Object System.Collections.Concurrent.ConcurrentQueue[string]
$script:splitPath = Join-Path $here 'split-tunnel.ps1'

function New-Button([string]$text, [int]$x, [int]$y, [int]$w) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Left = $x
    $b.Top = $y
    $b.Width = $w
    $b.Height = 34
    $b.FlatStyle = 'Flat'
    $b.BackColor = [System.Drawing.Color]::FromArgb(42, 46, 42)
    $b.ForeColor = [System.Drawing.Color]::FromArgb(235, 236, 234)
    $b.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(70, 76, 70)
    return $b
}

function Set-Busy([bool]$on, [string]$status) {
    $script:busy = $on
    foreach ($b in @($script:btnConnect, $script:btnNext, $script:btnMeasure, $script:btnOff)) {
        $b.Enabled = -not $on
    }
    if ($status) { $script:lblState.Text = $status }
    Update-TrayTip
}

function Update-TrayTip {
    if (-not $script:notify) { return }
    $tip = 'VPN Gate'
    if ($script:current -and $script:current.ok) {
        $bits = @(
            $(if ($script:current.country -and $script:current.country -ne '?') { [string]$script:current.country } else { [string]$script:current.exitCountry }),
            [string]$script:current.ip,
            $(if ($script:current.host -and $script:current.host -ne 'текущий' -and $script:current.host -ne '?') { [string]$script:current.host })
        ) | Where-Object { $_ }
        if ($bits) { $tip = $bits -join ' · ' }
    } elseif ($script:lblState -and $script:lblState.Text) {
        $tip = 'VPN Gate — ' + $script:lblState.Text
    }
    if ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }
    $script:notify.Text = $tip
}

function Show-MainWindow {
    $script:allowHide = $false
    $form.ShowInTaskbar = $true
    $form.Show()
    $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
    $form.Activate()
    try { [Win32Tray]::SetForegroundWindow($form.Handle) | Out-Null } catch {}
    $script:allowHide = $true
}

function Hide-ToTray {
    if (-not $script:allowHide) { return }
    $script:allowHide = $false
    $form.ShowInTaskbar = $false
    $form.Hide()
    $script:notify.Visible = $true
    $script:allowHide = $true
}

function Add-Log([string]$line) {
    if (-not $line) { return }
    $script:log.AppendText($line.TrimEnd() + [Environment]::NewLine)
    $script:log.SelectionStart = $script:log.TextLength
    $script:log.ScrollToCaret()
}

function Show-AccountList($r) {
    if (-not $script:lst) { return }
    $script:lst.Items.Clear()
    $accounts = @()
    if ($r -and $r.accounts) { $accounts = @($r.accounts) }
    if ($accounts.Count -eq 0) {
        [void]$script:lst.Items.Add('В SoftEther нет сессий')
        return
    }
    foreach ($a in $accounts) {
        $mark = if ($a.connected) { 'вкл' } else { [string]$a.status }
        $bits = @([string]$a.country, [string]$a.host, $(if ($a.ip) { '{0}:{1}' -f $a.ip, $a.port })) | Where-Object { $_ }
        [void]$script:lst.Items.Add(('{0,-10} {1}   {2}' -f $mark, $a.name, ($bits -join '   ')))
    }
}

function Show-Report($r) {
    $script:current = $r
    Show-AccountList $r

    $listTitle = 'Сессии SoftEther'
    if ($r -and $r.speedMbps) { $listTitle += ('   в списке {0} Мбит/с' -f $r.speedMbps) }
    if ($r -and $r.rotationRound -and $r.rotationSeen) {
        $rot = if ($r.rotationTotal -and [int]$r.rotationTotal -ge [int]$r.rotationSeen) {
            'круг {0} · шлюз {1} из {2}' -f [int]$r.rotationRound, [int]$r.rotationSeen, [int]$r.rotationTotal
        } else {
            'круг {0} · пройдено {1}' -f [int]$r.rotationRound, [int]$r.rotationSeen
        }
        $listTitle += '   ' + $rot
    }
    $script:lblList.Text = $listTitle

    if (-not $r -or -not $r.ok) {
        $script:lblCountry.Text = 'Нет активного туннеля'
        $script:lblServer.Text = if ($r.message) { [string]$r.message } else { 'Не подключено' }
        $script:lblAddr.Text = ''
        $script:lblExit.Text = ''
        Update-TrayTip
        return
    }
    $countryName = if ($r.country -and $r.country -ne '?' -and $r.country -ne '??') { [string]$r.country } elseif ($r.exitCountry) { [string]$r.exitCountry } else { 'не определилась' }
    $hostName = if ($r.host -and $r.host -ne 'текущий' -and $r.host -ne '?') { [string]$r.host } else { 'имя не пришло' }
    $script:lblCountry.Text = 'Страна:  ' + $countryName
    $script:lblServer.Text = 'Хост:  ' + $hostName
    $script:lblAddr.Text = 'IP шлюза:  ' + $(if ($r.ip) { '{0}:{1}' -f $r.ip, $r.port } else { 'неизвестен' })
    $exit = @($r.exitIp, $r.exitCountry) | Where-Object { $_ }
    $script:lblExit.Text = if ($exit) { 'Снаружи  ' + ($exit -join ' ') } else { 'Снаружи  адрес не определился' }
    Update-TrayTip
}

function Measure-Quality {
    $pingText = 'нет ответа'
    try {
        $samples = @(Test-Connection -ComputerName '1.1.1.1' -Count 4 -ErrorAction SilentlyContinue)
        $times = @($samples | Where-Object { $null -ne $_.ResponseTime } | ForEach-Object { [int]$_.ResponseTime })
        if ($times.Count -gt 0) {
            $avg = [int](($times | Measure-Object -Average).Average)
            $pingText = ('{0} мс, ответов {1}/4' -f $avg, $times.Count)
        }
    } catch {}

    $downText = 'не скачалось'
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        $raw = & curl.exe -4 -sS -o NUL -w '%{size_download} %{time_total}' --max-time 20 'https://speed.cloudflare.com/__down?bytes=2000000' 2>$null
        $parts = @(($raw | Out-String).Trim() -split '\s+')
        if ($parts.Count -ge 2) {
            $inv = [Globalization.CultureInfo]::InvariantCulture
            $bytes = 0.0
            $sec = 0.0
            $okBytes = [double]::TryParse($parts[0], [Globalization.NumberStyles]::Float, $inv, [ref]$bytes)
            $okSec = [double]::TryParse($parts[1], [Globalization.NumberStyles]::Float, $inv, [ref]$sec)
            if ($okBytes -and $okSec -and $bytes -gt 100000 -and $sec -gt 0) {
                $downText = ('{0} Мбит/с за {1} с' -f ([math]::Round(($bytes * 8) / $sec / 1000000, 1)), ([math]::Round($sec, 1)))
            }
        }
    }
    return [pscustomobject]@{ Ping = $pingText; Down = $downText }
}

function Start-Measure {
    Set-Busy $true 'Меряю пинг и загрузку…'
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript(${function:Measure-Quality})
    $script:measure = @{ Ps = $ps; Rs = $rs; Handle = $ps.BeginInvoke() }
}

function Start-Auto([string]$status, [string[]]$extra) {
    if ($script:proc -and -not $script:proc.HasExited) { return }
    Set-Busy $true $status
    $script:reportPath = Join-Path $env:TEMP ('vpngate-ui-' + [guid]::NewGuid().ToString('n') + '.json')
    $isInventory = $false
    $clean = @()
    foreach ($a in @($extra)) {
        if ($a -eq '-Inventory') { $isInventory = $true } else { $clean += $a }
    }
    $argList = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $auto,
        '-ReportPath', $script:reportPath
    )
    if ($isInventory) { $argList += '-Inventory' } else { $argList += '-Once' }
    $argList += $clean
    $quoted = foreach ($a in $argList) {
        if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = ($quoted -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $psi.EnvironmentVariables['VPNGATE_NO_ELEVATE'] = '1'
    $script:proc = New-Object System.Diagnostics.Process
    $script:proc.StartInfo = $psi
    $script:proc.EnableRaisingEvents = $true
    $null = Register-ObjectEvent -InputObject $script:proc -EventName OutputDataReceived -MessageData $script:lines -Action {
        if ($EventArgs.Data) { $Event.MessageData.Enqueue([string]$EventArgs.Data) }
    }
    $null = Register-ObjectEvent -InputObject $script:proc -EventName ErrorDataReceived -MessageData $script:lines -Action {
        if ($EventArgs.Data) { $Event.MessageData.Enqueue([string]$EventArgs.Data) }
    }
    [void]$script:proc.Start()
    $script:proc.BeginOutputReadLine()
    $script:proc.BeginErrorReadLine() | Out-Null
}

function Finish-Auto {
    $r = $null
    if ($script:reportPath -and (Test-Path $script:reportPath)) {
        try { $r = Get-Content -Raw -Encoding UTF8 $script:reportPath | ConvertFrom-Json } catch {}
        Remove-Item $script:reportPath -Force -ErrorAction SilentlyContinue
    }
    if ($r -and $r.inventory) {
        Show-Report $r
        if ($r.ok) { Start-Measure } else { Set-Busy $false 'Нет активного туннеля' }
        Start-AppsRefresh
    } else {
        Start-Auto 'Обновляю сессии SoftEther…' @('-Inventory')
    }
}

function Quote-Arg([string]$a) {
    if ($a -match '[\s"]') { return '"' + ($a -replace '"', '\"') + '"' }
    return $a
}

function Set-AppBusy([bool]$on) {
    $script:appsBusy = $on
    foreach ($c in @($script:btnAppsRefresh, $script:btnAppsAdd, $script:btnAppsRemove, $script:btnAppsAdapter, $script:clbApps, $script:cbAdapter)) {
        if ($c) { $c.Enabled = -not $on }
    }
}

function Invoke-SplitAction([string[]]$ActionArgs) {
    if (-not $script:splitPath -or -not (Test-Path $script:splitPath)) {
        $script:lblAppsState.Text = 'split-tunnel.ps1 не найден'
        return 1
    }
    Set-AppBusy $true
    $script:lblAppsState.Text = 'Применяю правила…'
    try { $script:form.Refresh() } catch {}
    try {
        $q = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Quote-Arg $script:splitPath), '-NoElevate')
        foreach ($a in @($ActionArgs)) { $q += Quote-Arg ([string]$a) }
        $p = Start-Process -FilePath 'powershell.exe' -ArgumentList ($q -join ' ') -Wait -PassThru -WindowStyle Hidden
        return [int]$p.ExitCode
    } catch {
        $script:lblAppsState.Text = 'Ошибка: ' + $_.Exception.Message
        return 1
    } finally {
        Set-AppBusy $false
    }
}

function Show-Apps($st) {
    if (-not $script:clbApps) { return }
    $script:appsLoading = $true
    try {
        $script:clbApps.Items.Clear()
        $script:appRules = @($st.Rules)
        foreach ($r in $script:appRules) {
            $ad = if ($r.AdapterName) { [string]$r.AdapterName } else { 'адаптер не задан' }
            $mark = if ($r.Enabled -and $r.ProcessCount -gt 0) { ' · запущено' } else { '' }
            $idx = $script:clbApps.Items.Add(('{0}   →   {1}{2}' -f $r.Name, $ad, $mark))
            $script:clbApps.SetItemChecked($idx, [bool]$r.Enabled)
        }
    } finally {
        $script:appsLoading = $false
    }

    $tr = if (-not $st.Ruler.Running) { 'TrafikRuler не запущен' } elseif ($st.Ruler.Active) { 'перехват активен' } else { 'перехват остановлен' }
    $wifi = if ($st.Wifi.Name) {
        if ($st.Wifi.HasDefault) { 'Wi-Fi готов' } else { 'Wi-Fi без шлюза' }
    } else { 'Wi-Fi не найден' }
    $script:lblAppsState.Text = ('TrafikRuler: {0} · {1}' -f $tr, $wifi)

    $prev = $script:cbAdapter.Text
    $script:cbAdapter.Items.Clear()
    foreach ($a in @($st.Wifi, $st.Wire)) {
        if ($a -and $a.Name -and -not $script:cbAdapter.Items.Contains([string]$a.Name)) {
            [void]$script:cbAdapter.Items.Add([string]$a.Name)
        }
    }
    if ($prev -and $script:cbAdapter.Items.Contains($prev)) { $script:cbAdapter.Text = $prev }
    elseif ($st.Wifi.Name) { $script:cbAdapter.Text = [string]$st.Wifi.Name }
}

function Start-AppsRefresh {
    if ($script:appsRefresh -or $script:appsBusy) { return }
    if (-not $script:splitPath -or -not (Test-Path $script:splitPath)) {
        $script:lblAppsState.Text = 'split-tunnel.ps1 не найден'
        Set-AppBusy $true
        return
    }
    Set-AppBusy $true
    $script:lblAppsState.Text = 'TrafikRuler: читаю правила…'
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript(@'
param($Path)
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = 'powershell.exe'
$psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $Path + '" -Json -NoElevate'
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()
$out = $p.StandardOutput.ReadToEnd()
$null = $p.StandardError.ReadToEnd()
$p.WaitForExit()
$out
'@).AddArgument($script:splitPath)
    $script:appsRefresh = @{ Ps = $ps; Rs = $rs; Handle = $ps.BeginInvoke() }
}

function Finish-AppsRefresh {
    if (-not $script:appsRefresh) { return }
    $json = ''
    try {
        $parts = @($script:appsRefresh.Ps.EndInvoke($script:appsRefresh.Handle))
        $json = ($parts | Out-String).Trim()
    } catch {}
    try { $script:appsRefresh.Ps.Dispose(); $script:appsRefresh.Rs.Close() } catch {}
    $script:appsRefresh = $null
    if (-not $json) {
        $script:lblAppsState.Text = 'Не удалось прочитать правила'
        Set-AppBusy $false
        return
    }
    $st = $null
    try { $st = $json | ConvertFrom-Json } catch {}
    if (-not $st) {
        $script:lblAppsState.Text = 'Ответ split-tunnel не разобран'
        Set-AppBusy $false
        return
    }
    Show-Apps $st
    Set-AppBusy $false
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'VPN Gate'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.MinimizeBox = $true
$form.ClientSize = New-Object System.Drawing.Size(560, 860)
$form.BackColor = [System.Drawing.Color]::FromArgb(26, 27, 27)
$form.ForeColor = [System.Drawing.Color]::FromArgb(235, 236, 234)
$form.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$script:form = $form

$script:lblState = New-Object System.Windows.Forms.Label
$script:lblState.Left = 20; $script:lblState.Top = 16; $script:lblState.Width = 520; $script:lblState.Height = 24
$script:lblState.ForeColor = [System.Drawing.Color]::FromArgb(181, 206, 165)
$script:lblState.Text = 'Смотрю текущий шлюз…'
$form.Controls.Add($script:lblState)

$script:lblCountry = New-Object System.Windows.Forms.Label
$script:lblCountry.Left = 20; $script:lblCountry.Top = 48; $script:lblCountry.Width = 520; $script:lblCountry.Height = 36
$script:lblCountry.Font = New-Object System.Drawing.Font('Segoe UI', 18, [System.Drawing.FontStyle]::Bold)
$script:lblCountry.Text = '…'
$form.Controls.Add($script:lblCountry)

$script:lblServer = New-Object System.Windows.Forms.Label
$script:lblServer.Left = 20; $script:lblServer.Top = 92; $script:lblServer.Width = 520; $script:lblServer.Height = 22
$form.Controls.Add($script:lblServer)

$script:lblAddr = New-Object System.Windows.Forms.Label
$script:lblAddr.Left = 20; $script:lblAddr.Top = 116; $script:lblAddr.Width = 520; $script:lblAddr.Height = 22
$script:lblAddr.ForeColor = [System.Drawing.Color]::FromArgb(172, 175, 171)
$form.Controls.Add($script:lblAddr)

$script:lblExit = New-Object System.Windows.Forms.Label
$script:lblExit.Left = 20; $script:lblExit.Top = 146; $script:lblExit.Width = 520; $script:lblExit.Height = 22
$form.Controls.Add($script:lblExit)

$script:lblList = New-Object System.Windows.Forms.Label
$script:lblList.Left = 20; $script:lblList.Top = 170; $script:lblList.Width = 520; $script:lblList.Height = 20
$script:lblList.ForeColor = [System.Drawing.Color]::FromArgb(172, 175, 171)
$script:lblList.Text = 'Сессии SoftEther'
$form.Controls.Add($script:lblList)

$script:lst = New-Object System.Windows.Forms.ListBox
$script:lst.Left = 20; $script:lst.Top = 192; $script:lst.Width = 520; $script:lst.Height = 88
$script:lst.BackColor = [System.Drawing.Color]::FromArgb(19, 21, 20)
$script:lst.ForeColor = [System.Drawing.Color]::FromArgb(235, 236, 234)
$script:lst.BorderStyle = 'FixedSingle'
$script:lst.Font = New-Object System.Drawing.Font('Consolas', 9)
$form.Controls.Add($script:lst)

$script:lblPing = New-Object System.Windows.Forms.Label
$script:lblPing.Left = 20; $script:lblPing.Top = 290; $script:lblPing.Width = 250; $script:lblPing.Height = 28
$script:lblPing.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$script:lblPing.Text = 'Пинг  —'
$form.Controls.Add($script:lblPing)

$script:lblDown = New-Object System.Windows.Forms.Label
$script:lblDown.Left = 280; $script:lblDown.Top = 290; $script:lblDown.Width = 260; $script:lblDown.Height = 28
$script:lblDown.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
$script:lblDown.Text = 'Загрузка  —'
$form.Controls.Add($script:lblDown)

$script:btnConnect = New-Button 'Подключить' 20 328 165
$script:btnNext = New-Button 'Следующий шлюз' 197 328 170
$script:btnMeasure = New-Button 'Замерить' 379 328 160
$script:btnOff = New-Button 'Отключить' 20 370 165
$script:btnClose = New-Button 'Свернуть в трей' 197 370 170
$form.Controls.AddRange(@($script:btnConnect, $script:btnNext, $script:btnMeasure, $script:btnOff, $script:btnClose))

$hint = New-Object System.Windows.Forms.Label
$hint.Left = 20; $hint.Top = 412; $hint.Width = 520; $hint.Height = 46
$hint.ForeColor = [System.Drawing.Color]::FromArgb(172, 175, 171)
$hint.Text = 'Сворачивание и крестик прячут окно в трей, VPN остаётся. Выход — в меню иконки. «Следующий шлюз» идёт по кругу.'
$form.Controls.Add($hint)

$script:log = New-Object System.Windows.Forms.TextBox
$script:log.Left = 20; $script:log.Top = 462; $script:log.Width = 520; $script:log.Height = 118
$script:log.Multiline = $true
$script:log.ReadOnly = $true
$script:log.ScrollBars = 'Vertical'
$script:log.BackColor = [System.Drawing.Color]::FromArgb(19, 21, 20)
$script:log.ForeColor = [System.Drawing.Color]::FromArgb(200, 204, 198)
$script:log.Font = New-Object System.Drawing.Font('Consolas', 9)
$form.Controls.Add($script:log)

$script:lblAppsTitle = New-Object System.Windows.Forms.Label
$script:lblAppsTitle.Left = 20; $script:lblAppsTitle.Top = 592; $script:lblAppsTitle.Width = 180; $script:lblAppsTitle.Height = 20
$script:lblAppsTitle.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$script:lblAppsTitle.Text = 'Приложения без VPN'
$form.Controls.Add($script:lblAppsTitle)

$script:lblAppsState = New-Object System.Windows.Forms.Label
$script:lblAppsState.Left = 200; $script:lblAppsState.Top = 592; $script:lblAppsState.Width = 340; $script:lblAppsState.Height = 20
$script:lblAppsState.ForeColor = [System.Drawing.Color]::FromArgb(172, 175, 171)
$script:lblAppsState.Font = New-Object System.Drawing.Font('Segoe UI', 8.25)
$script:lblAppsState.TextAlign = 'MiddleRight'
$script:lblAppsState.Text = 'TrafikRuler: читаю правила…'
$form.Controls.Add($script:lblAppsState)

$script:clbApps = New-Object System.Windows.Forms.CheckedListBox
$script:clbApps.Left = 20; $script:clbApps.Top = 616; $script:clbApps.Width = 350; $script:clbApps.Height = 140
$script:clbApps.CheckOnClick = $true
$script:clbApps.IntegralHeight = $false
$script:clbApps.BackColor = [System.Drawing.Color]::FromArgb(19, 21, 20)
$script:clbApps.ForeColor = [System.Drawing.Color]::FromArgb(235, 236, 234)
$script:clbApps.BorderStyle = 'FixedSingle'
$script:clbApps.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Controls.Add($script:clbApps)

$script:btnAppsRefresh = New-Button 'Обновить' 382 616 158
$script:btnAppsAdd = New-Button 'Добавить .exe' 382 652 158
$script:btnAppsRemove = New-Button 'Удалить правило' 382 688 158
$form.Controls.AddRange(@($script:btnAppsRefresh, $script:btnAppsAdd, $script:btnAppsRemove))

$lblAdapter = New-Object System.Windows.Forms.Label
$lblAdapter.Left = 382; $lblAdapter.Top = 726; $lblAdapter.Width = 158; $lblAdapter.Height = 18
$lblAdapter.ForeColor = [System.Drawing.Color]::FromArgb(172, 175, 171)
$lblAdapter.Text = 'Адаптер без VPN:'
$form.Controls.Add($lblAdapter)

$script:cbAdapter = New-Object System.Windows.Forms.ComboBox
$script:cbAdapter.Left = 382; $script:cbAdapter.Top = 746; $script:cbAdapter.Width = 158
$script:cbAdapter.DropDownStyle = 'DropDownList'
$script:cbAdapter.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$form.Controls.Add($script:cbAdapter)

$script:btnAppsAdapter = New-Button 'Применить адаптер' 382 776 158
$form.Controls.Add($script:btnAppsAdapter)

$hintApps = New-Object System.Windows.Forms.Label
$hintApps.Left = 20; $hintApps.Top = 816; $hintApps.Width = 520; $hintApps.Height = 38
$hintApps.ForeColor = [System.Drawing.Color]::FromArgb(172, 175, 171)
$hintApps.Text = 'Галочка пускает программу через выбранный адаптер мимо VPN. Уже открытую программу перезапустите. Новые программы добавляются включёнными.'
$form.Controls.Add($hintApps)

$script:btnConnect.Add_Click({
    if ($script:busy) { return }
    $script:lblPing.Text = 'Пинг  —'
    $script:lblDown.Text = 'Загрузка  —'
    Start-Auto 'Подключаюсь…' @()
})
$script:btnNext.Add_Click({
    if ($script:busy) { return }
    $skip = ''
    if ($script:current -and $script:current.ip) { $skip = [string]$script:current.ip }
    $script:lblPing.Text = 'Пинг  —'
    $script:lblDown.Text = 'Загрузка  —'
    if ($skip) { Start-Auto 'Ищу следующий шлюз по кругу…' @('-SkipEndpoint', $skip, '-Rotate') } else { Start-Auto 'Ищу следующий шлюз по кругу…' @('-Rotate') }
})
$script:btnMeasure.Add_Click({
    if ($script:busy) { return }
    Start-Measure
})
$script:btnOff.Add_Click({
    if ($script:busy) { return }
    $script:current = $null
    $script:lblPing.Text = 'Пинг  —'
    $script:lblDown.Text = 'Загрузка  —'
    Start-Auto 'Отключаю…' @('-Disconnect')
})
$script:btnClose.Add_Click({ Hide-ToTray })

$script:clbApps.Add_ItemCheck({
    param($sender, $e)
    if ($script:appsLoading -or $script:appsBusy) { return }
    if ($e.Index -lt 0 -or $e.Index -ge $script:appRules.Count) { return }
    $r = $script:appRules[$e.Index]
    $enable = ($e.NewValue -eq [System.Windows.Forms.CheckState]::Checked)
    $arg = if ($enable) { '-EnableRule' } else { '-DisableRule' }
    $code = Invoke-SplitAction @($arg, [string]$r.Name)
    if ($code -ne 0) {
        $script:appsLoading = $true
        try { $script:clbApps.SetItemChecked($e.Index, -not $enable) } finally { $script:appsLoading = $false }
        $script:lblAppsState.Text = 'Не удалось изменить правило'
    } else {
        $script:lblAppsState.Text = if ($enable) { 'Правило включено' } else { 'Правило выключено' }
    }
    Start-AppsRefresh
})

$script:btnAppsRefresh.Add_Click({ Start-AppsRefresh })

$script:btnAppsAdd.Add_Click({
    if ($script:appsBusy) { return }
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title = 'Программа, которой нужен обычный интернет'
    $dlg.Filter = 'Программы (*.exe)|*.exe'
    if ($dlg.ShowDialog($script:form) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    $ad = $script:cbAdapter.Text
    if (-not $ad) {
        [void][System.Windows.Forms.MessageBox]::Show($script:form, 'Сначала выберите адаптер.')
        return
    }
    $code = Invoke-SplitAction @('-AddApp', $dlg.FileName, '-Adapter', $ad, '-EnableNew')
    if ($code -eq 0) { $script:lblAppsState.Text = 'Добавлено: ' + [System.IO.Path]::GetFileName($dlg.FileName) }
    Start-AppsRefresh
})

$script:btnAppsRemove.Add_Click({
    if ($script:appsBusy) { return }
    $i = $script:clbApps.SelectedIndex
    if ($i -lt 0 -or $i -ge $script:appRules.Count) {
        $script:lblAppsState.Text = 'Выберите правило в списке'
        return
    }
    $r = $script:appRules[$i]
    $ans = [System.Windows.Forms.MessageBox]::Show($script:form, ('Удалить правило «{0}»?' -f $r.Name), 'VPN Gate', 'YesNo', 'Question')
    if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    $code = Invoke-SplitAction @('-RemoveRule', [string]$r.Name)
    if ($code -eq 0) { $script:lblAppsState.Text = 'Удалено: ' + $r.Name }
    Start-AppsRefresh
})

$script:btnAppsAdapter.Add_Click({
    if ($script:appsBusy) { return }
    $i = $script:clbApps.SelectedIndex
    if ($i -lt 0 -or $i -ge $script:appRules.Count) {
        $script:lblAppsState.Text = 'Выберите правило в списке'
        return
    }
    $ad = $script:cbAdapter.Text
    if (-not $ad) {
        $script:lblAppsState.Text = 'Выберите адаптер'
        return
    }
    $r = $script:appRules[$i]
    $code = Invoke-SplitAction @('-SetAdapterFor', [string]$r.Name, '-Adapter', $ad)
    if ($code -eq 0) { $script:lblAppsState.Text = ('{0} → {1}' -f $r.Name, $ad) }
    Start-AppsRefresh
})

$iconStream = New-Object System.IO.MemoryStream
[System.Drawing.SystemIcons]::Shield.Save($iconStream)
$iconStream.Position = 0
$script:trayIcon = New-Object System.Drawing.Icon($iconStream)

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$miOpen = $menu.Items.Add('Открыть')
$miNext = $menu.Items.Add('Следующий шлюз')
$miReset = $menu.Items.Add('Начать круг заново')
$miOff = $menu.Items.Add('Отключить')
[void]$menu.Items.Add('-')
$miExit = $menu.Items.Add('Выход')
$miOpen.Add_Click({ Show-MainWindow })
$miNext.Add_Click({ $script:btnNext.PerformClick() })
$miReset.Add_Click({
    if ($script:busy) { return }
    # Пустой файл круга, но с round=1: следующий «Следующий шлюз» снова
    # возьмёт проверенные шлюзы сверху, а не будет считать их пройденными.
    try {
        $rotFile = Join-Path $env:LOCALAPPDATA 'VPNGateAuto\rotation.txt'
        $rotDir = Split-Path -Parent $rotFile
        if (-not (Test-Path $rotDir)) { New-Item -ItemType Directory -Path $rotDir -Force | Out-Null }
        [System.IO.File]::WriteAllText($rotFile, "round=1`r`n", (New-Object System.Text.UTF8Encoding($false)))
        $script:lblState.Text = 'Круг сброшен — следующий шлюз начнёт с проверенных'
        $script:lblList.Text = 'Сессии SoftEther   круг сброшен'
        Add-Log 'Круг сброшен вручную'
    } catch {
        $script:lblState.Text = 'Не удалось сбросить круг: ' + $_.Exception.Message
    }
})
$miOff.Add_Click({ $script:btnOff.PerformClick() })
$miExit.Add_Click({
    $script:reallyExit = $true
    $form.Close()
})

$script:notify = New-Object System.Windows.Forms.NotifyIcon
$script:notify.Icon = $script:trayIcon
$script:notify.Visible = $true
$script:notify.ContextMenuStrip = $menu
$script:notify.Text = 'VPN Gate'
$script:notify.Add_MouseClick({
    param($sender, $e)
    if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Show-MainWindow }
})
$script:notify.Add_DoubleClick({ Show-MainWindow })

$form.Add_Resize({
    if ($script:allowHide -and $form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) { Hide-ToTray }
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 300
$timer.Add_Tick({
    $line = $null
    while ($script:lines.TryDequeue([ref]$line)) { Add-Log $line }
    if ($script:proc -and $script:proc.HasExited) {
        $script:proc = $null
        Finish-Auto
    }
    if ($script:appsRefresh -and $script:appsRefresh.Handle.IsCompleted) {
        Finish-AppsRefresh
    }
    if ($script:measure -and $script:measure.Handle.IsCompleted) {
        $q = $null
        try { $q = $script:measure.Ps.EndInvoke($script:measure.Handle) } catch {}
        try { $script:measure.Ps.Dispose(); $script:measure.Rs.Close() } catch {}
        $script:measure = $null
        if ($q) {
            $script:lblPing.Text = 'Пинг  ' + $q.Ping
            $script:lblDown.Text = 'Загрузка  ' + $q.Down
            Add-Log ('Пинг ' + $q.Ping + ', загрузка ' + $q.Down)
        }
        Set-Busy $false $(if ($script:current -and $script:current.ok) { 'Подключено' } else { 'Готово' })
    }
})
$timer.Start()

$form.Add_Shown({ Start-Auto 'Смотрю сессии SoftEther…' @('-Inventory'); Start-AppsRefresh })
$form.Add_FormClosing({
    if (-not $script:reallyExit) {
        $_.Cancel = $true
        Hide-ToTray
        return
    }
    if ($script:appsRefresh) {
        try {
            $script:appsRefresh.Ps.Stop()
            $script:appsRefresh.Ps.Dispose()
            $script:appsRefresh.Rs.Close()
        } catch {}
        $script:appsRefresh = $null
    }
    $timer.Stop()
    if ($script:proc -and -not $script:proc.HasExited) {
        try { $script:proc.Kill() } catch {}
    }
    $script:notify.Visible = $false
    $script:notify.Dispose()
    $script:trayIcon.Dispose()
    $iconStream.Dispose()
})

[System.Windows.Forms.Application]::Run($form)
