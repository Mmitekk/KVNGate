#Requires -Version 5.1
<#
    Починка WMI на машине, где он заклинил.

    СИМПТОМЫ (проверено 18.11.2026 на этой машине):
      • Get-NetAdapter / Get-NetRoute / Get-ScheduledTask падают с
        «Вызов был отклонен фильтром сообщений (0x80010002 RPC_E_CALL_CANCELED)»;
      • или висят намертво;
      • из-за этого демон шлюзов (keep-gateways.ps1) умирает, туннель
        «подключён», но трафик идёт мимо него;
      • автоподключение VPN Gate считает живые шлюзы мёртвыми
        («Не удалось подключиться. Проверено: N шлюзов»);
      • панель «Приложения без VPN» не отвечает.

    ЧТО ДЕЛАЕТ:
      1. Убивает зависшие провайдеры WMI (WmiPrvSE.exe).
      2. Останавливает службу Winmgmt — с таймаутом и принудительным
         снятием процесса, если она не останавливается сама.
      3. Если WMI после этого не отвечает — пересобирает репозиторий
         WMI (штатная процедура восстановления).
      4. Поднимает задачи VPNGateKeepGateways и TrafikRuler заново.
      5. Пишет отчёт в C:\ProgramData\VPNGateSetup\repair-wmi.log

    ЗАПУСК (от администратора):
      powershell -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\VPNGateSetup\repair-wmi.ps1"

    ВАЖНО: если WMI заклинило, служба Winmgmt может зависнуть в
    STOP_PENDING внутри защищённого процесса svchost. Тогда снять её
    без перезагрузки Windows нельзя — скрипт честно напишет об этом.
#>
[CmdletBinding()]
param(
    [switch]$RebuildRepository   # сразу пересобрать репозиторий WMI
)

$ErrorActionPreference = 'Continue'
$LogPath = 'C:\ProgramData\VPNGateSetup\repair-wmi.log'
$Utf8 = New-Object System.Text.UTF8Encoding($false)

function Say([string]$Text) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $Text
    Write-Host $line
    try { [System.IO.File]::AppendAllText($LogPath, $line + "`r`n", $Utf8) } catch {}
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Проверка WMI с таймаутом: если провайдер завис — ждать бессмысленно.
function Test-Wmi([int]$TimeoutSec = 30) {
    $job = Start-Job -ScriptBlock {
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            $ad = @(Get-NetAdapter -ErrorAction Stop)
            [pscustomobject]@{ Ok = $true; Caption = $os.Caption; Adapters = $ad.Count }
        } catch {
            [pscustomobject]@{ Ok = $false; Error = $_.Exception.Message }
        }
    }
    if (Wait-Job $job -Timeout $TimeoutSec) {
        $r = Receive-Job $job
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $r
    }
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Ok = $false; Error = "WMI did not answer in $TimeoutSec s" }
}

function Get-WinmgmtPid {
    $t = & tasklist.exe /svc /fi "SERVICE eq Winmgmt" 2>$null | Out-String
    $m = [regex]::Match($t, '(\d{2,6})\s+Winmgmt')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return 0
}

# TerminateProcess с таймаутом: обычный taskkill на зависшем процессе
# тоже зависает (он ждёт, пока процесс «успокоится»).
function Stop-ProcessSafe([int]$TargetPid, [int]$TimeoutSec = 15) {
    $job = Start-Job -ScriptBlock {
        param($pid2)
        try {
            $p = [Diagnostics.Process]::GetProcessById($pid2)
            $p.Kill()
            $p.WaitForExit(10000)
            "killed"
        } catch { "error: $($_.Exception.Message)" }
    } -ArgumentList $TargetPid
    if (Wait-Job $job -Timeout $TimeoutSec) {
        $r = Receive-Job $job
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $r
    }
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    return 'hung'
}

function Stop-Winmgmt([int]$WaitSec = 15) {
    & sc.exe stop winmgmt 2>&1 | ForEach-Object { Say "  sc stop: $_" }
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
        $q = & sc.exe query winmgmt 2>&1 | Out-String
        if ($q -match 'STOPPED') { Say '  Winmgmt stopped.'; return $true }
        Start-Sleep -Seconds 2
    }
    Say '  Winmgmt does not stop - killing the provider host.'
    $prov = @(Get-Process wmiprvse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
    foreach ($p in $prov) { Say ('  WmiPrvSE ' + (Stop-ProcessSafe $p)) }
    Start-Sleep -Seconds 2
    $svcPid = Get-WinmgmtPid
    if ($svcPid -gt 0) {
        Say ('  svchost ' + $svcPid + ': ' + (Stop-ProcessSafe $svcPid))
        Start-Sleep -Seconds 3
    }
    $q = & sc.exe query winmgmt 2>&1 | Out-String
    if ($q -match 'STOPPED') { Say '  Winmgmt stopped after kill.'; return $true }
    Say '  Winmgmt is stuck in STOP_PENDING. Only a Windows restart can clear it.'
    return $false
}

function Start-Winmgmt {
    & sc.exe start winmgmt 2>&1 | ForEach-Object { Say "  sc start: $_" }
    Start-Sleep -Seconds 8
    $q = & sc.exe query winmgmt 2>&1 | Out-String
    if ($q -match 'RUNNING') { Say '  Winmgmt is running.'; return $true }
    Say '  Winmgmt is NOT running.'
    return $false
}

function Rebuild-Repository {
    Say 'Rebuilding the WMI repository.'
    Stop-Winmgmt 15 | Out-Null
    $repo = Join-Path $env:windir 'System32\wbem\Repository'
    $bak = Join-Path $env:windir 'System32\wbem\Repository.bak'
    try {
        if (Test-Path $bak) { Remove-Item $bak -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path $repo) {
            Rename-Item -LiteralPath $repo -NewName 'Repository.bak' -ErrorAction Stop
            Say '  Repository -> Repository.bak'
        }
    } catch {
        Say "  rename failed: $($_.Exception.Message)"
    }
    Start-Winmgmt | Out-Null
    Start-Sleep -Seconds 10
}

if (-not (Test-Admin)) {
    Write-Host 'Administrator rights required.'
    exit 1
}

try { [System.IO.File]::WriteAllText($LogPath, '', $Utf8) } catch {}
Say '=== WMI repair ==='

Say 'Checking WMI.'
$r = Test-Wmi 30
if ($r.Ok) {
    Say "WMI is alive: $($r.Caption); adapters: $($r.Adapters) - nothing to repair."
} else {
    Say "WMI is broken: $($r.Error)"
    Say 'Killing hung provider hosts.'
    foreach ($p in @(Get-Process wmiprvse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)) {
        Say ('  WmiPrvSE ' + (Stop-ProcessSafe $p))
    }
    Stop-Winmgmt 15 | Out-Null
    Start-Winmgmt | Out-Null
    $r = Test-Wmi 30
    if ($r.Ok) {
        Say "WMI is alive again: $($r.Caption); adapters: $($r.Adapters)"
    } else {
        Say "WMI is still broken: $($r.Error)"
        Rebuild-Repository
        $r = Test-Wmi 45
        if ($r.Ok) {
            Say "WMI recovered after the repository rebuild: $($r.Caption)"
        } else {
            Say "WMI is still dead: $($r.Error)"
            Say 'Restart Windows. After the restart the VPN Gate stack works even with broken WMI.'
            exit 2
        }
    }
}

Say 'Restarting the scheduled tasks.'
& schtasks.exe /Run /TN 'VPNGateKeepGateways' 2>&1 | Out-Null
Say "  VPNGateKeepGateways exit=$LASTEXITCODE"
Start-Sleep -Seconds 3
& schtasks.exe /Run /TN 'TrafikRuler' 2>&1 | Out-Null
Say "  TrafikRuler exit=$LASTEXITCODE"
Start-Sleep -Seconds 3

Say '--- default routes ---'
foreach ($d in ((& route.exe print -4 2>$null) | Select-String -Pattern '^\s+0\.0\.0\.0\s+0\.0\.0\.0')) {
    Say ('  ' + $d.ToString().Trim())
}

Say '=== Done ==='
