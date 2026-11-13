# Установка SoftEther VPN Client (с плагином VPN Gate), ярлыков,
# TrafikRuler и службы, которая возвращает шлюзы физических адаптеров.
# VPN сам не подключается. Два профиля SoftEther одновременно не поднимать.
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"')
    )
    exit 0
}

$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Payload = Join-Path $Here 'payload'
$Dest = Join-Path $env:ProgramData 'VPNGateSetup'
$SoftEtherUrl = 'https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases/download/v4.44-9807-rtm/softether-vpnclient-v4.44-9807-rtm-2025.04.16-windows-x86_x64-intel.exe'
$SoftEtherMirror = 'http://www.softether-download.com/files/softether/v4.44-9807-rtm-2025.04.16-tree/Windows/SoftEther_VPN_Client/softether-vpnclient-v4.44-9807-rtm-2025.04.16-windows-x86_x64-intel.exe'
$DotNetUrl = 'https://aka.ms/dotnet/8.0/windowsdesktop-runtime-win-x64.exe'

function Say([string]$Text) { Write-Host $Text }

function Find-VpnCmd {
    $candidates = @(
        "$env:ProgramFiles\SoftEther VPN Client\vpncmd_x64.exe",
        "${env:ProgramFiles(x86)}\SoftEther VPN Client\vpncmd_x64.exe",
        'C:\Program Files\SoftEther VPN Client\vpncmd_x64.exe',
        'C:\Program Files (x86)\SoftEther VPN Client\vpncmd_x64.exe'
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    return $null
}

function Save-Url([string]$Url, [string]$OutFile) {
    Say "Скачиваю $Url"
    & curl.exe -fL --retry 3 --retry-delay 2 -o $OutFile $Url
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutFile) -or (Get-Item $OutFile).Length -lt 1MB) {
        throw "Не скачалось: $Url"
    }
}

Say 'Копирую скрипты и TrafikRuler...'
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item -Path (Join-Path $Payload '*') -Destination $Dest -Recurse -Force

$vpncmd = Find-VpnCmd
if (-not $vpncmd) {
    $setup = Join-Path $env:TEMP 'softether-vpnclient-4.44.exe'
    try { Save-Url $SoftEtherUrl $setup } catch {
        Say "GitHub недоступен, пробую зеркало."
        Save-Url $SoftEtherMirror $setup
    }
    Say 'Запускаю установщик SoftEther VPN Client. Если откроется окно — ставь VPN Client, не Server.'
    $p = Start-Process -FilePath $setup -ArgumentList '/SILENT' -Wait -PassThru
    $vpncmd = Find-VpnCmd
    if (-not $vpncmd) {
        Say "Тихая установка не положила клиент (код $($p.ExitCode)). Открываю установщик вручную."
        Start-Process -FilePath $setup -Wait
        $vpncmd = Find-VpnCmd
    }
}
if (-not $vpncmd) { throw 'SoftEther VPN Client не установлен: vpncmd_x64.exe не найден.' }
Say "vpncmd: $vpncmd"

$desktopFx = Get-ChildItem 'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -like '8.*' }
if (-not $desktopFx) {
    Say 'Ставлю .NET 8 Desktop Runtime для TrafikRuler...'
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & winget install --id Microsoft.DotNet.DesktopRuntime.8 -e --accept-package-agreements --accept-source-agreements
    }
    if (-not (Get-ChildItem 'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -like '8.*' })) {
        $net = Join-Path $env:TEMP 'windowsdesktop-runtime-8-x64.exe'
        Save-Url $DotNetUrl $net
        Start-Process -FilePath $net -ArgumentList '/install','/quiet','/norestart' -Wait
    }
}

$desktop = [Environment]::GetFolderPath('Desktop')
$shell = New-Object -ComObject WScript.Shell
function New-Link([string]$Name, [string]$Target, [string]$Args) {
    $lnk = $shell.CreateShortcut((Join-Path $desktop $Name))
    $lnk.TargetPath = $Target
    if ($Args) { $lnk.Arguments = $Args }
    $lnk.WorkingDirectory = $Dest
    $lnk.Save()
}
New-Link 'VPN Gate — Включить.lnk' (Join-Path $Dest 'VPNGateAuto.bat') $null
New-Link 'VPN Gate — Выключить.lnk' (Join-Path $Dest 'VPNGateOff.bat') $null
New-Link 'VPN Gate — Статус.lnk' (Join-Path $Dest 'VPNGateStatus.bat') $null
New-Link 'TrafikRuler.lnk' (Join-Path $Dest 'TrafikRuler\TrafikRuler.exe') $null

$task = 'VPNGateKeepGateways'
$tr = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Dest\keep-gateways.ps1`""
& schtasks.exe /Create /TN $task /SC ONLOGON /RL HIGHEST /F /TR $tr | Out-Null
$running = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like '*keep-gateways.ps1*' })
if (-not $running) {
    Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',"`"$Dest\keep-gateways.ps1`"")
}

Say ''
Say 'Готово. VPN сам не подключён.'
Say "Файлы: $Dest"
Say 'Дальше человек один раз открывает SoftEther VPN Client Manager и подключается через VPN Gate.'
Say 'Программы, которым нужен обычный интернет, добавляются правилом в TrafikRuler. Остальные идут в VPN.'
Say 'Два профиля SoftEther одновременно не включать.'
