@echo off
chcp 65001 >nul
title VPN Gate - OFF
setlocal
set "SCRIPT=%~dp0vpn-auto.ps1"

REM Self-elevation: NicDisable and route fixes need administrator rights.
fltmc >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Disconnect
echo.
echo === VPN disconnected ===
timeout /t 5 >nul
exit /b
