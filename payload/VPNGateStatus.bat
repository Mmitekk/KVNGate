@echo off
chcp 65001 >nul
title VPN Gate - Status
setlocal
set "SCRIPT=%~dp0vpn-auto.ps1"

REM Administrator rights are needed to see all adapters and routes.
fltmc >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -Status
echo.
timeout /t 8 >nul
exit /b
