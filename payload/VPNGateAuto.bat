@echo off
chcp 65001 >nul
title VPN Gate - ON
setlocal
set "SCRIPT=%~dp0vpn-auto.ps1"

REM Self-elevation: route changes need administrator rights.
REM fltmc is a reliable admin check (net session depends on the Server service).
fltmc >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
echo.
echo === Done. Closing in 5 sec ===
timeout /t 5 >nul
exit /b
