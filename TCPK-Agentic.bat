@echo off
:: TCPK Agentic workbench launcher -- loopback-only (127.0.0.1), discovery-only.
::
:: A phased, AI-driven front-end: audit -> decompile -> AI line-by-line review,
:: every claim cross-checked by the IL prover. Same security model as the web panel
:: (loopback bind, per-session token header, Host-header lock, exploit bucket NEVER
:: reachable).
::
:: This console stays OPEN on purpose: it prints the URL + one-time session token
:: and is where you press Ctrl+C to stop the server. Your browser opens automatically.
:: Pass-through args work, e.g.:  TCPK-Agentic.bat -Port 51900 -NoBrowser
setlocal
set "PSD1=%~dp0TCPK\TCPK.psd1"
if not exist "%PSD1%" (
    echo TCPK module not found at: %PSD1%
    echo Run this .bat from the TCPK folder (it expects TCPK\TCPK.psd1 next to it^).
    pause
    exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Import-Module '%~dp0TCPK\TCPK.psd1' -Force; Start-TcpkAgentic %*"
