@echo off
:: TCPK GUI launcher -- STA mode required for WinForms dropdowns.
setlocal
set "SCRIPT=%~dp0Start-TCPKGui.ps1"
if not exist "%SCRIPT%" (
    echo TCPK GUI script not found at: %SCRIPT%
    pause
    exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%SCRIPT%"
