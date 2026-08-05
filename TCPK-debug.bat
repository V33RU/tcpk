@echo off
:: TCPK debug launcher -- shows errors in a visible console and logs to %TEMP%\tcpk-error.log
setlocal
set "SCRIPT=%~dp0Start-TCPKGui.ps1"
set "LOG=%TEMP%\tcpk-error.log"
if not exist "%SCRIPT%" (
    echo TCPK GUI script not found at: %SCRIPT%
    pause
    exit /b 1
)
echo Launching TCPK (debug mode -- errors logged to %LOG%) ...
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "%SCRIPT%" 2>"%LOG%"
if %errorlevel% neq 0 (
    echo.
    echo PowerShell exited with error %errorlevel%. Log:
    echo.
    type "%LOG%"
    echo.
    pause
)
