@echo off
setlocal

set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" (
    echo [DNSFIX] Windows PowerShell is unavailable. 1>&2
    endlocal
    exit /b 1
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fix-dns.ps1"
set "EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %EXIT_CODE%
