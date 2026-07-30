@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "LOG_DIR=%LOCALAPPDATA%\WireguardSplitTunnel\logs"
set "LOG_FILE=%LOG_DIR%\start-admin.cmd.log"
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%PS_EXE%" (
    echo [START-ADMIN.CMD] Windows PowerShell is unavailable.
    endlocal
    exit /b 1
)

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
echo [%date% %time%] [START-ADMIN.CMD] entering guarded start > "%LOG_FILE%"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\start.ps1" >> "%LOG_FILE%" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo [START-ADMIN.CMD] failed with exit code %EXIT_CODE%. >> "%LOG_FILE%"
    echo [START-ADMIN.CMD] failed with exit code %EXIT_CODE%.
    echo See log: "%LOG_FILE%"
)

endlocal
exit /b %EXIT_CODE%
