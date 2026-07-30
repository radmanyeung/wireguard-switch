@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "LOG_DIR=%LOCALAPPDATA%\WireguardSplitTunnel\logs"
set "LOG_FILE=%LOG_DIR%\install.cmd.log"
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
if not exist "%PS_EXE%" (
    echo [INSTALL] Trusted Windows PowerShell is missing.
    echo [INSTALL] Trusted Windows PowerShell is missing. > "%LOG_FILE%"
    exit /b 9009
)
echo [%date% %time%] [INSTALL.CMD] launching install.ps1 > "%LOG_FILE%"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%scripts\install.ps1" -LauncherLogPath "%LOG_DIR%\install.ps1.log" %* >> "%LOG_FILE%" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo [INSTALL] install.cmd failed with exit code %EXIT_CODE%.
    echo [INSTALL] install.cmd failed with exit code %EXIT_CODE%. >> "%LOG_FILE%"
    echo See log: "%LOG_FILE%"
)

exit /b %EXIT_CODE%
