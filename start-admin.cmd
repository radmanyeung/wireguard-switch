@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%scripts\start.ps1"
set "LOG_DIR=%SCRIPT_DIR%logs"
set "LOG_FILE=%LOG_DIR%\start-admin.cmd.log"
set "START_PS_LOG=%LOG_DIR%\start.ps1.log"
set "PS_EXE=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS_EXE%" set "PS_EXE=powershell"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
echo [%date% %time%] [START-ADMIN.CMD] requesting elevated start > "%LOG_FILE%"
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%PS_EXE%' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','\"%PS1%\"','-Elevated','-LauncherLogPath','\"%START_PS_LOG%\"')" >> "%LOG_FILE%" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
    echo [START-ADMIN.CMD] failed with exit code %EXIT_CODE%. >> "%LOG_FILE%"
    echo [START-ADMIN.CMD] failed with exit code %EXIT_CODE%.
    echo See log: "%LOG_FILE%"
)

endlocal
exit /b %EXIT_CODE%
