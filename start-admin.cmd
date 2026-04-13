@echo off
setlocal
set "PS1=%~dp0scripts\start.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath 'powershell' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','\"%PS1%\"','-Elevated')"
endlocal