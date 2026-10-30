@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "action=%~1"
if not defined action set "action=--start"
where python >nul 2>&1
if errorlevel 1 (
    py -3 -B "%~dp0login.py" %action%
) else (
    python -B "%~dp0login.py" %action%
)
if "%action%"=="--help" exit /b %errorlevel%
if errorlevel 1 (
    pause
) else (
    if "%action%"=="--status" (pause) else (timeout /t 3 >nul)
)
endlocal
