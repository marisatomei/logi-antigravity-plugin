@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Installation failed with error code %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)
endlocal
