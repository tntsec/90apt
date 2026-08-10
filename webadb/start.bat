@echo off
setlocal
cd /d "%~dp0"
echo.
echo ============================================
echo   Web ADB Wireless Debug Tool - Local Server
echo ============================================
echo.
where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js not found. Please install Node.js first.
    echo.
    pause
    exit /b 1
)
node serve.js
if errorlevel 1 (
    echo.
    echo [ERROR] Server exited. Port 8000 may already be in use.
    echo.
    pause
)
endlocal
