@echo off
REM WiFi Monitor - Network Visibility & Management Tool (Admin Mode)
REM Launch script with Administrator privileges for MITM features

title NetWatch Pro - WiFi Monitor (Admin Mode)
color 0C

echo ========================================
echo   NetWatch Pro - WiFi Monitor
echo   ADMIN MODE - MITM Features Enabled
echo ========================================
echo.

REM Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with Administrator privileges...
    echo.
    
    REM Change to the wifi-monitor root directory
    cd /d "%~dp0.."
    
    REM Launch the Python GUI using the new launcher
    python run.py
    
    REM Keep window open if there's an error
    if errorlevel 1 (
        echo.
        echo ========================================
        echo   Error: Application failed to start
        echo ========================================
        echo.
        pause
    )
) else (
    echo ERROR: This script requires Administrator privileges!
    echo Please right-click and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)
