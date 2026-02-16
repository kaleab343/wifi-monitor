@echo off
REM WiFi Monitor - Network Visibility & Management Tool
REM Launch script for NetWatch Pro GUI

title NetWatch Pro - WiFi Monitor
color 0A

echo ========================================
echo   NetWatch Pro - WiFi Monitor
echo   Starting GUI Application...
echo ========================================
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
