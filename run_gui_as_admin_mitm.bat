@echo off
REM Run Hybrid Router GUI with Administrator privileges for MITM scanning

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ================================================
echo   NetWatch Pro - MITM Mode
echo ================================================
echo.
echo Running with Administrator privileges
echo MITM Passive Scan is now available!
echo.

REM Install scapy if needed
pip install scapy >nul 2>&1

REM Run GUI
python hybrid_router_gui.py

pause
