@echo off
echo ========================================
echo  MITM Browser Monitor GUI Launcher
echo ========================================
echo.
echo This will launch the Hybrid Router GUI with MITM browser monitoring.
echo.
echo IMPORTANT: For MITM features to work, you need to:
echo 1. Right-click this file and select "Run as Administrator"
echo 2. Install Scapy: pip install scapy
echo.
echo Features:
echo - Device scanning and management
echo - Block/unblock devices via router API
echo - MITM Browser Monitor - See what websites users are browsing
echo.

REM Check if scapy is installed
python -c "import scapy" 2>nul
if errorlevel 1 (
    echo [WARNING] Scapy not installed!
    echo.
    echo Installing Scapy for MITM monitoring...
    pip install scapy
    echo.
)

echo Starting Hybrid Router GUI...
echo.
python hybrid_router_gui.py

pause
