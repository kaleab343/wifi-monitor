@echo off
echo ================================================
echo      MITM Passive Network Scanner
echo ================================================
echo.
echo WARNING: This requires Administrator privileges!
echo.
echo This scanner will:
echo   - Intercept ALL network traffic (ARP spoofing)
echo   - Detect EVERY device on the network
echo   - Even find silent/sleeping devices
echo   - Run for 30 seconds
echo.
pause

REM Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Not running as Administrator!
    echo.
    echo Please right-click this file and select "Run as Administrator"
    pause
    exit /b 1
)

echo Installing required packages...
pip install scapy >nul 2>&1

echo.
echo Starting MITM scan...
echo.

python mitm_passive_scanner.py 192.168.1.1

echo.
echo ================================================
echo Scan complete! Check mitm_devices.json
echo ================================================
pause
