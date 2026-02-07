@echo off
echo ================================================
echo   MITM Scanner Setup
echo ================================================
echo.
echo Installing required packages...
echo.

pip install scapy

echo.
echo ================================================
echo Testing MITM scanner...
echo ================================================
echo.

python test_mitm_scanner.py

echo.
echo ================================================
echo Setup complete!
echo ================================================
echo.
echo Next steps:
echo   1. Run GUI with admin: run_gui_as_admin_mitm.bat
echo   2. Click "MITM Scan" button
echo   3. Wait 30 seconds for results
echo.
pause
