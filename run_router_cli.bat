@echo off
echo ========================================
echo  Router Management CLI
echo ========================================
echo.
echo Examples:
echo   python router_manager.py --action all
echo   python router_manager.py --action devices
echo   python router_manager.py --action block --mac AA:BB:CC:DD:EE:FF
echo   python router_manager.py --action wifi-info
echo.
echo Type your command:
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed
    pause
    exit /b 1
)

REM Run with command line arguments or interactive
if "%1"=="" (
    REM No arguments - show all info
    python router_manager.py --action all
) else (
    REM Forward all arguments
    python router_manager.py %*
)

pause
