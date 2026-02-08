@echo off
echo ========================================
echo  NetWatch Pro
echo  Complete Network Visibility & Management
echo ========================================
echo.
echo Checking requirements...

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found!
    pause
    exit /b 1
)

REM Check g++ for C++ scanner
g++ --version >nul 2>&1
if errorlevel 1 (
    echo WARNING: g++ not found - C++ scanner will be disabled
    echo Install MinGW from: https://www.mingw-w64.org/
    echo.
    echo You can still use Python-only features
    pause
)

REM Check requests library
pip show requests >nul 2>&1
if errorlevel 1 (
    echo Installing requests...
    pip install requests
)

echo.
echo Starting Hybrid Router Manager...
echo.
python hybrid_router_gui.py

pause
