@echo off
echo ========================================
echo  Router Management GUI Launcher
echo ========================================
echo.
echo Starting Router Management Center...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.7 or higher from python.org
    pause
    exit /b 1
)

REM Install required packages if needed
echo Checking dependencies...
pip show requests >nul 2>&1
if errorlevel 1 (
    echo Installing required packages...
    pip install requests
)

REM Run the GUI
echo.
echo Launching GUI...
python router_gui.py

if errorlevel 1 (
    echo.
    echo ERROR: Failed to start GUI
    pause
)
