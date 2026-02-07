@echo off
echo ========================================
echo WiFi Protection GUI - Administrator Mode
echo ========================================
echo.
echo This will launch the GUI with Administrator privileges
echo to enable device blocking features.
echo.
echo Press any key to continue...
pause >nul

:: Request admin rights and run the GUI
PowerShell -Command "Start-Process -FilePath '%~dp0wifi_gui_window.exe' -Verb RunAs"

echo.
echo GUI launched with Administrator rights!
echo.
pause
