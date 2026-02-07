@echo off
echo ========================================
echo Building WiFi Protection GUI
echo ========================================
echo.

echo Compiling wifi_gui_app.cpp...
g++ -std=c++20 wifi_gui_app.cpp -o wifi_gui_app.exe -lwlanapi -lole32 -liphlpapi -lws2_32

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Build completed successfully!
    echo Executable: wifi_gui_app.exe
    echo.
    echo Run 'wifi_gui_app.exe' or 'run_gui.bat' to start the application.
) else (
    echo.
    echo [ERROR] Build failed!
)

echo.
pause
