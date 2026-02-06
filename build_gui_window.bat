@echo off
echo ========================================
echo Building WiFi Protection GUI (Graphical)
echo ========================================
echo.

echo Compiling wifi_gui_window.cpp...
REM Use CLion's MinGW compiler if building from CLion
if exist "C:\Users\hp\downloads\CLion-2025.3.2.win\bin\mingw\bin\g++.exe" (
    C:\Users\hp\downloads\CLion-2025.3.2.win\bin\mingw\bin\g++.exe -std=c++20 wifi_gui_window.cpp -o cmake-build-debug\wifi_gui_window.exe -mwindows -municode -lwlanapi -lole32 -lgdi32 -lcomdlg32 -liphlpapi -lws2_32
) else (
    REM Fallback to system g++ with all required libraries
    g++ -std=c++20 wifi_gui_window.cpp -o wifi_gui_window.exe -mwindows -municode -lwlanapi -lole32 -lgdi32 -lcomdlg32 -liphlpapi -lws2_32
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Graphical GUI built successfully!
    echo Executable: wifi_gui_window.exe or cmake-build-debug\wifi_gui_window.exe
    echo.
    echo Double-click wifi_gui_window.exe or run_gui_window.bat to launch!
) else (
    echo.
    echo [ERROR] Build failed!
)

echo.
if not "%1"=="nopause" pause
