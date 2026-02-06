@echo off
echo Building WiFi GUI Window...
C:\Users\hp\downloads\CLion-2025.3.2.win\bin\mingw\bin\g++.exe -std=c++20 wifi_gui_window.cpp -o cmake-build-debug\wifi_gui_window.exe -mwindows -lwlanapi -lole32 -lgdi32 -lcomdlg32 -liphlpapi -lws2_32

if %ERRORLEVEL% EQU 0 (
    echo Build successful! Running GUI...
    start cmake-build-debug\wifi_gui_window.exe
) else (
    echo Build failed!
    pause
)
