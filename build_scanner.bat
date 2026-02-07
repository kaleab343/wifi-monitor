@echo off
echo Building Device Scanner CLI...
g++ device_scanner_cli.cpp -o device_scanner.exe -liphlpapi -lws2_32 -static
if %errorlevel% == 0 (
    echo Build successful!
    echo Testing...
    device_scanner.exe > devices.json
    type devices.json
) else (
    echo Build failed!
)
pause
