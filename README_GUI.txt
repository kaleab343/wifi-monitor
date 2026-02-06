========================================
WiFi Protection GUI - Quick Start Guide
========================================

OVERVIEW:
---------
This is a sample console-based GUI application for testing WiFi protection features.
It provides an interactive interface to scan networks, test protection mechanisms,
and monitor WiFi security.

FEATURES:
---------
1. WiFi Network Scanner - Scans and displays available networks
2. Network Connection - Simulates connecting to WiFi networks
3. Protection Toggle - Enable/disable WiFi protection features
4. Log Viewer - View protection activity logs
5. Feature Testing - Run automated tests on protection features
6. Network Statistics - Display connection stats and metrics

BUILD INSTRUCTIONS:
-------------------

Option 1: Using CMake (Recommended)
------------------------------------
1. Open terminal in project directory
2. Create build directory:
   mkdir build
   cd build

3. Generate build files:
   cmake ..

4. Build the project:
   cmake --build .

5. Run the GUI application:
   ./wifi_gui_app (or wifi_gui_app.exe on Windows)

Option 2: Using CLion
---------------------
1. Open the project in CLion
2. CLion will automatically detect CMakeLists.txt
3. Select "wifi_gui_app" from the run configurations dropdown
4. Click the Run button or press Shift+F10

Option 3: Direct Compilation (Windows with MSVC)
-------------------------------------------------
cl /EHsc wifi_gui_app.cpp wlanapi.lib ole32.lib /Fe:wifi_gui_app.exe

Option 4: Direct Compilation (Windows with MinGW)
--------------------------------------------------
g++ -std=c++20 wifi_gui_app.cpp -o wifi_gui_app.exe -lwlanapi -lole32

USAGE:
------
1. Run the application
2. Use the numbered menu to navigate features:
   [1] Scan for networks
   [2] Connect to a network
   [3] Toggle protection on/off
   [4] View activity logs
   [5] Run protection tests
   [6] View network statistics
   [0] Exit

NOTES:
------
- On Windows, the app uses native WiFi API to scan real networks
- On other platforms, it uses mock data for demonstration
- Administrator/root privileges may be required for some features
- The protection features are simulated for testing purposes

INTEGRATION:
------------
To integrate with your existing procationApp.cpp:
1. Include the WiFiProtectionGUI class in your app
2. Call the run() method to start the GUI
3. Customize the menu and features as needed
4. Add your actual WiFi protection logic

TROUBLESHOOTING:
----------------
- If build fails, ensure CMake version 4.1 or higher is installed
- On Windows, ensure Windows SDK is installed for WiFi API support
- Check that C++20 standard is supported by your compiler
- Run as administrator if WiFi scanning doesn't work

========================================
Created: 2026-02-06
Version: 1.0
========================================
