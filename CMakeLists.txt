cmake_minimum_required(VERSION 3.20)
project(wifi_protion)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Original executable
add_executable(wifi_protion main.cpp)

# WiFi Console GUI Test Application
add_executable(wifi_gui_app wifi_gui_app.cpp)

# WiFi Graphical GUI Application (Windows)
# Use batch script for building (CMake MinGW has issues with this specific build)
add_custom_target(wifi_gui_window ALL
    COMMAND cmd /c ${CMAKE_SOURCE_DIR}/build_gui_window.bat
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Building WiFi GUI Window Application"
)

# Link Windows WiFi libraries on Windows
if(WIN32)
    target_link_libraries(wifi_gui_app wlanapi ole32)
    # wifi_gui_window is built using custom command, no need for target_link_libraries
endif()
