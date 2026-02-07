#!/usr/bin/env python3
"""
Create a desktop shortcut for WiFi Router Manager
"""

import os
import sys
from pathlib import Path

def create_windows_shortcut():
    """Create Windows desktop shortcut"""
    try:
        import winshell
        from win32com.client import Dispatch
    except ImportError:
        print("Installing required packages...")
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "install", "pywin32", "winshell"])
        import winshell
        from win32com.client import Dispatch
    
    # Get paths
    desktop = winshell.desktop()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Path to shortcut
    shortcut_path = os.path.join(desktop, "WiFi Router Manager.lnk")
    
    # Target: PowerShell script to run as admin
    target = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    # Arguments: Run the GUI as admin
    arguments = f'-ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList \'-NoExit\', \'-Command\', \'cd \\\"{current_dir}\\\"; python hybrid_router_gui.py\'\'"'
    
    # Create shortcut
    shell = Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(shortcut_path)
    shortcut.Targetpath = target
    shortcut.Arguments = arguments
    shortcut.WorkingDirectory = current_dir
    shortcut.IconLocation = os.path.join(current_dir, "app_icon.ico")
    shortcut.Description = "WiFi Router Manager - MITM Scanner & Device Blocker"
    shortcut.save()
    
    print(f"✅ Desktop shortcut created: {shortcut_path}")
    print(f"📂 Working directory: {current_dir}")
    print(f"🚀 Double-click the shortcut to launch WiFi Router Manager!")
    
    return shortcut_path

def create_simple_shortcut():
    """Create simple .bat launcher on desktop"""
    desktop = Path.home() / "Desktop"
    current_dir = Path(__file__).parent.absolute()
    
    # Create batch file
    bat_content = f'''@echo off
cd /d "{current_dir}"
echo ================================================
echo    WiFi Router Manager - Starting...
echo ================================================
echo.

REM Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo Running with Administrator privileges
echo.

python hybrid_router_gui.py

pause
'''
    
    bat_path = desktop / "WiFi Router Manager.bat"
    
    with open(bat_path, 'w') as f:
        f.write(bat_content)
    
    print(f"✅ Desktop launcher created: {bat_path}")
    print(f"📂 Working directory: {current_dir}")
    print(f"🚀 Double-click to launch WiFi Router Manager!")
    
    return bat_path

if __name__ == "__main__":
    print("Creating desktop shortcut for WiFi Router Manager...")
    print()
    
    try:
        # Try to create proper Windows shortcut
        create_windows_shortcut()
    except Exception as e:
        print(f"Could not create .lnk shortcut: {e}")
        print("Creating .bat launcher instead...")
        create_simple_shortcut()
