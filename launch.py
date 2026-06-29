#!/usr/bin/env python3
"""
NetWatch Pro - Cross-Platform Launcher
Automatically detects OS and runs with appropriate settings
"""

import sys
import os
import platform
import subprocess

def main():
    system = platform.system()
    
    print("=" * 50)
    print("  NetWatch Pro - WiFi Network Monitor")
    print("=" * 50)
    print(f"\n📍 Detected OS: {system}")
    print(f"📍 Python: {sys.version.split()[0]}")
    print()
    
    # Check if running with admin/root privileges
    is_admin = False
    try:
        if system == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = os.geteuid() == 0
    except:
        pass
    
    if is_admin:
        print("🔐 Running with elevated privileges (MITM features available)")
    else:
        print("ℹ️  Running in normal mode")
        print("💡 For MITM features:")
        if system == 'Windows':
            print("   - Right-click and 'Run as Administrator'")
        else:
            print("   - Run with: sudo python3 launch.py")
    
    print("\n🚀 Starting NetWatch Pro...\n")
    
    # Add src to path and launch
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    
    try:
        from gui.hybrid_router_gui import main as gui_main
        gui_main()
    except KeyboardInterrupt:
        print("\n\n👋 NetWatch Pro stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\n📋 Troubleshooting:")
        print("   1. Install dependencies: pip3 install -r requirements.txt")
        if system == 'Linux':
            print("   2. Install tkinter: sudo apt-get install python3-tk")
        print("   3. Check Python version (requires 3.7+)")
        sys.exit(1)

if __name__ == "__main__":
    main()
