#!/usr/bin/env python3
"""
NetWatch Pro - Installation Test
Tests if all dependencies are properly installed
"""

import sys
import platform

def test_python_version():
    """Test Python version"""
    version = sys.version_info
    print(f"🐍 Python Version: {version.major}.{version.minor}.{version.micro}")
    if version.major >= 3 and version.minor >= 7:
        print("   ✅ Python version OK (3.7+)")
        return True
    else:
        print("   ❌ Python version too old (requires 3.7+)")
        return False

def test_module(name, optional=False):
    """Test if a module can be imported"""
    try:
        __import__(name)
        print(f"   ✅ {name}")
        return True
    except ImportError:
        if optional:
            print(f"   ⚠️  {name} (optional - not installed)")
        else:
            print(f"   ❌ {name} (REQUIRED - not installed)")
        return not optional

def main():
    print("=" * 60)
    print("  NetWatch Pro - Installation Test")
    print("=" * 60)
    print()
    
    # System info
    print(f"💻 Operating System: {platform.system()} {platform.release()}")
    print(f"🏗️  Architecture: {platform.machine()}")
    print()
    
    # Python version
    all_ok = test_python_version()
    print()
    
    # Required modules
    print("📦 Required Dependencies:")
    all_ok &= test_module("tkinter")
    all_ok &= test_module("requests")
    print()
    
    # Optional modules
    print("📦 Optional Dependencies:")
    test_module("scapy", optional=True)
    test_module("PIL", optional=True)
    print()
    
    # Check privileges
    print("🔐 Privilege Status:")
    try:
        if platform.system() == 'Windows':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            import os
            is_admin = os.geteuid() == 0
        
        if is_admin:
            print("   ✅ Running with elevated privileges (MITM features available)")
        else:
            print("   ℹ️  Running without elevated privileges (basic features only)")
            print("      For MITM features:")
            if platform.system() == 'Windows':
                print("      - Run as Administrator")
            else:
                print("      - Run with: sudo python3 test_install.py")
    except Exception as e:
        print(f"   ⚠️  Could not check privileges: {e}")
    print()
    
    # Platform-specific notes
    print("📋 Platform Notes:")
    if platform.system() == 'Linux':
        print("   ℹ️  Linux detected")
        print("   💡 If tkinter is missing, install:")
        print("      - Debian/Ubuntu: sudo apt-get install python3-tk")
        print("      - Fedora: sudo dnf install python3-tkinter")
        print("      - Arch: sudo pacman -S tk")
        print()
        print("   💡 For MITM features, install:")
        print("      - pip3 install scapy")
        print("      - sudo apt-get install libpcap-dev (Debian/Ubuntu)")
        print("      - sudo dnf install libpcap-devel (Fedora)")
    elif platform.system() == 'Windows':
        print("   ℹ️  Windows detected")
        print("   💡 tkinter should be included with Python")
        print("   💡 For MITM features: pip install scapy")
    elif platform.system() == 'Darwin':
        print("   ℹ️  macOS detected")
        print("   💡 tkinter should be included with Python")
        print("   💡 For MITM features: pip3 install scapy")
    print()
    
    # Final result
    print("=" * 60)
    if all_ok:
        print("✅ Installation is READY!")
        print("🚀 Run: python3 launch.py")
    else:
        print("❌ Installation has missing dependencies")
        print("📖 See docs/LINUX_SETUP.md for installation instructions")
        print("📖 Or run: pip3 install -r requirements.txt")
    print("=" * 60)
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
