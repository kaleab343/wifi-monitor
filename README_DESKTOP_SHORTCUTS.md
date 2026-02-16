# NetWatch Pro - WiFi Monitor Desktop Installation

## ✅ Installation Complete!

The WiFi monitoring application has been successfully installed and configured to run from your desktop.

## 🖥️ Desktop Shortcuts Created

Two shortcuts have been created on your desktop:

### 1. **NetWatch Pro - WiFi Monitor** (Standard Mode)
- **Icon:** Network icon
- **Features:** 
  - Quick Scan (ARP-based device discovery)
  - Complete Discovery (NetBIOS + mDNS + SSDP)
  - Device blocking/unblocking
  - Network visibility
- **Usage:** Double-click to launch
- **Privileges:** Standard user

### 2. **NetWatch Pro - Admin Mode** (Advanced Features)
- **Icon:** Shield icon (admin)
- **Features:**
  - All standard features PLUS
  - MITM Passive Scanner (deep traffic analysis)
  - Real-time traffic monitoring
  - Advanced network interception
- **Usage:** Double-click to launch (will request admin privileges)
- **Privileges:** Administrator required

## 🚀 How to Use

### Quick Start
1. Double-click **"NetWatch Pro - WiFi Monitor"** on your desktop
2. The application will launch automatically
3. Click **"🔄 Quick Scan"** to discover devices on your network

### Advanced Features (MITM)
1. Double-click **"NetWatch Pro - Admin Mode"** on your desktop
2. Accept the UAC prompt (Administrator access required)
3. Use **"🕵️ MITM Scan"** or **"🕵️ Traffic Monitor"** tab for deep analysis

## 📋 Application Features

### Device Management Tab
- **Quick Scan:** Fast ARP-based device discovery
- **Complete Discovery:** Multi-protocol device identification (NetBIOS, mDNS, SSDP)
- **MITM Scan:** Intercept network traffic to detect ALL devices (even silent ones)
- **Block/Unblock:** Control device access to your network
- **Manual MAC Control:** Block/unblock devices by MAC address

### Traffic Monitor Tab (Admin Mode Only)
- Real-time traffic monitoring between router and devices
- Upload/download statistics per device
- Active connection tracking
- Export traffic data to JSON

## ⚙️ Requirements

### Already Installed ✅
- Python 3.13.7
- tkinter (GUI framework)
- requests (HTTP library)
- scapy (Network packet manipulation)
- pillow (Image processing)
- **Pure Python ARP Scanner** (No C++ compiler needed!)

### Network Requirements
- Connected to WiFi network
- Router access for blocking features
- Administrator privileges for MITM features

### Important Notes
- ✅ **No C++ compiler required!** The app now uses a pure Python ARP scanner
- ✅ Works without MinGW/g++ or CLion
- ✅ All scanning features available out-of-the-box

## 📁 File Locations

- **Application:** `C:\Users\hp\Desktop\work\9-5\wifi_perotion\wifi analisis\wifi-monitor\`
- **Launcher Scripts:** 
  - `launch_wifi_monitor.bat` (Standard)
  - `launch_wifi_monitor_admin.bat` (Admin)
- **Main Application:** `hybrid_router_gui.py`
- **Desktop Shortcuts:** `C:\Users\hp\Desktop\`

## 🔧 Troubleshooting

### Application won't start
- Ensure Python is installed and in PATH
- Check that all dependencies are installed: `pip install requests scapy pillow`
- Run from command line to see error messages

### MITM features not working
- Must run in **Admin Mode** (use the admin shortcut)
- Administrator privileges are required for network interception
- Scapy requires elevated permissions

### No devices found
- Ensure you're connected to the WiFi network
- Try "Complete Discovery" for better results
- Some devices may be silent - use "MITM Scan" to detect them

## 🛡️ Security Notes

- MITM features require administrator privileges for legitimate network monitoring
- Only use on networks you own or have permission to monitor
- Traffic interception is powerful - use responsibly
- All data stays local on your machine

## 📞 Support

For issues or questions:
1. Check the Activity Log in the application
2. Review error messages in the log window
3. Ensure all requirements are met

---

**Installation Date:** February 16, 2026  
**Version:** NetWatch Pro v1.0  
**Python Version:** 3.13.7
