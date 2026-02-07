# 🚀 WiFi Router Manager - Deployment Guide

## ✅ Desktop Shortcut Created!

A desktop shortcut has been created on your Desktop:
**"WiFi Router Manager.bat"**

### 🎯 How to Use:

1. **Go to your Desktop**
2. **Double-click "WiFi Router Manager.bat"**
3. The app will:
   - Request Administrator privileges
   - Launch the WiFi Router Manager GUI
   - Enable all features including MITM scanning

---

## 📦 Deployment Options

### Option 1: Desktop Shortcut (Already Done!) ✅

**What you have:**
- Desktop shortcut: `WiFi Router Manager.bat`
- Application icon: `app_icon.ico` / `app_icon.png`
- Runs with admin privileges automatically

**How to use:**
- Double-click the desktop shortcut
- Click "Yes" when prompted for admin access
- GUI launches with full MITM capabilities

---

### Option 2: Create Standalone Executable

**To create a single .exe file:**

```bash
python deploy.py
```

**This will:**
- Install PyInstaller
- Create `dist/WiFiRouterManager.exe`
- Bundle all dependencies
- Create installer script

**Result:**
- Single executable file
- No Python installation required
- Can be distributed to other computers

---

### Option 3: Create Windows Installer

**Requirements:**
- NSIS (Nullsoft Scriptable Install System)
- Download from: https://nsis.sourceforge.io/

**Steps:**
1. Run `python deploy.py` to create executable
2. Install NSIS
3. Right-click `installer.nsi` → "Compile NSIS Script"
4. Get `WiFiRouterManager_Setup.exe`

**Result:**
- Professional installer
- Creates Start Menu shortcuts
- Creates Desktop shortcut
- Includes uninstaller

---

## 🎨 Application Icon

The WiFi Router Manager now has a custom icon!

**Files:**
- `app_icon.ico` - Windows icon file
- `app_icon.png` - PNG version

**Design:**
- Blue circular background
- White WiFi signal waves
- Red lock symbol (security)

---

## 📂 Files Structure

```
WiFi Router Manager/
├── 📱 Application Files
│   ├── hybrid_router_gui.py          - Main GUI
│   ├── mitm_passive_scanner.py       - MITM scanner
│   ├── complete_device_discovery.py  - Discovery engine
│   ├── router_manager.py             - Router API
│   └── device_manager_gui.py         - Device manager
│
├── 🎨 Icons & Resources
│   ├── app_icon.ico                  - Application icon
│   └── app_icon.png                  - Icon (PNG)
│
├── 🚀 Deployment Scripts
│   ├── deploy.py                     - Create executable
│   ├── create_app_icon.py            - Create icon
│   ├── create_desktop_shortcut.py    - Create shortcut
│   └── installer.nsi                 - NSIS installer
│
├── 📝 Launchers
│   ├── WiFi Router Manager.bat       - Desktop shortcut
│   ├── run_gui_as_admin_mitm.bat     - Admin launcher
│   └── run_gui.bat                   - Normal launcher
│
└── 📚 Documentation
    ├── MITM_SCANNER_README.md
    ├── QUICK_START_MITM.txt
    └── README_DEPLOYMENT.md           - This file
```

---

## 🖥️ Desktop Shortcut Details

**Location:** Your Desktop

**Shortcut Name:** WiFi Router Manager.bat

**What it does:**
1. Checks for Administrator privileges
2. Requests elevation if needed
3. Changes to application directory
4. Launches Python GUI with admin rights
5. Keeps console window open for logs

**Icon:** Uses `app_icon.ico` if available

---

## 🎯 Quick Start

### For Daily Use:

1. **Double-click desktop shortcut**
2. Click "Yes" for admin access
3. GUI opens with 3 scan buttons:
   - 🔄 Quick Scan (2 sec)
   - 🔍 Complete Discovery (7 sec)
   - 🕵️ MITM Scan (30 sec)

### For Distribution:

**Simple Way:**
- Share the entire folder
- Recipient runs desktop shortcut

**Professional Way:**
1. Run `python deploy.py`
2. Share `dist/WiFiRouterManager.exe`
3. Recipient double-clicks .exe

**Enterprise Way:**
1. Create installer with NSIS
2. Share `WiFiRouterManager_Setup.exe`
3. Recipient runs installer
4. App appears in Start Menu & Desktop

---

## ⚙️ System Requirements

**To Run:**
- Windows 7/8/10/11
- Python 3.7+ (if using .bat launcher)
- Administrator privileges

**To Deploy:**
- Python 3.7+
- PyInstaller (auto-installed by deploy.py)
- Pillow (for icon creation)
- NSIS (optional, for installer)

**Dependencies (bundled in .exe):**
- Scapy (packet capture)
- tkinter (GUI)
- requests (HTTP client)

---

## 🔧 Customization

### Change Icon:

Edit `create_app_icon.py` and run:
```bash
python create_app_icon.py
```

### Modify Launcher:

Edit desktop shortcut path in `create_desktop_shortcut.py`

### Change App Name:

In `deploy.py`, modify:
```python
'--name=WiFiRouterManager'  # Change this
```

---

## 📋 Deployment Checklist

- [x] Application icon created
- [x] Desktop shortcut created
- [ ] Standalone .exe created (optional)
- [ ] Windows installer created (optional)
- [x] Admin privileges configured
- [x] All dependencies included
- [x] Documentation written

---

## 🎉 You're Ready!

Your WiFi Router Manager is now deployed!

**Try it:**
1. Go to Desktop
2. Double-click "WiFi Router Manager.bat"
3. Enjoy your network management tool!

**Share it:**
- Copy entire folder to USB drive
- Send to friends/colleagues
- Or create .exe for easy distribution

---

## 🆘 Troubleshooting

### "Python not found"
**Solution:** Install Python 3.7+ from python.org

### "Not running as Administrator"
**Solution:** Right-click shortcut → "Run as administrator"

### "Scapy not installed"
**Solution:** Run `pip install scapy`

### Icon not showing
**Solution:** Ensure `app_icon.ico` is in the same folder

### Want single .exe file
**Solution:** Run `python deploy.py`

---

## 📞 Support

**Documentation:**
- MITM Scanner: MITM_SCANNER_README.md
- Quick Start: QUICK_START_MITM.txt
- Deployment: README_DEPLOYMENT.md (this file)

**GitHub:**
https://github.com/kaleab343/wifi-monitor

---

**Enjoy your WiFi Router Manager! 🎊**
