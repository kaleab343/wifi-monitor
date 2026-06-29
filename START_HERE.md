# 🚀 START HERE - NetWatch Pro Cross-Platform Edition

## Welcome to NetWatch Pro v2.0!

Your WiFi network monitoring tool now works on **Windows, Linux, and macOS**!

---

## ⚡ Quick Start (Choose Your OS)

### 🪟 Windows Users

```batch
python launch.py
```
Done! The app will launch.

For MITM features: Right-click `launch.py` → "Run as Administrator"

---

### 🐧 Linux Users

```bash
# 1. Install dependencies (one time)
sudo apt-get install python3 python3-pip python3-tk  # Debian/Ubuntu
# or use: ./scripts/setup_mitm_scanner.sh

pip3 install -r requirements.txt

# 2. Make executable (one time)
chmod +x scripts/*.sh launch.py

# 3. Run
python3 launch.py

# For MITM features:
sudo python3 launch.py
```

**📖 Need help?** See: `docs/LINUX_SETUP.md`

---

### 🍎 macOS Users

```bash
pip3 install -r requirements.txt
python3 launch.py

# For MITM features:
sudo python3 launch.py
```

---

## 🧪 Test Your Installation First

Before starting, run:
```bash
python3 test_install.py
```

This checks:
- ✅ Python version
- ✅ Required modules
- ✅ Optional modules
- 🔐 Privilege status

---

## 📚 Documentation Roadmap

### New User? Read in This Order:

1. **This File** (`START_HERE.md`) - You are here! ✓
2. **Quick Reference** (`QUICK_REFERENCE.md`) - Common commands
3. **Main README** (`README.md`) - Full feature list
4. **Platform Guide** (`docs/PLATFORM_SUPPORT.md`) - OS-specific info

### Linux User?

👉 **Go straight to**: `docs/LINUX_SETUP.md`
- Complete installation guide
- Troubleshooting
- Desktop integration
- Tips & tricks

### Want to Know What Changed?

👉 **See**: `LINUX_READY.md` or `CROSS_PLATFORM_UPDATE.md`

---

## 🎯 What Can NetWatch Pro Do?

### Without Admin/Root Privileges ✅
- 🔍 **Quick Scan** - Find devices on your network (ARP)
- 🔎 **Complete Discovery** - Multi-protocol device detection
- 📋 **Device Management** - Rename, categorize, manage devices
- 🚫 **Device Blocking** - Block/unblock via router API
- 📱 **Device Info** - MAC, IP, manufacturer, OS detection

### With Admin/Root Privileges 🔒
- 🕵️ **MITM Passive Scan** - Detect hidden/silent devices
- 📊 **Traffic Monitor** - Real-time traffic analysis
- 🌐 **Deep Inspection** - HTTP/HTTPS traffic visibility
- 📡 **Packet Capture** - Raw network packet analysis

---

## 🗂️ Project Structure

```
wifi-monitor/
│
├── 🚀 LAUNCH FILES
│   ├── launch.py              ⭐ USE THIS - Universal launcher
│   ├── run.py                    Legacy launcher
│   └── test_install.py           Test your setup
│
├── 📖 DOCUMENTATION
│   ├── START_HERE.md          ⭐ This file!
│   ├── README.md                 Main documentation
│   ├── QUICK_REFERENCE.md        Command cheat sheet
│   ├── LINUX_READY.md            What's new for Linux
│   ├── CHANGELOG.md              Version history
│   └── docs/
│       ├── LINUX_SETUP.md     ⭐ Complete Linux guide
│       ├── PLATFORM_SUPPORT.md   Cross-platform details
│       └── ...                   More guides
│
├── 🔧 SCRIPTS (in scripts/)
│   ├── *.sh                   ⭐ Linux shell scripts
│   ├── *.bat                     Windows batch files
│   └── README.md                 Script documentation
│
├── 💾 SOURCE CODE (in src/)
│   ├── gui/                      GUI components
│   ├── scanners/                 Network scanners
│   └── utils/                    Helper utilities
│
└── 🎨 ASSETS (in assets/)
    ├── NetWatchPro.desktop    ⭐ Linux desktop entry
    └── app_icon.*                Application icons
```

---

## 🎓 Your Learning Path

### Beginner (First 5 Minutes)
```bash
1. python3 test_install.py    # Test setup
2. python3 launch.py          # Launch app
3. Click "🔄 Quick Scan"      # Scan network
4. Right-click a device       # Try actions
```

### Intermediate (Next 15 Minutes)
```bash
1. Read QUICK_REFERENCE.md    # Learn commands
2. Try "🔍 Complete Discovery" # Better scanning
3. Explore device management   # Rename, categorize
4. Read README.md             # Full features
```

### Advanced (Next Hour)
```bash
1. Read docs/LINUX_SETUP.md   # Deep dive (Linux)
2. Try MITM features          # sudo python3 launch.py
3. Set up desktop integration # .desktop file
4. Configure for your router  # Edit router_manager.py
```

---

## 🔥 Most Common Commands

### Launch Application
```bash
python3 launch.py              # All platforms
./scripts/launch_wifi_monitor.sh   # Linux (basic)
./scripts/launch_wifi_monitor_admin.sh  # Linux (root)
```

### Test Installation
```bash
python3 test_install.py
```

### Install Dependencies
```bash
# Windows
pip install -r requirements.txt

# Linux (Debian/Ubuntu)
sudo apt-get install python3 python3-pip python3-tk
pip3 install -r requirements.txt

# Linux (Quick)
./scripts/setup_mitm_scanner.sh
```

---

## 🐛 Quick Troubleshooting

### Problem: "No module named 'tkinter'"

**Linux:**
```bash
sudo apt-get install python3-tk  # Debian/Ubuntu
sudo dnf install python3-tkinter # Fedora
sudo pacman -S tk                # Arch
```

**Windows:** Reinstall Python with tcl/tk checked

---

### Problem: "Permission denied"

**Linux:**
```bash
chmod +x scripts/*.sh launch.py
```

---

### Problem: MITM features don't work

**Solution:** Run with admin/root privileges:
```bash
# Windows: Right-click → Run as Administrator
# Linux:
sudo python3 launch.py
```

---

### Problem: Can't see any devices

**Check:**
1. Are you connected to WiFi?
2. Try "Complete Discovery" instead
3. Try MITM scan (requires admin/root)
4. Check router is accessible

---

## 💡 Pro Tips

### 🐧 Linux Tips

**Create alias:**
```bash
echo 'alias nwp="python3 ~/wifi-monitor/launch.py"' >> ~/.bashrc
source ~/.bashrc
nwp  # Quick launch!
```

**Desktop integration:**
```bash
cp assets/NetWatchPro.desktop ~/.local/share/applications/
# Edit paths in the file
```

**Run at startup:**
See `docs/LINUX_SETUP.md` for systemd instructions

---

### 🪟 Windows Tips

**Create desktop shortcut:**
Right-click `launch.py` → Create Shortcut → Drag to desktop

**Add to startup:**
Press `Win+R` → Type `shell:startup` → Add shortcut there

---

## 📊 Features by Platform

| Feature | Windows | Linux | macOS |
|---------|:-------:|:-----:|:-----:|
| GUI | ✅ | ✅ | ✅ |
| Quick Scan | ✅ | ✅ | ✅ |
| Complete Discovery | ✅ | ✅ | ✅ |
| MITM Scan | ✅ | ✅ | ✅ |
| Traffic Monitor | ✅ | ✅ | ✅ |
| Device Blocking | ✅ | ✅ | ✅ |

All features work on all platforms! 🎉

---

## 🆘 Need Help?

### 📖 Read Documentation
- Quick commands: `QUICK_REFERENCE.md`
- Linux setup: `docs/LINUX_SETUP.md`
- Platform info: `docs/PLATFORM_SUPPORT.md`
- Troubleshooting: `docs/WHY_BLOCKING_DOESNT_WORK.md`

### 🧪 Test Your Setup
```bash
python3 test_install.py
```

### 🔍 Check Logs
Look at the "Activity Log" section in the GUI for errors

### 💬 Get Support
1. Check relevant documentation first
2. Run installation test
3. Review error messages
4. Open GitHub issue with details

---

## 🎉 Success Checklist

Before you start, make sure:

- [ ] Python 3.7+ installed (`python3 --version`)
- [ ] Dependencies installed (`pip3 install -r requirements.txt`)
- [ ] Scripts executable (`chmod +x` on Linux)
- [ ] Installation test passes (`python3 test_install.py`)
- [ ] Connected to WiFi/network
- [ ] Read `QUICK_REFERENCE.md`

All checked? **You're ready!** 🚀

---

## 🎯 What's Next?

### Right Now
```bash
python3 launch.py
```

### After First Launch
1. Try a Quick Scan
2. Explore the device list
3. Try right-click menu on a device
4. Read `QUICK_REFERENCE.md` for more commands

### Going Deeper
1. Read platform-specific docs
2. Set up desktop integration
3. Configure router settings
4. Try MITM features (with admin/root)

---

## 🌟 Version 2.0 Highlights

✨ **NEW in v2.0 Cross-Platform Edition:**
- ✅ Full Linux support
- ✅ macOS compatibility
- ✅ Cross-platform launcher
- ✅ Installation tester
- ✅ 2500+ lines of new documentation
- ✅ 7 new scripts
- ✅ Desktop integration
- ✅ Comprehensive troubleshooting guides

---

## 📞 Quick Links

| Topic | File |
|-------|------|
| 🚀 **Quick Start** | `START_HERE.md` (this file) |
| ⚡ **Quick Commands** | `QUICK_REFERENCE.md` |
| 🐧 **Linux Guide** | `docs/LINUX_SETUP.md` |
| 📖 **Full Docs** | `README.md` |
| 🔧 **Platform Info** | `docs/PLATFORM_SUPPORT.md` |
| 📋 **Changes** | `CHANGELOG.md` |
| 🧪 **Test Setup** | Run `python3 test_install.py` |

---

## 🎊 Final Words

**NetWatch Pro is now truly cross-platform!**

Whether you're on Windows, Linux, or macOS, you have access to the same powerful network monitoring features.

**Your next command:**
```bash
python3 launch.py
```

**Happy monitoring!** 🔍📡

---

**Version**: 2.0 Cross-Platform Edition  
**Date**: June 29, 2026  
**License**: MIT  
**Repository**: https://github.com/kaleab343/wifi-monitor

---

*Don't forget to star ⭐ the repo if you find it useful!*
