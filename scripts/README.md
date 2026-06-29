# NetWatch Pro - Launch Scripts

This directory contains platform-specific launcher scripts for NetWatch Pro.

## 📁 Scripts Overview

### Windows Scripts (.bat)

| Script | Description | Admin Required |
|--------|-------------|----------------|
| `launch_wifi_monitor.bat` | Basic launcher | No |
| `launch_wifi_monitor_admin.bat` | Admin launcher | Yes |
| `run_gui_as_admin.bat` | GUI with admin | Yes |
| `run_gui_as_admin_mitm.bat` | GUI with MITM | Yes |
| `run_hybrid_gui.bat` | Hybrid GUI launcher | No |
| `run_mitm_scan.bat` | MITM scanner | Yes |
| `setup_mitm_scanner.bat` | Dependency installer | No |

### Linux Scripts (.sh)

| Script | Description | Root Required |
|--------|-------------|---------------|
| `launch_wifi_monitor.sh` | Basic launcher | No |
| `launch_wifi_monitor_admin.sh` | Root launcher (auto-sudo) | Yes |
| `run_gui_as_admin.sh` | GUI with root | Yes |
| `run_mitm_scan.sh` | MITM scanner | Yes |
| `setup_mitm_scanner.sh` | Dependency installer | No* |

*May request sudo for package installation

## 🚀 Usage

### Windows

Simply double-click the `.bat` file you want to run:

```batch
REM Basic scanning
launch_wifi_monitor.bat

REM Admin mode (right-click → Run as Administrator)
launch_wifi_monitor_admin.bat
```

### Linux

First make scripts executable (one time):
```bash
chmod +x *.sh
```

Then run:
```bash
# Basic scanning
./launch_wifi_monitor.sh

# Root mode (auto-requests sudo)
./launch_wifi_monitor_admin.sh

# Or with sudo directly
sudo ./launch_wifi_monitor.sh
```

## 🔐 Privilege Requirements

### Features WITHOUT Admin/Root

✅ Quick Scan (ARP)
✅ Complete Discovery (NetBIOS, mDNS, SSDP)
✅ Device listing
✅ GUI interface
✅ Router API access
✅ Device management (rename, categorize)

### Features WITH Admin/Root

🔒 MITM Passive Scanning
🔒 Traffic Monitoring
🔒 Deep Packet Inspection
🔒 Raw Socket Access
🔒 IP Forwarding
🔒 Promiscuous Mode

## 📋 Script Details

### `launch_wifi_monitor.sh` / `.bat`
- **Purpose**: Basic launcher for normal use
- **Privileges**: Not required
- **Features**: Quick scan, device listing, basic features

### `launch_wifi_monitor_admin.sh` / `.bat`
- **Purpose**: Launch with elevated privileges
- **Privileges**: Admin/Root
- **Features**: All features including MITM
- **Linux**: Auto-detects if root and requests sudo if needed

### `run_gui_as_admin.sh` / `.bat`
- **Purpose**: Directly launch GUI with admin/root
- **Privileges**: Admin/Root required
- **Features**: Full GUI with all features

### `run_mitm_scan.sh` / `.bat`
- **Purpose**: Run MITM scanner standalone (CLI)
- **Privileges**: Admin/Root required
- **Duration**: 30 seconds of passive scanning
- **Output**: JSON file with discovered devices

### `setup_mitm_scanner.sh` / `.bat`
- **Purpose**: Install all dependencies
- **Privileges**: May need sudo for system packages
- **Linux**: Auto-detects package manager
- **Windows**: Uses pip for Python packages

## 🔧 Troubleshooting

### Windows

**"Python not found"**
```batch
REM Add Python to PATH or use full path
C:\Python39\python.exe launch.py
```

**"Access denied" on admin scripts**
```batch
REM Right-click the .bat file
REM Select "Run as Administrator"
```

### Linux

**"Permission denied"**
```bash
# Make scripts executable
chmod +x *.sh
```

**"Command not found: python3"**
```bash
# Install Python 3
sudo apt-get install python3  # Debian/Ubuntu
sudo dnf install python3      # Fedora
sudo pacman -S python         # Arch
```

**MITM features not working**
```bash
# Run with sudo
sudo ./launch_wifi_monitor.sh
```

## 🎯 Which Script Should I Use?

### I want to...

**Just scan my network and see devices**
- Windows: `launch_wifi_monitor.bat`
- Linux: `./launch_wifi_monitor.sh`

**Monitor traffic and use MITM features**
- Windows: `run_gui_as_admin_mitm.bat` (right-click → Run as Admin)
- Linux: `./launch_wifi_monitor_admin.sh`

**Run MITM scanner standalone without GUI**
- Windows: `run_mitm_scan.bat` (right-click → Run as Admin)
- Linux: `./run_mitm_scan.sh`

**Install all dependencies**
- Windows: `setup_mitm_scanner.bat`
- Linux: `./setup_mitm_scanner.sh`

## 💡 Pro Tips

### Linux

**Create desktop shortcut:**
```bash
# Copy desktop entry
cp ../assets/NetWatchPro.desktop ~/.local/share/applications/

# Edit paths to match your installation
nano ~/.local/share/applications/NetWatchPro.desktop
```

**Create alias:**
```bash
# Add to ~/.bashrc or ~/.zshrc
echo 'alias netwatchpro="python3 /path/to/wifi-monitor/launch.py"' >> ~/.bashrc
source ~/.bashrc

# Now just run:
netwatchpro
```

**Run at startup (systemd):**
```bash
# See docs/LINUX_SETUP.md for full instructions
sudo systemctl enable netwatchpro
```

### Windows

**Create desktop shortcut:**
```batch
REM Right-click launch_wifi_monitor.bat
REM Select "Create Shortcut"
REM Drag to desktop
```

**Add to startup:**
```batch
REM Press Win+R
REM Type: shell:startup
REM Copy launch_wifi_monitor.bat shortcut there
```

## 📖 Further Reading

- **[Linux Setup Guide](../docs/LINUX_SETUP.md)** - Complete Linux instructions
- **[Platform Support](../docs/PLATFORM_SUPPORT.md)** - Cross-platform guide
- **[Main README](../README.md)** - General documentation

---

**Last Updated**: June 29, 2026  
**Scripts**: Windows (.bat) and Linux (.sh)  
**Version**: 2.0 Cross-Platform
