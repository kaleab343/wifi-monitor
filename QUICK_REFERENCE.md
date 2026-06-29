# NetWatch Pro - Quick Reference Card

## 🚀 Launch Commands

### Windows
```batch
python launch.py                          # Basic mode
scripts\launch_wifi_monitor.bat           # Basic mode (alt)
scripts\run_gui_as_admin_mitm.bat         # Admin mode (right-click → Run as Admin)
```

### Linux
```bash
python3 launch.py                         # Basic mode
./scripts/launch_wifi_monitor.sh          # Basic mode (alt)
./scripts/launch_wifi_monitor_admin.sh    # Root mode (auto-sudo)
sudo python3 launch.py                    # Root mode (direct)
```

### macOS
```bash
python3 launch.py                         # Basic mode
sudo python3 launch.py                    # Root mode
```

## 📦 Installation

### Windows
```batch
pip install -r requirements.txt
python launch.py
```

### Linux (Debian/Ubuntu)
```bash
sudo apt-get install python3 python3-pip python3-tk
pip3 install -r requirements.txt
chmod +x scripts/*.sh launch.py
python3 launch.py
```

### Linux (Quick Setup)
```bash
./scripts/setup_mitm_scanner.sh
python3 launch.py
```

## 🔍 Features & Shortcuts

### Scanning Methods
| Feature | Button | Privileges | Speed |
|---------|--------|------------|-------|
| Quick Scan | 🔄 Quick Scan | None | Fast |
| Complete Discovery | 🔍 Complete Discovery | None | Medium |
| MITM Scan | 🕵️ MITM Scan | Admin/Root | Slow |

### Device Actions (Right-Click Menu)
- **Block Device** - Disconnect from network
- **Unblock Device** - Allow reconnection
- **Rename Device** - Set custom name
- **Set Device Type** - Categorize device
- **Copy MAC** - Copy MAC address
- **Copy IP** - Copy IP address

### Tabs
- **📱 Device Management** - View and control devices
- **🕵️ Traffic Monitor** - Real-time traffic analysis (requires admin/root)

## 🔐 Privilege Requirements

### Without Admin/Root ✅
- Quick Scan
- Complete Discovery
- Device listing
- Device management
- Router API access

### With Admin/Root 🔒
- MITM Passive Scan
- Traffic Monitor
- Deep packet inspection
- Raw socket access

## 🐛 Quick Troubleshooting

### "ModuleNotFoundError: No module named 'tkinter'"
```bash
# Linux
sudo apt-get install python3-tk         # Debian/Ubuntu
sudo dnf install python3-tkinter        # Fedora
sudo pacman -S tk                       # Arch
```

### "Permission denied" on scripts (Linux)
```bash
chmod +x scripts/*.sh launch.py
```

### "Operation not permitted" during scan (Linux)
```bash
sudo python3 launch.py
```

### MITM features not working
- **Windows**: Right-click → Run as Administrator
- **Linux**: Run with `sudo`
- Check if scapy is installed: `pip3 install scapy`

### GUI doesn't appear (Linux)
```bash
export DISPLAY=:0
python3 launch.py
```

## 📊 Status Indicators

| Icon | Meaning |
|------|---------|
| ● | Ready |
| ⟳ | Scanning |
| ✓ | Success |
| ✗ | Error |
| ⚠ | Warning |

## 🎨 Device Status

| Status | Color | Meaning |
|--------|-------|---------|
| Active | Green | Currently connected |
| Blocked | Red | Blocked from network |
| Offline | Gray | Not currently connected |
| This PC | Blue | Your computer |

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| F5 | Refresh scan (when implemented) |
| Ctrl+C | Copy selected device info |
| Delete | Block selected device |
| Right-Click | Context menu |

## 📁 Important Files

```
wifi-monitor/
├── launch.py              # Main launcher
├── run.py                 # Legacy launcher
├── test_install.py        # Test installation
├── requirements.txt       # Dependencies
├── data/
│   └── known_devices.json # Device database
├── scripts/
│   ├── *.bat             # Windows scripts
│   └── *.sh              # Linux scripts
└── docs/
    ├── LINUX_SETUP.md    # Linux guide
    └── PLATFORM_SUPPORT.md
```

## 🔧 Configuration

### Router Settings
Edit `src/utils/router_manager.py`:
```python
self.router_ip = "192.168.1.1"
self.username = "admin"
self.password = "password"
```

### Network Interface
Auto-detected, but can be manually set in scanner modules.

## 📖 Documentation Quick Links

| Topic | File |
|-------|------|
| General | `README.md` |
| Linux Setup | `docs/LINUX_SETUP.md` |
| Platform Support | `docs/PLATFORM_SUPPORT.md` |
| Blocking Guide | `docs/BLOCKING_STATUS.md` |
| Troubleshooting | `docs/WHY_BLOCKING_DOESNT_WORK.md` |
| Scripts Guide | `scripts/README.md` |
| Changelog | `CHANGELOG.md` |

## 🧪 Test Your Setup

```bash
python3 test_install.py
```

Expected: `✅ Installation is READY!`

## 🆘 Getting Help

1. Check relevant documentation
2. Run `test_install.py`
3. Check error logs in GUI
4. See troubleshooting guides
5. Open GitHub issue with details

## 💡 Pro Tips

### Linux Alias
```bash
echo 'alias nwp="python3 /path/to/wifi-monitor/launch.py"' >> ~/.bashrc
source ~/.bashrc
nwp  # Quick launch
```

### Windows Shortcut
```batch
REM Right-click launch.py → Create Shortcut → Move to Desktop
```

### Desktop Integration (Linux)
```bash
cp assets/NetWatchPro.desktop ~/.local/share/applications/
# Edit file to set correct paths
```

### Running at Startup
- **Windows**: Add to `shell:startup`
- **Linux**: Create systemd service (see `docs/LINUX_SETUP.md`)
- **macOS**: Create LaunchAgent

## 🔄 Common Workflows

### First Time Setup
```bash
1. Install dependencies
2. chmod +x scripts/*.sh launch.py (Linux only)
3. python3 test_install.py
4. python3 launch.py
```

### Daily Use
```bash
1. Launch application
2. Click "Quick Scan"
3. View devices
4. Right-click for actions
```

### Deep Scan
```bash
1. Launch with admin/root
2. Click "Complete Discovery"
3. Click "MITM Scan"
4. View detailed results
```

### Traffic Monitoring
```bash
1. Launch with admin/root
2. Switch to "Traffic Monitor" tab
3. Click "Start MITM Monitor"
4. Watch real-time traffic
```

## 📊 Feature Comparison

| Feature | Quick Scan | Complete | MITM |
|---------|-----------|----------|------|
| Speed | Fast | Medium | Slow |
| Accuracy | Good | Better | Best |
| Admin Required | No | No | Yes |
| Discovers Hidden | No | Some | Yes |
| Traffic Info | No | No | Yes |

## 🌐 Network Requirements

- ✅ Connected to WiFi/Ethernet
- ✅ Same network as target devices
- ✅ Router accessible (for blocking)
- ⚠️ Admin/Root for MITM features

---

**Quick Start**: `python3 launch.py`  
**Help**: `docs/LINUX_SETUP.md` (Linux) or `README.md`  
**Test**: `python3 test_install.py`  
**Version**: 2.0 Cross-Platform
