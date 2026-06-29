# NetWatch Pro - WiFi Network Monitor

A comprehensive, **cross-platform** WiFi network monitoring and management tool with device discovery, traffic analysis, and blocking capabilities.

**Supported Platforms**: Windows, Linux, macOS

---

## 🚀 **NEW USER? [START HERE →](START_HERE.md)**

**Quick Start:**
```bash
python3 launch.py    # All platforms
```

---

## 🚀 Quick Start

### Option 1: Cross-Platform Launcher (Recommended - All OS)
```bash
python3 launch.py
# or on Windows: python launch.py
```

### Option 2: Desktop Shortcut (Windows)
Double-click **"NetWatch Pro - WiFi Monitor"** on your desktop.

### Option 3: Shell Scripts (Linux)
```bash
./scripts/launch_wifi_monitor.sh
```

### Option 4: Command Line (All OS)
```bash
python run.py
```

**For Linux users**: See [Linux Setup Guide](docs/LINUX_SETUP.md) for detailed instructions.

## 📁 Project Structure

```
wifi-monitor/
├── run.py                      # Main launcher script (legacy)
├── launch.py                   # Cross-platform launcher (recommended)
├── requirements.txt            # Python dependencies
├── LICENSE                     # License file
├── .gitignore                 # Git ignore rules
│
├── src/                        # Source code
│   ├── gui/                   # GUI components
│   │   └── hybrid_router_gui.py
│   ├── scanners/              # Network scanning modules
│   │   ├── python_arp_scanner.py
│   │   ├── complete_device_discovery.py
│   │   ├── mdns_ssdp_discovery.py
│   │   └── mitm_passive_scanner.py
│   └── utils/                 # Utility modules
│       └── router_manager.py
│
├── scripts/                    # Launcher scripts
│   ├── launch_wifi_monitor.bat           # Windows launcher
│   ├── launch_wifi_monitor_admin.bat     # Windows admin launcher
│   ├── launch_wifi_monitor.sh            # Linux launcher
│   ├── launch_wifi_monitor_admin.sh      # Linux root launcher
│   ├── run_gui_as_admin.sh              # Linux root GUI
│   ├── run_mitm_scan.sh                 # Linux MITM scanner
│   └── setup_mitm_scanner.sh            # Linux dependency installer
│
├── docs/                       # Documentation
│   ├── README.md              # Main documentation
│   ├── LINUX_SETUP.md         # Linux installation guide
│   ├── BLOCKING_STATUS.md     # Blocking guide
│   ├── WHY_BLOCKING_DOESNT_WORK.md
│   ├── FIXED_NO_CPP_NEEDED.md
│   └── README_DESKTOP_SHORTCUTS.md
│
├── data/                       # Data files
│   ├── known_devices.json     # Device database
│   └── mitm_devices.json      # MITM scan results
│
└── assets/                     # Resources
    ├── app_icon.ico           # Application icon (Windows)
    ├── app_icon.png           # Application icon (Linux)
    ├── NetWatchPro.manifest   # Windows manifest
    └── NetWatchPro.desktop    # Linux desktop entry
```

## ✨ Features

### 🔍 Device Discovery
- **Quick Scan** - Fast ARP-based device discovery
- **Complete Discovery** - Multi-protocol detection (NetBIOS, mDNS, SSDP)
- **MITM Passive Scan** - Deep packet inspection to detect all devices

### 📊 Network Monitoring
- Real-time traffic analysis
- Upload/download statistics per device
- Device type identification
- Manufacturer detection from MAC address

### 🛡️ Device Management
- Block/Unblock devices (right-click menu)
- Rename devices
- Set custom device types
- Copy MAC/IP addresses

### 🖥️ User Interface
- Modern, clean GUI
- Dark theme
- Real-time activity logs
- Device status indicators
- "This PC" identification

## 🔧 Installation

### Requirements
- Python 3.7+
- Windows/Linux/macOS
- Network access

### Linux Setup

#### Quick Install (Debian/Ubuntu)
```bash
# Install dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk

# Clone or download the project
cd wifi-monitor

# Install Python packages
pip3 install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh
chmod +x launch.py

# Run the application
python3 launch.py
```

#### Quick Install (Fedora/RHEL)
```bash
sudo dnf install python3 python3-pip python3-tkinter
pip3 install -r requirements.txt
chmod +x scripts/*.sh launch.py
python3 launch.py
```

#### Quick Install (Arch Linux)
```bash
sudo pacman -S python python-pip tk
pip3 install -r requirements.txt
chmod +x scripts/*.sh launch.py
python3 launch.py
```

### Windows Setup

#### Install Dependencies
```bash
# Install Python from python.org (3.7+)
# Then run:
pip install -r requirements.txt
```

### macOS Setup
```bash
# Python 3 comes with tkinter on macOS
pip3 install -r requirements.txt
python3 launch.py
```

### Dependencies
- `requests` - HTTP communication with router
- `scapy` - Network packet manipulation (MITM features, optional)
- `pillow` - Image processing (optional)
- `tkinter` - GUI framework (included with Python on Windows/macOS, install separately on Linux)

### Linux Additional Dependencies
```bash
# For MITM features (requires root):
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo dnf install libpcap-devel    # Fedora/RHEL
sudo pacman -S libpcap            # Arch

# Install scapy
pip3 install scapy
```

## 📖 Usage

### Launch Methods

#### Cross-Platform (Recommended)
```bash
# Auto-detects OS and runs appropriately
python3 launch.py

# With admin/root privileges for MITM features:
# Windows: Right-click launch.py → "Run as Administrator"
# Linux/Mac: sudo python3 launch.py
```

#### Linux Specific
```bash
# Normal mode
./scripts/launch_wifi_monitor.sh

# With root privileges (for MITM)
./scripts/launch_wifi_monitor_admin.sh

# Or use sudo
sudo python3 run.py
```

#### Windows Specific
```batch
REM Normal mode
scripts\launch_wifi_monitor.bat

REM Administrator mode (for MITM)
scripts\launch_wifi_monitor_admin.bat
```

### Basic Scanning
1. Launch application
2. Click **"🔄 Quick Scan"**
3. View discovered devices

### Advanced Features
1. **Complete Discovery**: Multi-protocol deep scan
2. **MITM Scan**: Detect hidden/silent devices (requires admin)
3. **Traffic Monitor**: Real-time traffic analysis (requires admin)

### Device Actions (Right-Click Menu)
- **Block Device** - Disconnect device from network
- **Unblock Device** - Allow device to reconnect
- **Rename Device** - Set custom friendly name
- **Set Device Type** - Categorize device
- **Copy MAC/IP** - Copy to clipboard

## 🔐 Admin Mode

### Windows
For MITM features (traffic monitoring, deep scanning):
1. Right-click **"NetWatch Pro - WiFi Monitor"** shortcut
2. Select **"Run as Administrator"**
3. Or use `scripts\run_gui_as_admin_mitm.bat`

### Linux/macOS
For MITM features:
```bash
# Option 1: Use sudo
sudo python3 launch.py

# Option 2: Use provided script
sudo ./scripts/launch_wifi_monitor_admin.sh

# Option 3: Grant capabilities (Linux only, more secure)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
python3 launch.py
```

**Note:** Root/admin privileges are only required for:
- MITM passive scanning
- Traffic monitoring
- Deep packet inspection

Regular device scanning works without elevated privileges.

## ⚙️ Configuration

### Router Settings
Edit `src/utils/router_manager.py`:
```python
self.router_ip = "192.168.1.1"    # Your router IP
self.username = "admin"            # Router username
self.password = "password"         # Router password
```

## 🐛 Troubleshooting

### Device Scanning Issues
- Ensure you're connected to WiFi
- Try "Complete Discovery" for better results
- Use "MITM Scan" to detect silent devices

### Blocking Not Working
- Check router compatibility (see `docs/WHY_BLOCKING_DOESNT_WORK.md`)
- Verify router credentials
- Some routers don't support web-based MAC filtering

### Application Won't Start
- Check Python version: `python --version`
- Install dependencies: `pip install -r requirements.txt`
- Check error logs in console

## 📚 Documentation

- **[Platform Support Guide](docs/PLATFORM_SUPPORT.md)** - Windows/Linux/macOS compatibility
- **[Linux Setup Guide](docs/LINUX_SETUP.md)** - Complete Linux installation and configuration
- **Main Docs**: `docs/README.md`
- **Blocking Guide**: `docs/BLOCKING_STATUS.md`
- **Troubleshooting**: `docs/WHY_BLOCKING_DOESNT_WORK.md`
- **Desktop Setup**: `docs/README_DESKTOP_SHORTCUTS.md`

## 🖥️ Platform Compatibility

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| GUI Interface | ✅ | ✅ | ✅ |
| Quick Scan (ARP) | ✅ | ✅ | ✅ |
| Complete Discovery | ✅ | ✅ | ✅ |
| MITM Passive Scan | ✅ (Admin) | ✅ (Root) | ✅ (Root) |
| Traffic Monitor | ✅ (Admin) | ✅ (Root) | ✅ (Root) |
| Device Blocking | ✅ | ✅ | ✅ |
| Desktop Shortcuts | ✅ (.lnk) | ✅ (.desktop) | ✅ (.app) |
| Auto-start | ✅ (Task Scheduler) | ✅ (systemd) | ✅ (LaunchAgent) |

**Note**: Features marked with (Admin/Root) require elevated privileges.

## 🤝 Contributing

This is a personal project, but suggestions are welcome!

## 📜 License

See LICENSE file for details.

## 🔗 Repository

https://github.com/kaleab343/wifi-monitor.git

---

**Version**: 2.0  
**Last Updated**: February 16, 2026  
**Python**: 3.7+  
**Platform**: Windows, Linux, Mac
