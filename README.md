# NetWatch Pro - WiFi Network Monitor

A comprehensive WiFi network monitoring and management tool with device discovery, traffic analysis, and blocking capabilities.

## 🚀 Quick Start

### Option 1: Desktop Shortcut (Recommended)
Double-click **"NetWatch Pro - WiFi Monitor"** on your desktop.

### Option 2: Command Line
```bash
python run.py
```

## 📁 Project Structure

```
wifi-monitor/
├── run.py                      # Main launcher script
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
│   ├── launch_wifi_monitor.bat
│   └── launch_wifi_monitor_admin.bat
│
├── docs/                       # Documentation
│   ├── README.md              # Main documentation
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
    ├── app_icon.ico           # Application icon
    └── NetWatchPro.manifest   # Windows manifest
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
- Windows/Linux/Mac
- Network access

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Dependencies
- `requests` - HTTP communication with router
- `scapy` - Network packet manipulation (MITM features)
- `pillow` - Image processing (optional)
- `tkinter` - GUI framework (included with Python)

## 📖 Usage

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

For MITM features (traffic monitoring, deep scanning):
1. Right-click **"NetWatch Pro - WiFi Monitor"** shortcut
2. Select **"Run as Administrator"**
3. Or use the desktop shortcut (already configured for admin)

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

- **Main Docs**: `docs/README.md`
- **Blocking Guide**: `docs/BLOCKING_STATUS.md`
- **Troubleshooting**: `docs/WHY_BLOCKING_DOESNT_WORK.md`
- **Desktop Setup**: `docs/README_DESKTOP_SHORTCUTS.md`

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
