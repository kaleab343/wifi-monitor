# 🌐 WiFi Router Manager - Network Device Monitor & Manager

A powerful network monitoring and management tool that combines device scanning, traffic analysis, and router control capabilities.

![Version](https://img.shields.io/badge/version-2.0-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## 🚀 Features

### 📱 Device Management
- **Quick Scan** - Fast ARP-based device discovery
- **Complete Discovery** - Advanced scanning using NetBIOS, mDNS, SSDP, and MAC database
- **Custom Device Naming** - Rename and categorize your devices
- **Block/Unblock Devices** - Control network access via router API

### 🕵️ MITM Network Analysis
- **100% Traffic Capture** - No packet filtering, captures ALL network traffic
- **Promiscuous Mode** - Complete network visibility
- **Protocol Detection** - Identifies 20+ protocols (HTTP, HTTPS, DNS, SSH, FTP, RDP, mDNS, SSDP, ARP, etc.)
- **Silent Device Detection** - Identifies connected but inactive devices
- **Real-time Traffic Monitoring** - Live analysis of network activity

### 📊 Dynamic Interface
- **Smart Column Headers** - Changes based on scan mode (Traffic Type for MITM, Manufacturer for normal scans)
- **Merged Results** - Combines Quick Scan and MITM data for comprehensive device view
- **Traffic Statistics** - Upload/download bytes, packet counts, and protocol breakdowns

## 📋 Requirements

### System Requirements
- **OS:** Windows 10/11
- **Python:** 3.7 or higher
- **Administrator Privileges:** Required for MITM features

### Python Dependencies
```bash
pip install -r requirements.txt
```

**Required packages:**
- `scapy` - Packet capture and network analysis
- `requests` - Router API communication
- `tkinter` - GUI (usually included with Python)

## 🛠️ Installation

### Option 1: Use Pre-built Executable (Recommended)

1. Download `WiFiRouterManager.exe` from the releases page
2. Run as Administrator (right-click → "Run as administrator")
3. Start scanning and managing your network!

### Option 2: Run from Source

1. Clone the repository:
```bash
git clone https://github.com/kaleab343/wifi-monitor.git
cd wifi-monitor
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
# For normal features
python hybrid_router_gui.py

# For MITM features (requires admin)
run_gui_as_admin_mitm.bat
```

## 📖 Usage Guide

### Basic Workflow

1. **Start the Application**
   - Run `WiFiRouterManager.exe` or `python hybrid_router_gui.py`

2. **Scan Your Network**
   - Click **"🔄 Quick Scan"** to find connected devices
   - Click **"🔍 Complete Discovery"** for detailed device information

3. **MITM Traffic Analysis** (Requires Admin)
   - First run Quick Scan to find devices
   - Then click **"🕵️ MITM Scan"** to analyze traffic
   - Results show protocol usage and silent devices

4. **Manage Devices**
   - Right-click any device to rename or set device type
   - Select a device and click **"🚫 Block"** to disconnect it
   - Click **"✅ Unblock"** to restore access

### Scan Modes Explained

#### 🔄 Quick Scan
- **Method:** ARP table scanning
- **Speed:** Fast (seconds)
- **Shows:** IP, MAC, basic device info
- **Column Header:** "Manufacturer"

#### 🔍 Complete Discovery
- **Methods:** NetBIOS, mDNS, SSDP, MAC database
- **Speed:** Moderate (30-60 seconds)
- **Shows:** Hostnames, device types, OS detection
- **Column Header:** "Manufacturer"

#### 🕵️ MITM Scan
- **Method:** ARP spoofing + packet capture
- **Speed:** 30 seconds (configurable)
- **Shows:** Traffic types, protocols, silent devices
- **Column Header:** "Traffic Type"
- **Requirements:** Administrator privileges

## 🔒 Security & Privacy

### What This Tool Does
- Scans your local network for connected devices
- Analyzes network traffic when MITM mode is enabled
- Manages device access through your router

### Important Notes
- ⚠️ **MITM features require Administrator/root privileges**
- ⚠️ **Only use on networks you own or have permission to monitor**
- ⚠️ **Traffic analysis is performed locally - no data is sent externally**
- ✅ Network state is restored after MITM scan completes

## 📁 Project Structure

```
wifi-monitor/
├── hybrid_router_gui.py          # Main GUI application
├── mitm_passive_scanner.py       # MITM traffic capture engine
├── router_manager.py             # Router API integration
├── complete_device_discovery.py  # Advanced device discovery
├── device_manager_gui.py         # Device database manager
├── mdns_ssdp_discovery.py        # Network protocol discovery
├── known_devices.json            # Device database
├── requirements.txt              # Python dependencies
├── app_icon.ico                  # Application icon
├── run_gui_as_admin_mitm.bat    # Admin launcher (Windows)
└── README.md                     # This file
```

## 🎯 Key Features Breakdown

### Traffic Protocol Detection
The MITM scanner detects and identifies:

**Application Layer:**
- HTTP (Web traffic)
- HTTPS (Secure web traffic)
- DNS (Domain lookups)
- DHCP (IP assignment)

**Transport Layer:**
- TCP (Connection-oriented)
- UDP (Connectionless)

**Network Discovery:**
- mDNS (Apple devices)
- SSDP (UPnP discovery)
- ARP (Address resolution)

**Remote Access:**
- SSH (Secure shell)
- RDP (Remote desktop)
- FTP (File transfer)
- VNC (Remote desktop)

### Dynamic UI Behavior

The application adapts based on the scan mode:

| Scan Type | Column Header | Data Shown |
|-----------|--------------|------------|
| Quick Scan | Manufacturer | Apple, Samsung, TP-Link, etc. |
| Complete Discovery | Manufacturer | Device manufacturer from MAC |
| MITM Scan | Traffic Type | HTTPS, DNS, ARP, SSH, etc. |

## 🐛 Troubleshooting

### MITM Scan Not Working
- **Solution:** Run as Administrator (required for packet capture)
- **Check:** Ensure Npcap/WinPcap is installed (comes with Scapy)

### No Devices Found
- **Check:** You're connected to the network
- **Check:** Firewall isn't blocking the application
- **Try:** Run as Administrator

### Router API Features Not Working
- **Check:** Router credentials in `router_manager.py`
- **Check:** Router IP address is correct (default: 192.168.1.1)
- **Note:** Some routers require specific API access

## 🔧 Configuration

### Router Settings
Edit `router_manager.py` to configure:
```python
ROUTER_IP = "192.168.1.1"      # Your router's IP
ROUTER_USER = "admin"           # Router username
ROUTER_PASS = "password"        # Router password
```

### MITM Scan Duration
Edit `hybrid_router_gui.py`:
```python
scanner.start_passive_scan(duration=30)  # Change 30 to desired seconds
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and network administration purposes only. Use responsibly and only on networks you own or have explicit permission to monitor. The authors are not responsible for misuse or damage caused by this software.

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing issues for solutions
- Review the documentation above

## 🙏 Acknowledgments

- **Scapy** - Powerful packet manipulation library
- **Python Community** - For excellent networking libraries
- **Contributors** - Thank you for your contributions!

---

**Made with ❤️ for network administrators and security enthusiasts**
