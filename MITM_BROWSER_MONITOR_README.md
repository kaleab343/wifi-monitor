# 🕵️ MITM Browser Monitor - Real-time Web Browsing Tracker

## Overview

The **MITM (Man-in-the-Middle) Browser Monitor** is an advanced network monitoring tool that intercepts and displays **real-time web browsing activity** of all devices on your network. Unlike basic device scanners that only show connected devices, this tool shows you **exactly what websites and pages users are visiting**.

## 🌟 Key Features

### Real-time Browsing Tracking
- **HTTP Traffic Capture**: See all HTTP requests with full URLs
- **HTTPS Traffic Detection**: Detect HTTPS connections via SNI (Server Name Indication)
- **Live Updates**: URLs appear in real-time as users browse
- **Device Attribution**: See which device is visiting which website

### Comprehensive Information Display
Each browsing entry shows:
- ⏰ **Timestamp**: When the request was made
- 📱 **Device**: Device name/hostname
- 🌐 **IP Address**: Device IP
- 🔒 **Protocol**: HTTP or HTTPS
- 📝 **Method**: GET, POST, CONNECT, etc.
- 🔗 **Full URL**: Complete website address

### Statistics & Analytics
- Total URLs captured
- HTTP vs HTTPS breakdown
- Number of active devices
- Per-device traffic statistics
- Export to JSON for analysis

### Integrated Device Management
- **Block from Browsing**: Right-click any browsing entry to block that device
- **Copy URLs**: Easily copy URLs or IP addresses
- **Real-time Filtering**: See browsing activity as it happens

## 🚀 How It Works

### Technical Details

1. **ARP Spoofing**: The tool positions itself as a man-in-the-middle by poisoning ARP tables
2. **IP Forwarding**: Forwards packets between devices and router to maintain connectivity
3. **Deep Packet Inspection**: Analyzes HTTP headers and TLS handshakes
4. **SNI Extraction**: Extracts server names from HTTPS connections (without decryption)
5. **DNS Correlation**: Maps DNS queries to IP addresses for better tracking

### What Can Be Monitored

✅ **HTTP Traffic** (Full URLs):
- Regular websites (http://)
- Complete path and query parameters
- HTTP methods (GET, POST, etc.)

✅ **HTTPS Traffic** (Domain Names):
- Website domain via SNI (e.g., facebook.com, youtube.com)
- Cannot see encrypted content or full paths
- Connection detection only

✅ **DNS Queries**:
- All domain name lookups
- Helps identify even encrypted traffic

❌ **What Cannot Be Seen**:
- Encrypted HTTPS content (messages, passwords, etc.)
- Full HTTPS URLs beyond domain name
- VPN-encrypted traffic

## 📋 Requirements

### Software Requirements
```bash
# Python 3.7+
pip install scapy

# Optional but recommended
pip install pywin32  # For Windows admin detection
```

### System Requirements
- **Administrator/Root Privileges**: Required for packet capture
- **Network Interface**: Wired or wireless network adapter
- **Same Network**: Must be on the same local network as target devices

### Supported Platforms
- ✅ Windows 10/11 (Primary support)
- ✅ Linux (Ubuntu, Debian, etc.)
- ✅ macOS (with some limitations)

## 🎯 Usage Guide

### Method 1: GUI (Recommended)

#### Step 1: Launch as Administrator
```bash
# Windows: Right-click and "Run as Administrator"
run_mitm_browser_gui.bat

# Or use the admin launcher
run_gui_as_admin_mitm.bat
```

#### Step 2: Navigate to MITM Tab
1. Open the application
2. Click on the **"🕵️ Browsing Monitor (MITM)"** tab

#### Step 3: Start Monitoring
1. Click **"▶️ Start MITM Monitor"**
2. Wait for initialization (a few seconds)
3. Browsing activity will appear automatically in real-time

#### Step 4: View Results
- See browsing history in the table
- View statistics at the top
- Right-click entries for options:
  - 📋 Copy URL
  - 📋 Copy IP
  - 🚫 Block device

#### Step 5: Stop Monitoring
1. Click **"⏹️ Stop Monitor"**
2. Network will be restored automatically

### Method 2: Standalone Script

```bash
# Run as Administrator
python mitm_browser_monitor.py

# Or specify router IP
python mitm_browser_monitor.py 192.168.1.1
```

## 📊 Example Output

```
[HTTP] 192.168.1.105 -> http://example.com/page.html
[HTTPS] 192.168.1.106 -> https://facebook.com/
[DNS] 192.168.1.107 -> youtube.com
[HTTP] 192.168.1.105 -> http://api.example.com/data?id=123
```

### GUI Display

| Time     | Device      | IP            | Protocol | Method  | URL                           |
|----------|-------------|---------------|----------|---------|-------------------------------|
| 14:23:45 | iPhone-John | 192.168.1.105 | HTTP     | GET     | http://example.com/page.html  |
| 14:23:46 | Galaxy-S21  | 192.168.1.106 | HTTPS    | CONNECT | https://facebook.com/         |
| 14:23:47 | Laptop-Mary | 192.168.1.107 | HTTPS    | CONNECT | https://youtube.com/          |

## 🔒 Security & Privacy Considerations

### Ethical Use Only
⚠️ **WARNING**: This tool is for **authorized network monitoring only**!

**Legal Uses**:
- ✅ Monitoring your own home network
- ✅ Parental controls
- ✅ Network troubleshooting
- ✅ Security research on your own devices
- ✅ Educational purposes

**Illegal Uses**:
- ❌ Monitoring networks you don't own/administer
- ❌ Unauthorized corporate espionage
- ❌ Intercepting others' private communications
- ❌ Any use without proper consent

### Privacy Protection
- HTTPS content remains encrypted
- Only metadata (domain names) is visible for HTTPS
- Full URLs only visible for unencrypted HTTP
- No password or login credential capture
- VPN traffic cannot be monitored

### Network Impact
- Minimal latency added (< 1ms typically)
- All traffic is forwarded, not blocked
- Network connectivity maintained during monitoring
- Clean shutdown restores original state

## 🛠️ Troubleshooting

### "Administrator privileges required"
**Solution**: Right-click the .bat file and select "Run as Administrator"

### "Scapy not installed"
```bash
pip install scapy
```

### "Could not resolve gateway MAC"
**Causes**:
- Wrong router IP
- Not connected to network
- Firewall blocking ARP

**Solution**:
1. Check router IP: Usually 192.168.1.1 or 192.168.0.1
2. Verify network connection
3. Temporarily disable firewall

### No browsing history appearing
**Possible Causes**:
1. **All HTTPS Traffic**: Modern browsers use HTTPS (you'll see domains only)
2. **No Active Browsing**: Users need to browse for data to appear
3. **VPN Active**: VPN encrypts all traffic
4. **Wrong Interface**: Tool using wrong network adapter

**Solutions**:
- Look for HTTPS entries (domain names)
- Have users browse some HTTP sites for testing
- Disable VPN temporarily
- Specify correct network interface

### "Packet capture timeout"
**Solution**: 
- Check if another packet capture tool is running
- Restart network adapter
- Reboot system

## 📁 Export & Analysis

### Export Features
The tool can export all captured data to JSON:

```json
{
  "export_time": "2024-01-15T14:30:00",
  "total_urls": 150,
  "total_devices": 5,
  "browsing_history": [
    {
      "timestamp": "2024-01-15T14:23:45",
      "device_ip": "192.168.1.105",
      "device_name": "iPhone-John",
      "protocol": "HTTP",
      "method": "GET",
      "url": "http://example.com/page.html"
    }
  ],
  "devices": {
    "AA:BB:CC:DD:EE:FF": {
      "ip": "192.168.1.105",
      "hostname": "iPhone-John",
      "traffic": {
        "http_requests": 25,
        "https_requests": 30,
        "dns_queries": 15
      }
    }
  }
}
```

### Analysis Ideas
- Track most visited sites
- Identify bandwidth-heavy users
- Monitor for suspicious domains
- Generate usage reports
- Parental monitoring

## 🔧 Advanced Configuration

### Custom Router IP
Edit `hybrid_router_gui.py`:
```python
router_ip = "192.168.0.1"  # Change to your router's IP
```

### Monitoring Duration
For standalone script:
```python
monitor.start_monitoring(duration=60)  # 60 seconds
monitor.start_monitoring(duration=None)  # Continuous
```

### Custom Callbacks
```python
def on_url_captured(entry):
    print(f"New URL: {entry['url']}")

monitor.start_monitoring(callback_new_url=on_url_captured)
```

## 📚 Technical Architecture

### Components
1. **ARP Poisoner**: Maintains MITM position via continuous ARP spoofing
2. **Packet Sniffer**: Captures all network packets using Scapy
3. **HTTP Parser**: Extracts URLs from HTTP requests
4. **HTTPS Detector**: Extracts SNI from TLS ClientHello
5. **DNS Tracker**: Correlates DNS queries with connections
6. **GUI Display**: Real-time Tkinter interface

### Threading Model
- **Main Thread**: GUI event loop
- **ARP Thread**: Continuous ARP poisoning
- **Sniffer Thread**: Packet capture and processing
- **Callbacks**: Thread-safe UI updates

## 🎓 Educational Value

This tool demonstrates:
- Network protocols (ARP, IP, TCP, HTTP, HTTPS)
- Man-in-the-middle attack techniques
- Packet capture and analysis
- TLS/SSL handshake process
- DNS resolution
- Network security concepts

## ⚖️ Legal Disclaimer

This tool is provided for **educational and authorized use only**. 

- Users are responsible for complying with all applicable laws
- Only use on networks you own or have explicit permission to monitor
- Unauthorized interception of communications is illegal in most jurisdictions
- The authors assume no liability for misuse of this tool

**Use responsibly and ethically!**

## 🤝 Support & Contributions

### Getting Help
- Check troubleshooting section above
- Review system requirements
- Ensure administrator privileges
- Verify Scapy installation

### Known Limitations
- Cannot decrypt HTTPS content (by design)
- VPN traffic not monitorable
- Some apps use certificate pinning
- Limited to local network

## 📝 Changelog

### Version 1.0 (2024-01-15)
- ✨ Initial release
- 🕵️ Real-time HTTP/HTTPS monitoring
- 📊 Statistics and analytics
- 💾 JSON export
- 🚫 Integrated device blocking
- 🎨 Modern GUI interface

---

**Made with ❤️ for network security education and home network management**
