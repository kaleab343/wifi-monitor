# 🌐 Router Management Center

**Complete Control of Your China Telecom TG2212 Router**

---

## 🎯 What You Can Do

This Router Management Center gives you **FULL ACCESS** to your router with a modern, easy-to-use interface:

### 📱 Device Management
- ✅ View all connected devices (IP, MAC, hostname)
- 🚫 Block/unblock devices instantly
- 📊 See device status in real-time
- 🔍 Identify device types automatically

### 📶 WiFi Control
- 🔑 Change WiFi password
- 📝 Change network name (SSID)
- 👁️ View WiFi settings
- 🔐 View current WiFi password

### 🔒 Security
- 🛡️ MAC address filtering
- 🔑 Change admin password
- 🚫 Block unwanted devices
- 📋 View blocked devices list

### ⚙️ Router Management
- 📊 View router information
- 🔄 Reboot router
- 💾 See firmware version
- 🌐 Check WAN/LAN IP addresses

### 📋 Activity Logging
- 📝 Track all actions
- ⏰ Timestamped logs
- ✅ Success/error tracking

---

## 🚀 Quick Start

### Option 1: Modern GUI (Recommended)

**Just double-click:**
```
run_router_gui.bat
```

This opens a beautiful graphical interface with tabs for:
- 📱 Devices
- 📶 WiFi
- 🔒 Security
- ⚙️ Router
- 📋 Logs

### Option 2: Command Line

**View everything:**
```bash
python router_manager.py --action all
```

**View connected devices:**
```bash
python router_manager.py --action devices
```

**Block a device:**
```bash
python router_manager.py --action block --mac AA:BB:CC:DD:EE:FF
```

**Unblock a device:**
```bash
python router_manager.py --action unblock --mac AA:BB:CC:DD:EE:FF
```

**Change WiFi password:**
```bash
python router_manager.py --action change-wifi-password --value NewPassword123
```

**Change WiFi name:**
```bash
python router_manager.py --action change-ssid --value MyNewNetwork
```

**View WiFi info:**
```bash
python router_manager.py --action wifi-info
```

**Get current WiFi password:**
```bash
python router_manager.py --action wifi-password
```

**View router information:**
```bash
python router_manager.py --action router-info
```

**Reboot router:**
```bash
python router_manager.py --action reboot
```

---

## 📋 Requirements

- **Python 3.7+** (Download from [python.org](https://www.python.org/downloads/))
- **requests** library (auto-installed by batch file)

To install manually:
```bash
pip install requests
```

---

## 🎨 GUI Features

### Modern Design
- 🌑 Dark theme for comfortable viewing
- 📊 Professional layout with tabs
- 🎯 Easy-to-use buttons
- ⚡ Real-time updates

### Device Management Tab
- View all connected devices in a table
- See IP addresses, MAC addresses, and hostnames
- Block/unblock with one click
- Separate view for blocked devices

### WiFi Tab
- Change SSID easily
- Change password with visibility toggle
- View complete WiFi settings
- Beautiful formatted information display

### Security Tab
- Block devices by MAC address
- Change router admin password
- Enhanced security controls

### Router Tab
- View detailed router information
- System uptime
- Firmware version
- WAN/LAN IP addresses
- One-click router reboot

### Logs Tab
- See all actions in real-time
- Timestamped entries
- Color-coded success/error messages
- Clear log functionality

---

## 🔧 Configuration

The default router configuration is:
- **IP:** 192.168.1.1
- **Username:** user
- **Password:** 7dWU!fNf

To use different credentials, edit the files:

**For GUI (`router_gui.py`):**
```python
self.router = RouterManager("192.168.1.1", "user", "your_password")
```

**For CLI (`router_manager.py`):**
```bash
python router_manager.py --ip 192.168.1.1 --user user --password your_password --action all
```

---

## 📸 Screenshots

### Main Interface
```
╔══════════════════════════════════════════════════════════╗
║       🌐 Router Management Center                        ║
╚══════════════════════════════════════════════════════════╝

Tabs: [📱 Devices] [📶 WiFi] [🔒 Security] [⚙️ Router] [📋 Logs]
```

### Device List View
```
Connected Devices:
┌────────────────────────────────────────────────────────┐
│ # │ Hostname        │ IP           │ MAC             │
├───┼─────────────────┼──────────────┼─────────────────┤
│ 1 │ iPhone-12       │ 192.168.1.5  │ AA:BB:CC:DD:EE │
│ 2 │ Laptop-Dell     │ 192.168.1.10 │ 11:22:33:44:55 │
└────────────────────────────────────────────────────────┘

Buttons: [🔄 Refresh] [🚫 Block] [✅ Unblock]
```

---

## 🛡️ Security Notes

- ⚠️ **Keep your admin password secure**
- 🔒 **Use strong WiFi passwords** (8+ characters)
- 🚫 **Block unknown devices** immediately
- 📝 **Monitor logs** for suspicious activity
- 🔄 **Regular updates** - keep router firmware updated

---

## 🐛 Troubleshooting

### GUI won't start
```bash
# Install Python packages manually
pip install requests

# Run GUI directly
python router_gui.py
```

### Can't connect to router
1. Check router IP address (might be 192.168.0.1 instead)
2. Verify credentials are correct
3. Make sure you're connected to the WiFi network
4. Try accessing http://192.168.1.1 in browser first

### Python not found
- Download Python from [python.org](https://www.python.org/downloads/)
- During installation, check "Add Python to PATH"

### Commands not working
- Ensure you're connected to the router's network
- Check if router web interface is accessible
- Verify router model is TG2212

---

## 📚 API Features

The `RouterManager` class provides these methods:

### Device Management
```python
router.get_connected_devices()      # List all devices
router.get_mac_filter_list()        # List blocked devices
router.block_device(mac)            # Block device
router.unblock_device(mac)          # Unblock device
```

### WiFi Management
```python
router.get_wifi_settings()          # Get WiFi info
router.get_wifi_password()          # Get WiFi password
router.set_wifi_password(password)  # Change WiFi password
router.set_wifi_ssid(ssid)          # Change network name
```

### Router Control
```python
router.get_router_info()                        # Get router info
router.change_admin_password(old, new)          # Change admin password
router.reboot_router()                          # Reboot router
```

---

## 🎯 Use Cases

### Block a Kid's Device at Bedtime
1. Open GUI → Devices tab
2. Select the device
3. Click "🚫 Block Selected"
4. Device loses internet access immediately

### Change WiFi Password
1. Open GUI → WiFi tab
2. Enter new password
3. Click "Change Password"
4. All devices reconnect with new password

### Monitor Network Activity
1. Open GUI → Devices tab
2. Click "🔄 Refresh Devices"
3. See who's connected
4. Block unwanted devices

### Quick Device Block via CLI
```bash
python router_manager.py --action block --mac AA:BB:CC:DD:EE:FF
```

---

## 📝 Files Overview

```
wifi_protion/
├── router_manager.py          # Core API library
├── router_gui.py              # Graphical interface
├── block_device_router.py     # Original blocking script
├── run_router_gui.bat         # GUI launcher (Windows)
├── run_router_cli.bat         # CLI launcher (Windows)
└── ROUTER_MANAGER_README.md   # This file
```

---

## 🌟 Features Comparison

| Feature | Original Script | New GUI | New CLI |
|---------|----------------|---------|---------|
| Block devices | ✅ | ✅ | ✅ |
| Unblock devices | ❌ | ✅ | ✅ |
| View devices | ❌ | ✅ | ✅ |
| Change WiFi password | ❌ | ✅ | ✅ |
| Change SSID | ❌ | ✅ | ✅ |
| Router info | ❌ | ✅ | ✅ |
| Activity logs | ❌ | ✅ | ❌ |
| Modern UI | ❌ | ✅ | ❌ |
| Easy to use | ⚠️ | ✅ | ✅ |

---

## 🔮 Future Enhancements

Potential additions:
- 📊 Network traffic monitoring
- ⏰ Scheduled device blocking (parental controls)
- 📱 Mobile app interface
- 🔔 Device connection notifications
- 📈 Bandwidth usage statistics
- 🌐 Port forwarding management
- 🔥 Firewall rules management

---

## 💡 Tips & Tricks

1. **Quick Block:** Use the Security tab to block by MAC address
2. **Auto-Refresh:** GUI refreshes all info on startup
3. **Log Everything:** Check the Logs tab for troubleshooting
4. **Password Visibility:** Use "Show Password" checkbox in WiFi tab
5. **Confirmation Dialogs:** All dangerous actions ask for confirmation

---

## ⚠️ Important Notes

- 🔌 **Rebooting** the router disconnects all devices for 1-2 minutes
- 🔑 **Changing WiFi password** disconnects all devices
- 📝 **Changing SSID** requires all devices to reconnect
- 🚫 **Blocking devices** is instant and permanent until unblocked
- 🔐 **Admin password change** requires current password

---

## 📞 Support

For issues or questions:
1. Check the Logs tab for error messages
2. Verify router credentials
3. Ensure Python and dependencies are installed
4. Check router web interface accessibility

---

## 🎓 Learning Resources

- **Python requests:** https://docs.python-requests.org/
- **Tkinter GUI:** https://docs.python.org/3/library/tkinter.html
- **Router APIs:** Check your router's documentation

---

## 📜 License

Free to use and modify for personal use.

---

**Enjoy full control of your router! 🚀**

*Created: 2026-02-07*
*Version: 1.0*
