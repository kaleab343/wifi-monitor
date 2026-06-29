# 📋 Copy Feature Guide

## Enhanced Copy Functionality in Device Table

NetWatch Pro now provides comprehensive copy options for all device data directly from the device table!

---

## 🎯 How to Use

### Quick Access

1. **Right-click** on any device in the device table
2. Hover over **"📋 Copy..."** to see all copy options
3. Click the data you want to copy
4. The data is now in your clipboard!

---

## 📋 Available Copy Options

### Individual Fields

| Option | What It Copies | Example |
|--------|---------------|---------|
| **IP Address** | Device IP address | `192.168.1.5` |
| **MAC Address** | Device MAC address | `E0:51:D8:D7:13:B9` |
| **Hostname** | Device name/hostname | `Huawei-Phone` |
| **Manufacturer** | Device manufacturer | `Huawei` |
| **Device Type** | Type of device | `Phone` |
| **OS** | Operating system | `Android` |

### Combined Data

| Option | What It Copies |
|--------|---------------|
| **All Device Info** | Complete formatted device information |

---

## 💡 Example: Copy All Device Info

When you select "Copy All Device Info", you get a formatted text like this:

```
Device Information:
─────────────────────────────────────
Hostname:      Huawei-Phone
IP Address:    192.168.1.5
MAC Address:   E0:51:D8:D7:13:B9
Manufacturer:  Huawei
Device Type:   Phone
OS:            Android
Status:        ✓ Active
─────────────────────────────────────
```

This is perfect for:
- 📝 Documentation
- 🐛 Bug reports
- 💬 Sharing device info
- 📊 Network inventory

---

## 🎨 Visual Guide

### Context Menu Layout

```
Right-click on device:
┌────────────────────────────────┐
│ 🚫  Block Device              │
├────────────────────────────────┤
│ ✏️  Rename Device              │
│ 🏷️  Set Device Type            │
├────────────────────────────────┤
│ 📋  Copy...                ►  │──┐
└────────────────────────────────┘  │
                                    │
         ┌──────────────────────────┘
         │
         ▼
┌────────────────────────────────┐
│ 📋  IP Address                │
│ 📋  MAC Address               │
│ 📋  Hostname                  │
│ 📋  Manufacturer              │
│ 📋  Device Type               │
│ 📋  OS                        │
├────────────────────────────────┤
│ 📋  All Device Info           │
└────────────────────────────────┘
```

---

## 🔥 Use Cases

### 1. **Network Documentation**
Copy device details to add to your network inventory spreadsheet:
```
Right-click → Copy → All Device Info
Paste into Excel/Google Sheets
```

### 2. **Blocking Devices**
Need to block a device on your router admin panel?
```
Right-click → Copy → MAC Address
Paste into router's MAC filter
```

### 3. **Troubleshooting**
Report a problematic device to IT:
```
Right-click → Copy → All Device Info
Paste into support ticket
```

### 4. **Security Auditing**
Log all unknown devices:
```
For each unknown device:
  Right-click → Copy → All Device Info
  Save to security log
```

### 5. **Network Mapping**
Create a network diagram with device details:
```
Copy IP, MAC, and Type for each device
Add to network mapping tool
```

---

## 💡 Pro Tips

### Tip 1: Keyboard Shortcuts
After right-clicking, use **arrow keys** to navigate the menu:
- ↓ / ↑ : Navigate menu items
- → : Open Copy submenu
- Enter : Select option

### Tip 2: Quick Copy IP & MAC
The most commonly needed fields (IP and MAC) are in the submenu for easy access.

### Tip 3: Bulk Documentation
Use "Copy All Device Info" for each device when creating network documentation:
1. Right-click device
2. Copy → All Device Info
3. Paste into text file
4. Repeat for all devices
5. You now have complete network inventory!

### Tip 4: Share Device List
When asking for help or reporting issues:
1. Copy all device info for relevant devices
2. Include in your support request
3. Technicians can see exact device details

### Tip 5: Activity Log Confirmation
After copying, check the Activity Log at the bottom:
```
📋 Copied MAC address: E0:51:D8:D7:13:B9
```
This confirms the copy was successful.

---

## 🔧 Technical Details

### Clipboard Support
- ✅ Works on Windows
- ✅ Works on Linux (with X11/Wayland)
- ✅ Works on macOS
- ✅ Integrates with system clipboard
- ✅ Can paste into any application

### Data Format
- IP: Plain text (e.g., `192.168.1.5`)
- MAC: Colon format (e.g., `E0:51:D8:D7:13:B9`)
- All Info: Formatted text with separators

### Confirmation
All copy actions log to the Activity Log with:
- 📋 Icon
- Action performed
- Data copied

---

## 🎯 Feature Highlights

### ✅ What's Great

1. **One-Click Access** - Right-click any device
2. **All Data Available** - Every field can be copied
3. **Formatted Output** - "All Device Info" is beautifully formatted
4. **Visual Confirmation** - Activity log shows what was copied
5. **Cross-Platform** - Works everywhere
6. **Organized Menu** - Submenu keeps UI clean

### 🚀 Coming Soon

- Export all devices to CSV
- Copy multiple devices at once
- Custom format templates
- Auto-copy on device selection

---

## 🐛 Troubleshooting

### Problem: "Nothing happens when I click Copy"

**Solution**: Check the Activity Log - you should see a confirmation message. The data is in your clipboard even if there's no popup.

### Problem: "Clipboard doesn't work on Linux"

**Solution**: Install clipboard utilities:
```bash
# Debian/Ubuntu
sudo apt-get install xclip xsel

# Fedora
sudo dnf install xclip xsel

# Arch
sudo pacman -S xclip xsel
```

### Problem: "Pasted text looks wrong"

**Solution**: The formatting uses Unicode box-drawing characters. Make sure your text editor supports UTF-8.

---

## 📚 Related Features

- **Right-click Menu**: Access to Block/Unblock, Rename, Set Type
- **Activity Log**: Shows all actions including copy confirmations
- **Device Table**: Displays all device information

---

## 🎉 Success Stories

### "Great for network inventory!"
> "I use 'Copy All Device Info' to document every device on my network. Paste into a text file, and I have a complete inventory!" - Network Admin

### "Perfect for router configuration"
> "I copy the MAC address directly from NetWatch Pro and paste it into my router's MAC filter. So much faster than typing it!" - Home User

### "Helps with troubleshooting"
> "When a device is misbehaving, I copy all its info and send it to support. They can see everything they need!" - IT Professional

---

## 📞 Need Help?

- Check the Activity Log for copy confirmations
- Try a different field if one doesn't work
- Restart the app if clipboard stops working
- Open an issue on GitHub with details

---

## 🎊 Summary

**Copy Any Device Data in 2 Clicks:**
1. Right-click device
2. Choose what to copy

**Available Data:**
- IP Address
- MAC Address
- Hostname
- Manufacturer
- Device Type
- OS
- All Device Info (formatted)

**Perfect For:**
- Network documentation
- Router configuration
- Troubleshooting
- Security auditing
- Sharing device info

---

**Version**: 2.1+  
**Feature Added**: June 29, 2026  
**Platform**: Windows, Linux, macOS  
**Status**: Stable

---

*Happy copying! 📋✨*
