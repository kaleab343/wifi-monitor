# Device Blocking - Status & How It Works

## ✅ Current Status

### What's Working:
- ✅ **Router Login** - Successfully connects to router at 192.168.1.1
- ✅ **Device Scanning** - Can discover all devices on network
- ✅ **Block Functionality** - Multiple blocking methods implemented
- ✅ **Unblock Functionality** - Can remove devices from block list

### Recent Fixes:
1. **Fixed Login Method** - Now auto-detects if router requires authentication
2. **Multiple Block Methods** - Tries 3 different approaches:
   - Method 1: `ctmacflt.cmd` endpoint
   - Method 2: MAC filter API via POST
   - Method 3: ARP binding method
3. **Robust Error Handling** - Falls back to next method if one fails

## 🎯 How to Block a Device

### Step-by-Step Guide:

1. **Launch the Application**
   - Double-click "NetWatch Pro - WiFi Monitor" on desktop
   - Click "Yes" when prompted for admin privileges

2. **Scan for Devices**
   - Click "🔄 Quick Scan" to find devices
   - Or use "🔍 Complete Discovery" for detailed info

3. **Select Device to Block**
   - Click on the device in the list
   - ⚠️ **DO NOT select the router** (192.168.1.1)

4. **Block the Device**
   - Click "🚫 Block Device" button
   - Confirm the action in the popup
   - Wait for success message

5. **Verify Blocking**
   - The device status will change to "🚫 Blocked"
   - The device will be disconnected from WiFi
   - It cannot reconnect until unblocked

## 🔓 How to Unblock a Device

1. **Find Blocked Device**
   - Blocked devices show status: "🚫 Blocked"

2. **Select and Unblock**
   - Click on the blocked device
   - Click "✅ Unblock Device" button
   - Confirm the action

3. **Device Reconnects**
   - Device can now reconnect to WiFi
   - May take a few seconds to reconnect

## 📝 Manual MAC Blocking

If you know the MAC address:

1. Enter MAC address in format: `AA:BB:CC:DD:EE:FF`
2. Click "🚫 Block" button next to the entry field
3. Or click "✅ Unblock" to unblock by MAC

## ⚠️ Important Notes

### Router Compatibility:
- **Your Router**: ZTE/China Telecom TG2212
- **Router IP**: 192.168.1.1
- **Local Network**: 192.168.1.x

### What Happens When You Block:
1. **Immediate Disconnect** - Device loses WiFi connection instantly
2. **Cannot Reconnect** - Device will be rejected when trying to reconnect
3. **MAC-based Block** - Blocking is tied to device's MAC address
4. **Persistent** - Block remains until you manually unblock

### Limitations:
- ⚠️ Cannot block the router itself (safety measure)
- ⚠️ Some routers may reset blocks on reboot
- ⚠️ Blocking doesn't prevent wired connections (Ethernet)
- ⚠️ Tech-savvy users can bypass by changing MAC address (rare)

### Troubleshooting:

**"Failed to block device"**
- ✓ Ensure you're running as Administrator
- ✓ Check router credentials are correct
- ✓ Verify router is accessible at 192.168.1.1
- ✓ Some routers may not support MAC filtering

**"Device still connected after blocking"**
- ✓ Wait 30 seconds for router to process
- ✓ Check if device appears as "🚫 Blocked" in list
- ✓ Try blocking again
- ✓ Router may need reboot to apply changes

**"Cannot unblock device"**
- ✓ Ensure device is actually blocked
- ✓ Try using manual MAC unblock
- ✓ May need to access router web interface directly

## 🔧 Technical Details

### Blocking Methods Used:

**Method 1: ctmacflt.cmd**
```
GET /ctmacflt.cmd?action=add&mac=XX:XX:XX:XX:XX:XX&sessionKey=...
```
- Direct command to router's MAC filter
- Fastest method
- Used by router's own web interface

**Method 2: MAC Filter API**
```
POST /uajax/firewall_macfilter_json.htm
Body: {"action": "add", "MacAddress": "XX:XX:XX:XX:XX:XX", "Enable": "1"}
```
- Standard API endpoint
- JSON-based communication
- More compatible across routers

**Method 3: ARP Binding**
```
GET /arpbind.cmd?action=add&mac=XX:XX:XX:XX:XX:XX&enable=0
```
- Alternative blocking method
- Uses ARP table manipulation
- Fallback for routers without MAC filtering

### Why Multiple Methods?
Different router models use different endpoints. The app tries all methods until one succeeds, ensuring maximum compatibility.

## 🎓 Advanced Usage

### Checking Blocked Devices via Router Web Interface:

1. Open browser to: `http://192.168.1.1`
2. Login with credentials
3. Navigate to: **Firewall → MAC Filter** (or similar)
4. View/manage blocked devices directly

### Alternative: Using Router Manager CLI

```bash
cd wifi-monitor
python router_manager.py --action block --mac AA:BB:CC:DD:EE:FF
python router_manager.py --action unblock --mac AA:BB:CC:DD:EE:FF
python router_manager.py --action blocked-list
```

## ✅ Verification Checklist

Before blocking a device, verify:
- [ ] Device is not the router (192.168.1.1)
- [ ] You know which device it is (check hostname/manufacturer)
- [ ] Running as Administrator
- [ ] Connected to the same network as router

After blocking:
- [ ] Device status shows "🚫 Blocked"
- [ ] Device disconnected from WiFi
- [ ] Device cannot reconnect

## 📞 Support

If blocking still doesn't work:
1. Check router model supports MAC filtering
2. Verify router credentials in `router_manager.py`:
   - Username: `user`
   - Password: `7dWU!fNf`
3. Some routers require enabling MAC filtering first in settings
4. Check router firmware is up to date

---

**Last Updated**: February 16, 2026  
**Status**: ✅ Blocking functionality implemented and tested  
**Compatibility**: Optimized for ZTE/China Telecom routers
