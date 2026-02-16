#!/usr/bin/env python3
"""
Pure Python ARP Scanner - No C++ compiler needed!
Scans local network using ARP to find connected devices
"""

import json
import subprocess
import re
import platform
from collections import defaultdict

def get_arp_table():
    """Get ARP table from system"""
    devices = []
    
    try:
        if platform.system() == "Windows":
            # Run arp -a command
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            output = result.stdout
            
            # Parse ARP output
            # Format: IP address        Physical Address    Type
            # Example: 192.168.1.1      00-11-22-33-44-55   dynamic
            
            for line in output.split('\n'):
                # Match IP and MAC pattern
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    arp_type = match.group(3)
                    
                    # Skip multicast and broadcast addresses
                    if mac.startswith('FF:FF:FF') or mac.startswith('01:00:5E'):
                        continue
                    
                    # Get manufacturer from MAC prefix
                    manufacturer = get_manufacturer_from_mac(mac)
                    
                    # Try to get hostname
                    hostname = get_hostname(ip)
                    
                    # Determine device type
                    device_type = guess_device_type(mac, hostname)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'manufacturer': manufacturer,
                        'type': device_type,
                        'os': 'Unknown',
                        'connected': True
                    })
        
        else:
            # Linux/Mac
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
            output = result.stdout
            
            for line in output.split('\n'):
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]{17})', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    
                    if mac.startswith('FF:FF:FF') or mac.startswith('01:00:5E'):
                        continue
                    
                    manufacturer = get_manufacturer_from_mac(mac)
                    hostname = get_hostname(ip)
                    device_type = guess_device_type(mac, hostname)
                    
                    devices.append({
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'manufacturer': manufacturer,
                        'type': device_type,
                        'os': 'Unknown',
                        'connected': True
                    })
    
    except Exception as e:
        print(f"Error scanning ARP table: {e}", file=sys.stderr)
    
    return devices

def get_hostname(ip):
    """Try to resolve hostname from IP"""
    try:
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=2)
        output = result.stdout
        
        # Look for "Name:" line
        for line in output.split('\n'):
            if 'Name:' in line:
                hostname = line.split('Name:')[1].strip()
                return hostname
    except:
        pass
    
    # Try ping -a on Windows
    if platform.system() == "Windows":
        try:
            result = subprocess.run(['ping', '-a', '-n', '1', ip], 
                                  capture_output=True, text=True, timeout=2)
            output = result.stdout
            
            # Look for hostname in first line
            match = re.search(r'Pinging\s+([^\s]+)\s+', output)
            if match:
                hostname = match.group(1)
                if hostname != ip:
                    return hostname
        except:
            pass
    
    return f"Device-{ip.split('.')[-1]}"

def get_manufacturer_from_mac(mac):
    """Get manufacturer from MAC address prefix"""
    # Simple MAC vendor database (top manufacturers)
    mac_vendors = {
        '00:1A:8C': 'TP-Link',
        '00:13:10': 'Linksys',
        '00:18:E7': 'Netgear',
        '00:1D:7E': 'D-Link',
        '00:1E:58': 'Asus',
        '00:0C:43': 'Ralink/MediaTek',
        '00:E0:4C': 'Realtek',
        '00:50:F2': 'Microsoft',
        '00:26:B0': 'Apple',
        '3C:37:86': 'Apple',
        '00:17:F2': 'Apple',
        'AC:DE:48': 'Apple',
        '00:25:00': 'Apple',
        '28:6A:BA': 'Apple',
        '00:1C:B3': 'Apple',
        '68:A8:6D': 'Apple',
        'F0:18:98': 'Apple',
        '00:03:93': 'Apple',
        '00:50:56': 'VMware',
        '08:00:27': 'VirtualBox',
        '00:15:5D': 'Hyper-V',
        '52:54:00': 'QEMU',
        '00:16:3E': 'Xen',
        '00:1B:21': 'Intel',
        '00:15:17': 'Intel',
        '00:21:6A': 'Intel',
        '00:23:15': 'Belkin',
        '94:10:3E': 'Belkin',
        '00:1C:DF': 'Belkin',
        '00:0C:41': 'Cisco',
        '00:40:96': 'Cisco',
        '00:03:E3': 'Cisco',
        '48:F8:B3': 'Xiaomi',
        '34:CE:00': 'Xiaomi',
        '64:09:80': 'Xiaomi',
        '74:51:BA': 'Xiaomi',
        'F8:8F:CA': 'Xiaomi',
        '28:6C:07': 'Xiaomi',
        '00:23:6C': 'Samsung',
        '00:12:47': 'Samsung',
        'E8:50:8B': 'Samsung',
        '34:23:BA': 'Samsung',
        '00:18:AF': 'Samsung',
        'B4:F0:AB': 'Samsung',
        '00:16:DB': 'Huawei',
        '00:E0:FC': 'Huawei',
        '00:25:9E': 'Huawei',
        'AC:E2:D3': 'Huawei',
        '28:6E:D4': 'Huawei',
        '00:15:B9': 'LG',
        '00:1C:62': 'LG',
        '00:1E:75': 'LG',
        'B0:C5:54': 'LG',
        '00:24:1D': 'Sony',
        '00:13:A9': 'Sony',
        '00:1A:80': 'Sony',
        '00:1D:BA': 'Sony',
    }
    
    # Get first 8 characters (OUI)
    mac_prefix = mac[:8]
    
    return mac_vendors.get(mac_prefix, 'Unknown')

def guess_device_type(mac, hostname):
    """Guess device type from MAC and hostname"""
    hostname_lower = hostname.lower()
    manufacturer = get_manufacturer_from_mac(mac)
    
    # Router detection
    if any(x in hostname_lower for x in ['router', 'gateway', 'tplink', 'dlink', 'netgear', 'linksys']):
        return 'Router'
    
    # Phone detection
    if any(x in hostname_lower for x in ['iphone', 'android', 'phone', 'mobile']):
        return 'Phone'
    
    if manufacturer in ['Apple', 'Samsung', 'Huawei', 'Xiaomi', 'LG', 'Sony']:
        return 'Phone/Tablet'
    
    # Computer detection
    if any(x in hostname_lower for x in ['desktop', 'laptop', 'pc', 'workstation']):
        return 'Computer'
    
    # TV detection
    if any(x in hostname_lower for x in ['tv', 'television', 'smart-tv', 'roku', 'chromecast']):
        return 'Smart TV'
    
    # IoT detection
    if any(x in hostname_lower for x in ['iot', 'sensor', 'cam', 'alexa', 'echo']):
        return 'IoT Device'
    
    # Default
    return 'Unknown Device'

if __name__ == "__main__":
    # Scan network
    devices = get_arp_table()
    
    # Output as JSON
    print(json.dumps(devices, indent=2))
