#!/usr/bin/env python3
"""
Complete Device Discovery System
Combines: NetBIOS + mDNS + SSDP + Enhanced MAC Database + ARP
"""

import subprocess
import json
import sys
from mdns_ssdp_discovery import discover_all_devices

# Enhanced MAC vendor database with specific models
ENHANCED_MAC_DATABASE = {
    # Huawei - Your device!
    'E0:51:D8': {'manufacturer': 'Huawei', 'model': 'Huawei Phone', 'os': 'Android'},
    '00:E0:FC': {'manufacturer': 'Huawei', 'model': 'Huawei Phone', 'os': 'Android'},
    '0C:37:DC': {'manufacturer': 'Huawei', 'model': 'Huawei Mate/P Series', 'os': 'Android'},
    
    # Samsung
    'E8:50:8B': {'manufacturer': 'Samsung', 'model': 'Samsung Smart TV', 'os': 'Tizen'},
    '28:F0:76': {'manufacturer': 'Samsung', 'model': 'Samsung Galaxy', 'os': 'Android'},
    '2C:6E:85': {'manufacturer': 'Samsung', 'model': 'Samsung Galaxy S', 'os': 'Android'},
    '34:02:86': {'manufacturer': 'Samsung', 'model': 'Samsung Galaxy', 'os': 'Android'},
    
    # Apple
    'F0:18:98': {'manufacturer': 'Apple', 'model': 'iPhone', 'os': 'iOS'},
    '3C:22:FB': {'manufacturer': 'Apple', 'model': 'iPhone 12/13', 'os': 'iOS'},
    'AC:DE:48': {'manufacturer': 'Apple', 'model': 'iPhone 11/12', 'os': 'iOS'},
    'A4:83:E7': {'manufacturer': 'Apple', 'model': 'iPhone/iPad', 'os': 'iOS'},
    '00:C6:10': {'manufacturer': 'Apple', 'model': 'iPad', 'os': 'iPadOS'},
    'AC:BC:32': {'manufacturer': 'Apple', 'model': 'MacBook', 'os': 'macOS'},
    
    # Xiaomi
    '34:CE:00': {'manufacturer': 'Xiaomi', 'model': 'Xiaomi Redmi', 'os': 'Android'},
    '50:8F:4C': {'manufacturer': 'Xiaomi', 'model': 'Xiaomi Phone', 'os': 'Android'},
    '64:09:80': {'manufacturer': 'Xiaomi', 'model': 'Xiaomi Mi/Redmi', 'os': 'Android'},
    
    # Intel (Laptops)
    '3C:6A:A7': {'manufacturer': 'Intel', 'model': 'Laptop WiFi Adapter', 'os': 'Windows/Linux'},
    
    # China Telecom Router
    '00:4C:E5': {'manufacturer': 'China Telecom', 'model': 'TG2212 Router', 'os': 'Router OS'},
}

def load_known_devices():
    """Load manually identified devices from JSON file"""
    try:
        with open('known_devices.json', 'r') as f:
            data = json.load(f)
            return data.get('devices', {})
    except:
        return {}

def is_randomized_mac(mac):
    """Check if MAC address is locally administered (randomized)"""
    first_octet = int(mac.split(':')[0], 16)
    return (first_octet & 0x02) != 0  # Bit 1 set = locally administered

def get_enhanced_device_info(mac):
    """Get detailed device info from MAC address"""
    
    # First check manual database
    known_devices = load_known_devices()
    if mac.upper() in known_devices:
        device = known_devices[mac.upper()]
        return {
            'manufacturer': device.get('type', 'Manual Entry'),
            'model': device.get('name', 'Known Device'),
            'os': device.get('os', 'Unknown'),
            'is_manual': True
        }
    
    # Check if randomized MAC
    if is_randomized_mac(mac):
        return {
            'manufacturer': 'Privacy-Enabled Device',
            'model': 'Randomized MAC (iPhone/Android Privacy)',
            'os': 'iOS/Android',
            'is_randomized': True
        }
    
    # Check enhanced database
    mac_prefix = mac[:8].upper()
    if mac_prefix in ENHANCED_MAC_DATABASE:
        info = ENHANCED_MAC_DATABASE[mac_prefix]
        info['is_manual'] = False
        info['is_randomized'] = False
        return info
    
    # Fallback to basic manufacturer detection
    return {
        'manufacturer': 'Unknown',
        'model': 'Network Device',
        'os': 'Unknown',
        'is_manual': False,
        'is_randomized': False
    }


def merge_discovery_results(cpp_results, mdns_ssdp_results):
    """
    Merge C++ scanner results with Python mDNS/SSDP discoveries
    Priority: mDNS/SSDP name > NetBIOS name > Enhanced MAC > Generic
    """
    
    enhanced_devices = []
    
    for device in cpp_results:
        ip = device['ip']
        mac = device['mac']
        
        # Get enhanced MAC info
        mac_info = get_enhanced_device_info(mac)
        
        # Determine best device name
        best_name = device.get('hostname', '')
        name_source = 'DNS/NetBIOS'
        
        # Check if mDNS/SSDP found a better name
        if ip in mdns_ssdp_results:
            mdns_name = mdns_ssdp_results[ip]
            if mdns_name and len(mdns_name) > 3:
                best_name = mdns_name
                name_source = 'mDNS/SSDP'
        
        # If still no name, use MAC-based model name
        if not best_name or best_name == 'Unknown':
            best_name = mac_info['model']
            name_source = 'MAC Database'
        
        # Add flags for special cases
        is_randomized = mac_info.get('is_randomized', False)
        is_manual = mac_info.get('is_manual', False)
        
        # Build enhanced device info
        enhanced = {
            'ip': ip,
            'mac': mac,
            'hostname': best_name,
            'name_source': name_source + (' [Manual]' if is_manual else ' [Randomized MAC]' if is_randomized else ''),
            'manufacturer': mac_info['manufacturer'] if mac_info['manufacturer'] != 'Unknown' 
                          else device.get('manufacturer', 'Unknown'),
            'device_type': mac_info['model'] if mac_info['model'] != 'Network Device'
                          else device.get('device_type', 'Unknown'),
            'os': mac_info['os'] if mac_info['os'] != 'Unknown'
                 else device.get('os', 'Unknown'),
            'username': device.get('username', ''),
            'is_router': device.get('is_router', False),
            'is_randomized_mac': is_randomized,
            'is_manual_entry': is_manual
        }
        
        enhanced_devices.append(enhanced)
    
    return enhanced_devices


def main():
    print("=" * 70)
    print("Complete Device Discovery System")
    print("=" * 70)
    print()
    
    # Step 1: Run C++ scanner (NetBIOS + ARP)
    print("Step 1: Running C++ scanner (NetBIOS + ARP)...")
    try:
        result = subprocess.run(['device_scanner.exe'], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            cpp_devices = json.loads(result.stdout)
            print(f"  ✓ Found {len(cpp_devices)} devices via ARP/NetBIOS")
        else:
            print(f"  ✗ Scanner failed")
            cpp_devices = []
    except Exception as e:
        print(f"  ✗ Error: {e}")
        cpp_devices = []
    
    # Step 2: Run mDNS/SSDP discovery (reduced timeout for speed)
    print("\nStep 2: Running mDNS/SSDP discovery...")
    mdns_ssdp_devices = discover_all_devices(timeout=2)  # Reduced from 5 to 2 seconds
    print(f"  ✓ Found {len(mdns_ssdp_devices)} devices via mDNS/SSDP")
    
    # Step 3: Merge and enhance results
    print("\nStep 3: Merging and enhancing results...")
    final_devices = merge_discovery_results(cpp_devices, mdns_ssdp_devices)
    
    # Step 4: Output results
    print("\n" + "=" * 70)
    print(f"Final Results - {len(final_devices)} devices discovered")
    print("=" * 70)
    
    for i, device in enumerate(final_devices, 1):
        print(f"\n{i}. {device['hostname']}")
        print(f"   IP: {device['ip']}")
        print(f"   MAC: {device['mac']}")
        print(f"   Manufacturer: {device['manufacturer']}")
        print(f"   Type: {device['device_type']}")
        print(f"   OS: {device['os']}")
        if device['username']:
            print(f"   Username: {device['username']}")
        print(f"   Name Source: {device['name_source']}")
    
    # Output JSON for GUI
    print("\n" + "=" * 70)
    print("JSON Output (for GUI integration):")
    print("=" * 70)
    print(json.dumps(final_devices, indent=2))


if __name__ == "__main__":
    main()
