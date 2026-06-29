#!/usr/bin/env python3
"""
Test Scanner - Diagnose why devices aren't being found
"""

import sys
import os
import subprocess
import platform

print("=" * 70)
print("Scanner Diagnostic Test")
print("=" * 70)
print()

# Check Python version
print(f"Python: {sys.version}")
print(f"Platform: {platform.system()}")
print(f"Working Directory: {os.getcwd()}")
print()

# Test 1: Check ARP table directly
print("Test 1: Checking ARP table directly...")
print("-" * 70)
try:
    if platform.system() == "Windows":
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        print(result.stdout[:500])  # First 500 chars
        if result.stdout:
            # Count how many IP addresses found
            import re
            ips = re.findall(r'\d+\.\d+\.\d+\.\d+', result.stdout)
            print(f"\n✓ Found {len(ips)} IP addresses in ARP table")
        else:
            print("✗ ARP table is empty or inaccessible")
    else:
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True, timeout=10)
        print(result.stdout[:500])
except Exception as e:
    print(f"✗ Error: {e}")

print()

# Test 2: Test Python ARP scanner
print("Test 2: Testing Python ARP Scanner...")
print("-" * 70)
try:
    scanner_path = os.path.join(os.path.dirname(__file__), 'src', 'scanners', 'python_arp_scanner.py')
    print(f"Scanner path: {scanner_path}")
    print(f"Exists: {os.path.exists(scanner_path)}")
    print()
    
    if os.path.exists(scanner_path):
        print("Running scanner...")
        result = subprocess.run([sys.executable, scanner_path], 
                              capture_output=True, text=True, timeout=15)
        
        print(f"Return code: {result.returncode}")
        print(f"Output length: {len(result.stdout)} chars")
        print()
        
        if result.returncode == 0:
            print("Scanner output:")
            print(result.stdout)
            
            # Try to parse JSON
            import json
            try:
                devices = json.loads(result.stdout)
                print(f"\n✓ Successfully parsed {len(devices)} devices")
                for dev in devices:
                    print(f"  - {dev.get('ip')} | {dev.get('mac')} | {dev.get('hostname')}")
            except json.JSONDecodeError as e:
                print(f"\n✗ JSON parse error: {e}")
        else:
            print(f"✗ Scanner failed with code {result.returncode}")
            print(f"Error output:\n{result.stderr}")
    else:
        print("✗ Scanner file not found!")
        
except Exception as e:
    print(f"✗ Error running scanner: {e}")
    import traceback
    traceback.print_exc()

print()

# Test 3: Check network interface
print("Test 3: Checking Network Interface...")
print("-" * 70)
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    print(f"✓ Your local IP: {local_ip}")
    
    # Get subnet
    subnet = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
    print(f"✓ Subnet: {subnet}")
    
except Exception as e:
    print(f"✗ Could not determine local IP: {e}")

print()

# Test 4: Ping gateway
print("Test 4: Testing Gateway Connection...")
print("-" * 70)
try:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    
    # Assume gateway is .1
    gateway = '.'.join(local_ip.split('.')[:-1]) + '.1'
    print(f"Testing gateway: {gateway}")
    
    if platform.system() == "Windows":
        result = subprocess.run(['ping', '-n', '1', gateway], 
                              capture_output=True, text=True, timeout=5)
    else:
        result = subprocess.run(['ping', '-c', '1', gateway], 
                              capture_output=True, text=True, timeout=5)
    
    if result.returncode == 0:
        print(f"✓ Gateway {gateway} is reachable")
    else:
        print(f"✗ Gateway {gateway} is not reachable")
        
except Exception as e:
    print(f"✗ Gateway test failed: {e}")

print()
print("=" * 70)
print("Diagnostic Complete")
print("=" * 70)
