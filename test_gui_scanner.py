#!/usr/bin/env python3
"""
Test GUI Scanner Integration
Simulates how the GUI calls the scanner
"""

import sys
import os
import subprocess
import json

print("=" * 70)
print("GUI Scanner Integration Test")
print("=" * 70)
print()

# Simulate GUI path resolution
gui_dir = os.path.join(os.path.dirname(__file__), 'src', 'gui')
scanner_path = os.path.join(gui_dir, '..', 'scanners', 'python_arp_scanner.py')

print(f"GUI directory (simulated): {gui_dir}")
print(f"Scanner path: {scanner_path}")
print(f"Scanner exists: {os.path.exists(scanner_path)}")
print(f"Using Python: {sys.executable}")
print()

print("Running scanner as GUI would...")
print("-" * 70)

try:
    result = subprocess.run([sys.executable, scanner_path], 
                          capture_output=True, text=True, timeout=30)
    
    print(f"Return code: {result.returncode}")
    print()
    
    if result.stderr:
        print("STDERR (debug messages):")
        print(result.stderr)
        print()
    
    if result.returncode == 0:
        print("STDOUT (JSON output):")
        print(result.stdout)
        print()
        
        # Try to parse
        try:
            devices = json.loads(result.stdout)
            print(f"✓ Successfully parsed {len(devices)} devices")
            print()
            
            for i, dev in enumerate(devices, 1):
                print(f"{i}. {dev.get('hostname')}")
                print(f"   IP: {dev.get('ip')}")
                print(f"   MAC: {dev.get('mac')}")
                print(f"   Type: {dev.get('type')}")
                print(f"   Manufacturer: {dev.get('manufacturer')}")
                print()
            
            print("=" * 70)
            print("✓ TEST PASSED - Scanner works correctly from GUI context")
            print("=" * 70)
            
        except json.JSONDecodeError as e:
            print(f"✗ JSON parse error: {e}")
            print(f"Output preview: {result.stdout[:200]}")
    else:
        print(f"✗ Scanner failed with code {result.returncode}")
        print(f"Error: {result.stderr}")
        
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
