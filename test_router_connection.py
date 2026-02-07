#!/usr/bin/env python3
"""
Quick test to verify router connection and API access
"""

from router_manager import RouterManager
import sys

def test_connection():
    print("=" * 70)
    print("  Router Connection Test")
    print("=" * 70)
    print()
    
    # Create router manager
    print("Creating router manager instance...")
    router = RouterManager()
    
    print(f"Router IP: {router.router_ip}")
    print(f"Username: {router.username}")
    print()
    
    # Test 1: Get router info
    print("[Test 1] Getting router information...")
    success, info = router.get_router_info()
    if success:
        print("✓ SUCCESS - Router info retrieved:")
        print(f"  Model: {info.get('model', 'N/A')}")
        print(f"  Firmware: {info.get('firmware', 'N/A')}")
        print(f"  LAN IP: {info.get('lan_ip', 'N/A')}")
    else:
        print("✗ FAILED - Could not get router info")
        print(f"  Error: {info}")
    print()
    
    # Test 2: Get WiFi settings
    print("[Test 2] Getting WiFi settings...")
    success, wifi = router.get_wifi_settings()
    if success:
        print("✓ SUCCESS - WiFi settings retrieved:")
        print(f"  SSID: {wifi.get('ssid', 'N/A')}")
        print(f"  Channel: {wifi.get('channel', 'N/A')}")
        print(f"  Security: {wifi.get('security_mode', 'N/A')}")
    else:
        print("✗ FAILED - Could not get WiFi settings")
        print(f"  Error: {wifi}")
    print()
    
    # Test 3: Get connected devices
    print("[Test 3] Getting connected devices...")
    success, devices = router.get_connected_devices()
    if success:
        print(f"✓ SUCCESS - Found {len(devices)} device(s):")
        for i, device in enumerate(devices[:5], 1):  # Show first 5
            print(f"  {i}. {device.get('hostname', 'Unknown')} - {device.get('ip', 'N/A')}")
        if len(devices) > 5:
            print(f"  ... and {len(devices) - 5} more")
    else:
        print("✗ FAILED - Could not get devices")
        print(f"  Error: {devices}")
    print()
    
    # Test 4: Get blocked devices list
    print("[Test 4] Getting blocked devices list...")
    success, blocked = router.get_mac_filter_list()
    if success:
        print(f"✓ SUCCESS - Found {len(blocked)} blocked device(s)")
        for i, device in enumerate(blocked, 1):
            print(f"  {i}. MAC: {device.get('mac', 'N/A')}")
    else:
        print("✗ FAILED - Could not get blocked list")
        print(f"  Error: {blocked}")
    print()
    
    print("=" * 70)
    print("Test Complete!")
    print("=" * 70)
    print()
    print("If all tests passed, you have full router access!")
    print("If any failed, check:")
    print("  1. Router IP address is correct (currently: {})".format(router.router_ip))
    print("  2. Username and password are correct")
    print("  3. You are connected to the router's network")
    print("  4. Router web interface is accessible in browser")
    print()

if __name__ == "__main__":
    try:
        test_connection()
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
