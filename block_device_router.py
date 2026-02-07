#!/usr/bin/env python3
"""
Router Device Blocker - China Telecom TG2212
This script blocks devices on the router using the MAC filter API
"""

import requests
import sys
import json
from requests.auth import HTTPBasicAuth

def block_device_on_router(mac_address):
    """Block a device on the router using MAC filtering"""
    
    # Router configuration
    router_ip = "192.168.1.1"
    username = "user"
    password = "7dWU!fNf"
    
    # Create a session to handle cookies
    session = requests.Session()
    session.auth = HTTPBasicAuth(username, password)
    
    # API endpoint
    url = f"http://{router_ip}/uajax/firewall_macfilter_json.htm"
    
    # Prepare the JSON payload (exact format from browser dev tools)
    payload = {
        "MacFilterCfg": {
            "fullPath": "InternetGatewayDevice.X_CT_COM_MacFilterCfg.",
            "ExcludeMode": "FORWARD"
        },
        "MacFilterList": [{
            "fullPath": "InternetGatewayDevice.X_CT_COM_MacFilterCfg.X_CT_COM_MacFilterListCfgObj.{i}.",
            "MacAddress": mac_address
        }]
    }
    
    # Headers from browser dev tools
    headers = {
        'Content-Type': 'json',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': '*/*',
        'Accept-Language': 'en-GB,en-US;q=0.9,en;q=0.8',
        'Referer': f'http://{router_ip}/firewall_macfilter.html',
        'Origin': f'http://{router_ip}',
        'Connection': 'keep-alive'
    }
    
    try:
        # Try to block the device
        print(f"[*] Attempting to block device: {mac_address}")
        print(f"[*] Router: {router_ip}")
        
        response = session.post(url, json=payload, headers=headers, timeout=10)
        
        print(f"[*] Response Status: {response.status_code}")
        print(f"[*] Response Headers: {dict(response.headers)}")
        print(f"[*] Response Body: {response.text}")
        
        if response.status_code == 200 and response.text:
            print(f"[✓] Device blocked successfully!")
            return True
        else:
            print(f"[✗] Router returned empty response or error")
            print(f"[!] Try logging into router first to establish session")
            return False
            
    except requests.exceptions.Timeout:
        print(f"[✗] Timeout connecting to router")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"[✗] Connection error: {e}")
        return False
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False

def login_to_router():
    """Attempt to login to router and establish session"""
    router_ip = "192.168.1.1"
    username = "user"
    password = "7dWU!fNf"
    
    session = requests.Session()
    
    # Try to access the main page to get cookies
    try:
        print(f"[*] Logging into router...")
        response = session.get(f"http://{router_ip}", auth=HTTPBasicAuth(username, password), timeout=5)
        print(f"[*] Login response: {response.status_code}")
        print(f"[*] Cookies: {session.cookies.get_dict()}")
        return session
    except Exception as e:
        print(f"[✗] Login failed: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python block_device_router.py <MAC_ADDRESS>")
        print("Example: python block_device_router.py A6:57:18:57:C1:53")
        sys.exit(1)
    
    mac_address = sys.argv[1].lower()
    
    print("="*60)
    print("Router Device Blocker - China Telecom TG2212")
    print("="*60)
    
    # Try with session
    session = login_to_router()
    
    # Try to block
    success = block_device_on_router(mac_address)
    
    sys.exit(0 if success else 1)
