#!/usr/bin/env python3
"""
Complete Router Management System - China Telecom TG2212
Full access to router features via API
"""

import requests
import json
import sys
from requests.auth import HTTPBasicAuth
from typing import List, Dict, Optional, Tuple
import time

class RouterManager:
    """Comprehensive router management class"""
    
    def __init__(self, router_ip="192.168.1.1", username="user", password="7dWU!fNf"):
        self.router_ip = router_ip
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.base_url = f"http://{router_ip}"
        self.logged_in = False
        
    def login(self) -> bool:
        """Login to router web interface"""
        import base64
        
        if self.logged_in:
            return True
            
        try:
            # Encode password in base64 as required by router
            password_b64 = base64.b64encode(self.password.encode()).decode()
            
            # POST to login.cgi
            login_url = f"{self.base_url}/login.cgi"
            login_data = {
                'username': self.username,
                'wd': password_b64
            }
            
            response = self.session.post(login_url, data=login_data, timeout=10)
            
            # Check if login successful (returns home page)
            if response.status_code == 200 and len(response.text) > 5000:
                self.logged_in = True
                return True
            
            return False
            
        except Exception as e:
            return False
        
    def _make_request(self, endpoint: str, method: str = "GET", data: dict = None, 
                      headers: dict = None) -> Tuple[bool, any]:
        """Make HTTP request to router using raw sockets (router sends malformed HTTP)"""
        import socket
        import json as json_lib
        
        # Ensure we're logged in
        if not self.logged_in:
            if not self.login():
                return False, "Login failed"
        
        # For POST requests with malformed responses, use raw sockets
        if method == "POST":
            return self._raw_post_request(endpoint, data, headers)
        
        # For GET requests, try normal method first, fall back to raw
        try:
            return self._raw_get_request(endpoint, headers)
        except Exception as e:
            return False, f"Request error: {e}"
    
    def _raw_get_request(self, endpoint: str, extra_headers: dict = None) -> Tuple[bool, any]:
        """Make GET request using raw socket"""
        import socket
        import json as json_lib
        
        # Build headers
        headers = {
            'Host': self.router_ip,
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'close'
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        # Build HTTP request
        request = f"GET {endpoint} HTTP/1.1\r\n"
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        
        # Send via socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            sock.connect((self.router_ip, 80))
            sock.sendall(request.encode())
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            text = response.decode('utf-8', errors='ignore')
            
            # Router sends JSON without HTTP headers, just raw JSON
            json_start = text.find('{')
            if json_start >= 0:
                json_text = text[json_start:]
                try:
                    data = json_lib.loads(json_text)
                    return True, data
                except:
                    return True, json_text
            
            return False, "No JSON in response"
            
        except socket.timeout:
            return False, "Request timeout"
        except Exception as e:
            return False, f"Socket error: {e}"
        finally:
            sock.close()
    
    def _raw_post_request(self, endpoint: str, data: dict, extra_headers: dict = None) -> Tuple[bool, any]:
        """Make POST request using raw socket"""
        import socket
        import json as json_lib
        
        # Build JSON payload
        payload = json_lib.dumps(data)
        
        # Build headers
        headers = {
            'Host': self.router_ip,
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'Content-Type': 'json',
            'Content-Length': str(len(payload)),
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'close'
        }
        
        if extra_headers:
            headers.update(extra_headers)
        
        # Build HTTP request
        request = f"POST {endpoint} HTTP/1.1\r\n"
        for key, value in headers.items():
            request += f"{key}: {value}\r\n"
        request += "\r\n"
        request += payload
        
        # Send via socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        try:
            sock.connect((self.router_ip, 80))
            sock.sendall(request.encode())
            
            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            text = response.decode('utf-8', errors='ignore')
            
            # Look for JSON in response
            json_start = text.find('{')
            if json_start >= 0:
                json_text = text[json_start:]
                try:
                    result = json_lib.loads(json_text)
                    return True, result
                except:
                    return True, json_text
            
            # No JSON, but request succeeded
            return True, text
            
        except socket.timeout:
            return False, "Request timeout"
        except Exception as e:
            return False, f"Socket error: {e}"
        finally:
            sock.close()
    
    # ========== DEVICE MANAGEMENT ==========
    
    def get_connected_devices(self) -> Tuple[bool, List[Dict]]:
        """Get list of all connected devices - NOT USED, use C++ scanner instead"""
        # This method is kept for compatibility but not recommended
        # The C++ device scanner is faster and more reliable
        return False, []
    
    def _get_devices_from_home_page(self) -> Tuple[bool, List[Dict]]:
        """Get connected devices by parsing home.html (works with user account)"""
        import re
        import json as json_lib
        
        try:
            # Get home page
            response = self.session.get(f'{self.base_url}/home.html', timeout=10)
            
            if response.status_code != 200:
                return False, []
            
            html = response.text
            
            # Extract the datas JavaScript object
            # Look for AssocDe (Associated Devices) array
            assoc_match = re.search(r'"AssocDe":\s*\[([^\]]+)\]', html, re.DOTALL)
            
            if not assoc_match:
                return False, []
            
            devices = []
            
            # Parse each device entry
            device_entries = re.findall(r'\{[^}]+\}', assoc_match.group(1))
            
            for entry in device_entries:
                # Extract MAC address
                mac_match = re.search(r'"AssociatedDeviceMACAddress":"([^"]+)"', entry)
                
                if mac_match:
                    mac = mac_match.group(1)
                    
                    # Try to resolve hostname via reverse DNS
                    hostname = self._get_device_hostname_from_arp(mac)
                    
                    devices.append({
                        'hostname': hostname or 'Unknown',
                        'ip': self._get_device_ip_from_arp(mac) or 'Unknown',
                        'mac': mac,
                        'interface': 'WiFi',
                        'active': True
                    })
            
            return True, devices
            
        except Exception as e:
            return False, []
    
    def _get_device_hostname_from_arp(self, mac: str) -> str:
        """Try to get hostname from ARP table or reverse DNS"""
        import socket
        
        # Try to get IP from ARP first
        ip = self._get_device_ip_from_arp(mac)
        
        if ip and ip != 'Unknown':
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return hostname
            except:
                pass
        
        return ""
    
    def _get_device_ip_from_arp(self, mac: str) -> str:
        """Get IP address from ARP table for a given MAC"""
        import subprocess
        
        try:
            # Run arp command
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Normalize MAC for comparison
                mac_normalized = mac.upper().replace('-', ':')
                
                # Search for MAC in ARP output
                for line in result.stdout.split('\n'):
                    if mac_normalized.replace(':', '-') in line.upper():
                        # Extract IP address
                        import re
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            return ip_match.group(1)
        except:
            pass
        
        return ""
    
    def get_mac_filter_list(self) -> Tuple[bool, List[Dict]]:
        """Get current MAC filter list (blocked devices)"""
        success, result = self._make_request("/uajax/firewall_macfilter_json.htm")
        
        if success and isinstance(result, dict):
            blocked_devices = []
            if 'MacFilterList' in result:
                for entry in result['MacFilterList']:
                    if entry.get('MacAddress'):
                        blocked_devices.append({
                            'mac': entry['MacAddress'],
                            'path': entry.get('fullPath', '')
                        })
            return True, blocked_devices
        return False, []
    
    def block_device(self, mac_address: str) -> Tuple[bool, str]:
        """Block a device by MAC address using ctmacflt.cmd endpoint"""
        # Normalize MAC address format
        mac_normalized = mac_address.upper().strip()
        
        # Ensure MAC has colons
        if '-' in mac_normalized:
            mac_normalized = mac_normalized.replace('-', ':')
        elif len(mac_normalized) == 12 and ':' not in mac_normalized:
            mac_normalized = ':'.join([mac_normalized[i:i+2] for i in range(0, 12, 2)])
        
        try:
            # First, load the firewall page to get sessionKey
            response = self.session.get(f'{self.base_url}/firewall_macfilter.html', timeout=10)
            
            # Extract sessionKey from page
            import re
            match = re.search(r'sessionKey\s*=\s*["\']([^"\']+)["\']', response.text)
            session_key = match.group(1) if match else ''
            
            # Use ctmacflt.cmd endpoint (the REAL endpoint the router uses!)
            url = f'{self.base_url}/ctmacflt.cmd?action=add&mac={mac_normalized}'
            if session_key:
                url += f'&sessionKey={session_key}'
            
            # Send GET request to block
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                return True, f"Device {mac_normalized} blocked successfully"
            else:
                return False, f"HTTP {response.status_code}: {response.text[:100]}"
                
        except Exception as e:
            return False, f"Error blocking device: {e}"
    
    def unblock_device(self, mac_address: str) -> Tuple[bool, str]:
        """Unblock a device by removing it from MAC filter list"""
        mac_normalized = mac_address.upper().strip()
        if '-' in mac_normalized:
            mac_normalized = mac_normalized.replace('-', ':')
        elif len(mac_normalized) == 12 and ':' not in mac_normalized:
            mac_normalized = ':'.join([mac_normalized[i:i+2] for i in range(0, 12, 2)])
        
        # First, get the current blocked list to find the device's path
        success, blocked_devices = self.get_mac_filter_list()
        if not success:
            return False, "Failed to get current MAC filter list"
        
        # Find the device's fullPath
        device_path = None
        for device in blocked_devices:
            if device['mac'].upper() == mac_normalized:
                device_path = device['path']
                break
        
        if not device_path:
            return False, f"Device {mac_normalized} is not in the blocked list"
        
        # Use the actual delete format: a=del&x=<fullPath>
        # This is form-encoded, not JSON!
        payload_str = f"a=del&x={device_path}"
        
        headers = {
            'Referer': f'{self.base_url}/firewall_macfilter.html',
            'Origin': self.base_url,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            # Send POST with form data (not JSON)
            response = self.session.post(
                f'{self.base_url}/uajax/firewall_macfilter_json.htm',
                data=payload_str,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                return True, f"Device {mac_normalized} unblocked successfully"
            else:
                return False, f"HTTP {response.status_code}: {response.text[:100]}"
                
        except Exception as e:
            # Router sends malformed HTTP response, but the operation usually succeeds
            # Verify by checking if device is still in blocked list
            import time
            time.sleep(0.5)  # Give router time to process
            success, blocked_check = self.get_mac_filter_list()
            if success:
                still_blocked = any(d['mac'].upper() == mac_normalized for d in blocked_check)
                if not still_blocked:
                    return True, f"Device {mac_normalized} unblocked successfully"
            
            return False, f"Error unblocking device: {e}"
    
    # ========== WIFI MANAGEMENT ==========
    
    def get_wifi_settings(self) -> Tuple[bool, Dict]:
        """Get WiFi settings (SSID, password, security mode, etc.)"""
        success, result = self._make_request("/uajax/wlan_basic_json.htm")
        
        if success and isinstance(result, dict):
            wifi_info = {
                'ssid': result.get('SSID', ''),
                'ssid_hidden': result.get('SSIDAdvertisementEnabled', False),
                'channel': result.get('Channel', 'Auto'),
                'mode': result.get('Standard', ''),
                'security_mode': result.get('BeaconType', ''),
                'encryption': result.get('WPAEncryptionModes', ''),
                'enabled': result.get('Enable', False)
            }
            return True, wifi_info
        return False, {}
    
    def get_wifi_password(self) -> Tuple[bool, str]:
        """Get WiFi password"""
        success, result = self._make_request("/uajax/wlan_security_json.htm")
        
        if success and isinstance(result, dict):
            password = result.get('KeyPassphrase', '') or result.get('PreSharedKey', '')
            return True, password
        return False, ""
    
    def set_wifi_password(self, new_password: str) -> Tuple[bool, str]:
        """Change WiFi password"""
        if len(new_password) < 8:
            return False, "Password must be at least 8 characters"
        
        payload = {
            "KeyPassphrase": new_password,
            "PreSharedKey": new_password
        }
        
        headers = {
            'Referer': f'{self.base_url}/wlan_security.html',
            'Origin': self.base_url
        }
        
        success, result = self._make_request(
            "/uajax/wlan_security_json.htm",
            method="POST",
            data=payload,
            headers=headers
        )
        
        if success:
            return True, "WiFi password changed successfully"
        return False, f"Failed to change password: {result}"
    
    def set_wifi_ssid(self, new_ssid: str) -> Tuple[bool, str]:
        """Change WiFi SSID"""
        if not new_ssid or len(new_ssid) > 32:
            return False, "SSID must be between 1 and 32 characters"
        
        payload = {
            "SSID": new_ssid
        }
        
        headers = {
            'Referer': f'{self.base_url}/wlan_basic.html',
            'Origin': self.base_url
        }
        
        success, result = self._make_request(
            "/uajax/wlan_basic_json.htm",
            method="POST",
            data=payload,
            headers=headers
        )
        
        if success:
            return True, "WiFi SSID changed successfully"
        return False, f"Failed to change SSID: {result}"
    
    # ========== ROUTER SETTINGS ==========
    
    def get_router_info(self) -> Tuple[bool, Dict]:
        """Get router system information"""
        success, result = self._make_request("/uajax/status_info_json.htm")
        
        if success and isinstance(result, dict):
            info = {
                'model': result.get('DeviceModel', 'TG2212'),
                'firmware': result.get('SoftwareVersion', ''),
                'hardware': result.get('HardwareVersion', ''),
                'uptime': result.get('UpTime', ''),
                'wan_ip': result.get('WANIPAddress', ''),
                'lan_ip': result.get('LANIPAddress', '192.168.1.1'),
                'mac': result.get('MACAddress', '')
            }
            return True, info
        return False, {}
    
    def change_admin_password(self, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change router admin password"""
        if len(new_password) < 8:
            return False, "Password must be at least 8 characters"
        
        payload = {
            "OldPassword": old_password,
            "NewPassword": new_password,
            "ConfirmPassword": new_password
        }
        
        headers = {
            'Referer': f'{self.base_url}/system_password.html',
            'Origin': self.base_url
        }
        
        success, result = self._make_request(
            "/uajax/system_password_json.htm",
            method="POST",
            data=payload,
            headers=headers
        )
        
        if success:
            # Update credentials
            self.password = new_password
            self.session.auth = HTTPBasicAuth(self.username, new_password)
            return True, "Admin password changed successfully"
        return False, f"Failed to change password: {result}"
    
    def reboot_router(self) -> Tuple[bool, str]:
        """Reboot the router"""
        payload = {"Reboot": "1"}
        
        headers = {
            'Referer': f'{self.base_url}/system_reboot.html',
            'Origin': self.base_url
        }
        
        success, result = self._make_request(
            "/uajax/system_reboot_json.htm",
            method="POST",
            data=payload,
            headers=headers
        )
        
        if success:
            return True, "Router is rebooting... (will take 1-2 minutes)"
        return False, f"Failed to reboot: {result}"
    
    # ========== PARENTAL CONTROLS ==========
    
    def get_parental_controls(self) -> Tuple[bool, List[Dict]]:
        """Get parental control rules"""
        success, result = self._make_request("/uajax/parental_control_json.htm")
        
        if success and isinstance(result, dict):
            rules = []
            if 'ParentalControlList' in result:
                for rule in result['ParentalControlList']:
                    rules.append({
                        'enabled': rule.get('Enable', False),
                        'mac': rule.get('MACAddress', ''),
                        'description': rule.get('Description', ''),
                        'start_time': rule.get('StartTime', ''),
                        'end_time': rule.get('EndTime', ''),
                        'days': rule.get('Days', '')
                    })
            return True, rules
        return False, []
    
    # ========== FIREWALL ==========
    
    def get_firewall_status(self) -> Tuple[bool, Dict]:
        """Get firewall status and settings"""
        success, result = self._make_request("/uajax/firewall_general_json.htm")
        
        if success and isinstance(result, dict):
            firewall_info = {
                'enabled': result.get('Enable', False),
                'level': result.get('Level', 'Medium'),
                'dos_protection': result.get('DoSProtection', False),
                'syn_flood_protection': result.get('SynFloodProtection', False)
            }
            return True, firewall_info
        return False, {}
    
    # ========== PORT FORWARDING ==========
    
    def get_port_forwarding_rules(self) -> Tuple[bool, List[Dict]]:
        """Get port forwarding rules"""
        success, result = self._make_request("/uajax/nat_portforward_json.htm")
        
        if success and isinstance(result, dict):
            rules = []
            if 'PortForwardList' in result:
                for rule in result['PortForwardList']:
                    rules.append({
                        'enabled': rule.get('Enable', False),
                        'name': rule.get('Description', ''),
                        'protocol': rule.get('Protocol', 'TCP'),
                        'external_port': rule.get('ExternalPort', ''),
                        'internal_ip': rule.get('InternalClient', ''),
                        'internal_port': rule.get('InternalPort', '')
                    })
            return True, rules
        return False, []
    
    # ========== DHCP ==========
    
    def get_dhcp_settings(self) -> Tuple[bool, Dict]:
        """Get DHCP server settings"""
        success, result = self._make_request("/uajax/dhcp_server_json.htm")
        
        if success and isinstance(result, dict):
            dhcp_info = {
                'enabled': result.get('DHCPServerEnable', False),
                'start_ip': result.get('MinAddress', ''),
                'end_ip': result.get('MaxAddress', ''),
                'lease_time': result.get('DHCPLeaseTime', ''),
                'gateway': result.get('IPRouters', ''),
                'dns1': result.get('DNSServers', '').split(',')[0] if result.get('DNSServers') else '',
                'dns2': result.get('DNSServers', '').split(',')[1] if result.get('DNSServers') and ',' in result.get('DNSServers') else ''
            }
            return True, dhcp_info
        return False, {}
    
    def get_dhcp_clients(self) -> Tuple[bool, List[Dict]]:
        """Get list of DHCP clients"""
        success, result = self._make_request("/uajax/dhcp_clients_json.htm")
        
        if success and isinstance(result, dict):
            clients = []
            if 'DHCPClients' in result:
                for client in result['DHCPClients']:
                    clients.append({
                        'hostname': client.get('HostName', 'Unknown'),
                        'ip': client.get('IPAddress', ''),
                        'mac': client.get('MACAddress', ''),
                        'lease_time': client.get('LeaseTimeRemaining', '')
                    })
            return True, clients
        return False, []


def print_header(text):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)


def main():
    """Main CLI interface for testing"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Router Management Tool')
    parser.add_argument('--ip', default='192.168.1.1', help='Router IP address')
    parser.add_argument('--user', default='user', help='Username')
    parser.add_argument('--password', default='7dWU!fNf', help='Password')
    parser.add_argument('--action', required=True, 
                       choices=['devices', 'block', 'unblock', 'wifi-info', 
                               'wifi-password', 'change-wifi-password', 'change-ssid',
                               'router-info', 'blocked-list', 'reboot', 'all'],
                       help='Action to perform')
    parser.add_argument('--mac', help='MAC address (for block/unblock)')
    parser.add_argument('--value', help='New value (for password/SSID change)')
    
    args = parser.parse_args()
    
    # Create router manager
    router = RouterManager(args.ip, args.user, args.password)
    
    print_header("Router Management Tool - China Telecom TG2212")
    
    if args.action == 'devices' or args.action == 'all':
        print_header("Connected Devices")
        success, devices = router.get_connected_devices()
        if success:
            for i, device in enumerate(devices, 1):
                print(f"{i}. {device['hostname']}")
                print(f"   IP: {device['ip']} | MAC: {device['mac']}")
                print(f"   Interface: {device['interface']} | Active: {device['active']}")
                print()
        else:
            print("Failed to get devices")
    
    if args.action == 'blocked-list' or args.action == 'all':
        print_header("Blocked Devices (MAC Filter)")
        success, blocked = router.get_mac_filter_list()
        if success:
            if blocked:
                for i, device in enumerate(blocked, 1):
                    print(f"{i}. MAC: {device['mac']}")
            else:
                print("No devices blocked")
        else:
            print("Failed to get blocked list")
    
    if args.action == 'block':
        if not args.mac:
            print("Error: --mac required for block action")
            sys.exit(1)
        print_header(f"Blocking Device: {args.mac}")
        success, msg = router.block_device(args.mac)
        print(msg)
    
    if args.action == 'unblock':
        if not args.mac:
            print("Error: --mac required for unblock action")
            sys.exit(1)
        print_header(f"Unblocking Device: {args.mac}")
        success, msg = router.unblock_device(args.mac)
        print(msg)
    
    if args.action == 'wifi-info' or args.action == 'all':
        print_header("WiFi Settings")
        success, wifi = router.get_wifi_settings()
        if success:
            print(f"SSID: {wifi['ssid']}")
            print(f"Hidden: {wifi['ssid_hidden']}")
            print(f"Channel: {wifi['channel']}")
            print(f"Mode: {wifi['mode']}")
            print(f"Security: {wifi['security_mode']}")
            print(f"Encryption: {wifi['encryption']}")
            print(f"Enabled: {wifi['enabled']}")
        else:
            print("Failed to get WiFi settings")
    
    if args.action == 'wifi-password':
        print_header("WiFi Password")
        success, password = router.get_wifi_password()
        if success:
            print(f"Current Password: {password}")
        else:
            print("Failed to get WiFi password")
    
    if args.action == 'change-wifi-password':
        if not args.value:
            print("Error: --value required for password change")
            sys.exit(1)
        print_header("Changing WiFi Password")
        success, msg = router.set_wifi_password(args.value)
        print(msg)
    
    if args.action == 'change-ssid':
        if not args.value:
            print("Error: --value required for SSID change")
            sys.exit(1)
        print_header("Changing WiFi SSID")
        success, msg = router.set_wifi_ssid(args.value)
        print(msg)
    
    if args.action == 'router-info' or args.action == 'all':
        print_header("Router Information")
        success, info = router.get_router_info()
        if success:
            print(f"Model: {info['model']}")
            print(f"Firmware: {info['firmware']}")
            print(f"Hardware: {info['hardware']}")
            print(f"Uptime: {info['uptime']}")
            print(f"WAN IP: {info['wan_ip']}")
            print(f"LAN IP: {info['lan_ip']}")
            print(f"MAC: {info['mac']}")
        else:
            print("Failed to get router info")
    
    if args.action == 'reboot':
        print_header("Rebooting Router")
        confirm = input("Are you sure you want to reboot the router? (yes/no): ")
        if confirm.lower() == 'yes':
            success, msg = router.reboot_router()
            print(msg)
        else:
            print("Reboot cancelled")
    
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    main()
