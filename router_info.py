"""
Router information module - system info, DHCP, etc.
"""

from typing import Dict, List, Tuple
from config import ENDPOINTS


class RouterInfo:
    """Manages router system information and settings"""
    
    def __init__(self, router_auth, network_client):
        self.auth = router_auth
        self.client = network_client
        self.base_url = router_auth.base_url
    
    def get_router_info(self) -> Tuple[bool, Dict]:
        """Get router system information"""
        success, result = self.client.raw_get_request(ENDPOINTS['router_info'])
        
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
    
    def get_firewall_status(self) -> Tuple[bool, Dict]:
        """Get firewall status and settings"""
        success, result = self.client.raw_get_request(ENDPOINTS['firewall'])
        
        if success and isinstance(result, dict):
            firewall_info = {
                'enabled': result.get('Enable', False),
                'level': result.get('Level', 'Medium'),
                'dos_protection': result.get('DoSProtection', False),
                'syn_flood_protection': result.get('SynFloodProtection', False)
            }
            return True, firewall_info
        return False, {}
    
    def get_dhcp_settings(self) -> Tuple[bool, Dict]:
        """Get DHCP server settings"""
        success, result = self.client.raw_get_request(ENDPOINTS['dhcp_server'])
        
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
        success, result = self.client.raw_get_request(ENDPOINTS['dhcp_clients'])
        
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
    
    def reboot_router(self) -> Tuple[bool, str]:
        """Reboot the router"""
        payload = {"Reboot": "1"}
        
        headers = {
            'Referer': f'{self.base_url}/system_reboot.html',
            'Origin': self.base_url
        }
        
        success, result = self.client.raw_post_request(
            "/uajax/system_reboot_json.htm",
            data=payload,
            extra_headers=headers
        )
        
        if success:
            return True, "Router is rebooting... (will take 1-2 minutes)"
        return False, f"Failed to reboot: {result}"
