#!/usr/bin/env python3
"""
Advanced Device Discovery using mDNS and SSDP/UPnP
Discovers real names for iPhones, Android devices, Smart TVs, etc.
"""

import socket
import struct
import time
import json
from typing import Dict, List
import threading

# mDNS Discovery
class MDNSDiscovery:
    """Discover devices using mDNS/Bonjour protocol"""
    
    def __init__(self):
        self.devices = {}
        self.mcast_group = '224.0.0.251'
        self.mcast_port = 5353
        
    def discover(self, timeout=3):
        """Send mDNS queries and collect responses"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Bind to mDNS port
        try:
            sock.bind(('', self.mcast_port))
        except:
            print("Warning: Could not bind to mDNS port 5353")
            return {}
        
        # Join multicast group
        mreq = struct.pack('4sl', socket.inet_aton(self.mcast_group), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        
        # Set timeout
        sock.settimeout(timeout)
        
        # Send mDNS queries for common services
        queries = [
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # Header
            b'\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',  # PTR query
        ]
        
        for query in queries:
            try:
                sock.sendto(query, (self.mcast_group, self.mcast_port))
            except:
                pass
        
        # Collect responses
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                self._parse_mdns_response(data, addr[0])
            except socket.timeout:
                break
            except Exception as e:
                pass
        
        sock.close()
        return self.devices
    
    def _parse_mdns_response(self, data, ip):
        """Parse mDNS response packet"""
        try:
            # Simple parsing - look for readable device names
            text = data.decode('utf-8', errors='ignore')
            
            # Look for device name patterns
            for line in text.split('\x00'):
                if len(line) > 3 and len(line) < 50:
                    # Check if it looks like a device name
                    if any(keyword in line.lower() for keyword in 
                          ['iphone', 'ipad', 'android', 'samsung', 'galaxy', 
                           'pixel', 'macbook', 'huawei', 'xiaomi']):
                        if ip not in self.devices:
                            self.devices[ip] = line.strip()
                            print(f"[mDNS] Found: {ip} -> {line.strip()}")
        except:
            pass


# SSDP/UPnP Discovery
class SSDPDiscovery:
    """Discover devices using SSDP/UPnP protocol"""
    
    def __init__(self):
        self.devices = {}
        
    def discover(self, timeout=3):
        """Send SSDP M-SEARCH and collect responses"""
        # SSDP M-SEARCH message
        ssdp_request = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 3\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        )
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        
        # Send to SSDP multicast address
        try:
            sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))
        except Exception as e:
            print(f"SSDP send error: {e}")
            return {}
        
        # Collect responses
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(4096)
                self._parse_ssdp_response(data.decode('utf-8', errors='ignore'), addr[0])
            except socket.timeout:
                break
            except Exception as e:
                pass
        
        sock.close()
        return self.devices
    
    def _parse_ssdp_response(self, response, ip):
        """Parse SSDP response"""
        try:
            # Look for SERVER or friendly name
            for line in response.split('\r\n'):
                if line.startswith('SERVER:') or line.startswith('Server:'):
                    device_info = line.split(':', 1)[1].strip()
                    if ip not in self.devices:
                        self.devices[ip] = device_info
                        print(f"[SSDP] Found: {ip} -> {device_info}")
                    break
        except:
            pass


# Combined Discovery
def discover_all_devices(timeout=5):
    """Run all discovery methods in parallel"""
    
    print("Starting advanced device discovery...")
    print("Using: mDNS (Bonjour) + SSDP (UPnP)")
    print()
    
    results = {}
    threads = []
    
    # mDNS Discovery
    mdns = MDNSDiscovery()
    mdns_thread = threading.Thread(target=lambda: results.update({'mdns': mdns.discover(timeout)}))
    mdns_thread.start()
    threads.append(mdns_thread)
    
    # SSDP Discovery
    ssdp = SSDPDiscovery()
    ssdp_thread = threading.Thread(target=lambda: results.update({'ssdp': ssdp.discover(timeout)}))
    ssdp_thread.start()
    threads.append(ssdp_thread)
    
    # Wait for all discoveries to complete
    for thread in threads:
        thread.join()
    
    # Merge results
    all_devices = {}
    for method, devices in results.items():
        for ip, name in devices.items():
            if ip not in all_devices or len(name) > len(all_devices.get(ip, '')):
                all_devices[ip] = name
    
    return all_devices


if __name__ == "__main__":
    print("=" * 70)
    print("Advanced Device Discovery - mDNS + SSDP/UPnP")
    print("=" * 70)
    print()
    
    discovered = discover_all_devices(timeout=5)
    
    print()
    print("=" * 70)
    print(f"Discovery Complete - Found {len(discovered)} device(s)")
    print("=" * 70)
    
    if discovered:
        print("\nDiscovered Devices:")
        for ip, name in sorted(discovered.items()):
            print(f"  {ip:15s} -> {name}")
    else:
        print("\nNo devices responded to mDNS/SSDP queries.")
        print("Note: Some devices don't advertise themselves via these protocols.")
    
    # Output JSON for integration
    print("\n" + "=" * 70)
    print("JSON Output:")
    print("=" * 70)
    print(json.dumps(discovered, indent=2))
