#!/usr/bin/env python3
"""
Man-in-the-Middle Passive Monitor
Captures all network traffic to discover ALL devices
Requires: pip install scapy (or use raw socket alternative)
"""

import socket
import struct
import time
import json
from collections import defaultdict

class PassiveMITMMonitor:
    """Passive network monitor - captures all traffic"""
    
    def __init__(self):
        self.devices = {}
        
    def parse_ethernet_header(self, data):
        """Parse Ethernet header"""
        dest_mac = ':'.join(f'{b:02X}' for b in data[0:6])
        src_mac = ':'.join(f'{b:02X}' for b in data[6:12])
        eth_type = struct.unpack('!H', data[12:14])[0]
        return src_mac, dest_mac, eth_type
    
    def parse_ip_header(self, data):
        """Parse IP header"""
        iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        return src_ip, dst_ip
    
    def monitor(self, duration=10):
        """Monitor network traffic for X seconds"""
        
        print("=" * 70)
        print("Passive MITM Network Monitor")
        print("=" * 70)
        print("Capturing ALL network traffic...")
        print(f"Duration: {duration} seconds")
        print()
        
        try:
            # Create raw socket (requires admin on Windows)
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Get local IP
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Find 192.168.x.x IP
            for info in socket.getaddrinfo(hostname, None):
                ip = info[4][0]
                if ip.startswith('192.168.'):
                    local_ip = ip
                    break
            
            s.bind((local_ip, 0))
            
            # Enable promiscuous mode
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            print(f"Listening on: {local_ip}")
            print("Promiscuous mode enabled - capturing ALL traffic")
            print()
            
            start_time = time.time()
            packet_count = 0
            
            while time.time() - start_time < duration:
                try:
                    # Receive packet
                    packet = s.recvfrom(65536)[0]
                    packet_count += 1
                    
                    # Parse IP header
                    if len(packet) >= 20:
                        src_ip, dst_ip = self.parse_ip_header(packet)
                        
                        # Track devices on 192.168.x.x network
                        if src_ip.startswith('192.168.'):
                            if src_ip not in self.devices:
                                self.devices[src_ip] = {
                                    'ip': src_ip,
                                    'mac': 'Unknown',  # Can't get MAC from IP layer
                                    'packets': 0,
                                    'first_seen': time.strftime('%H:%M:%S'),
                                    'last_seen': time.strftime('%H:%M:%S')
                                }
                                print(f"NEW DEVICE: {src_ip}")
                            
                            self.devices[src_ip]['packets'] += 1
                            self.devices[src_ip]['last_seen'] = time.strftime('%H:%M:%S')
                        
                        # Show progress
                        if packet_count % 50 == 0:
                            print(f"\rPackets: {packet_count} | Devices: {len(self.devices)}   ", end='', flush=True)
                    
                except socket.timeout:
                    break
                except Exception as e:
                    pass
            
            # Disable promiscuous mode
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
            
            print(f"\n\nCapture complete!")
            print(f"Total packets: {packet_count}")
            print(f"Devices found: {len(self.devices)}")
            
            return True
            
        except PermissionError:
            print("ERROR: Administrator privileges required!")
            print("Please run as Administrator")
            return False
        except Exception as e:
            print(f"ERROR: {e}")
            return False
    
    def get_devices_with_mac(self):
        """Enhance device list with MAC addresses from ARP table"""
        import subprocess
        
        try:
            # Get ARP table
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if '192.168.' in line and 'dynamic' in line.lower():
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').upper()
                        
                        if ip in self.devices:
                            self.devices[ip]['mac'] = mac
        except:
            pass
    
    def output_json(self):
        """Output devices as JSON"""
        
        # Enhance with MAC addresses
        self.get_devices_with_mac()
        
        devices_list = []
        for ip, info in self.devices.items():
            devices_list.append({
                'ip': ip,
                'mac': info['mac'],
                'hostname': '',
                'type': 'Network Device',
                'is_router': ip in ['192.168.1.1', '192.168.0.1'],
                'packets_captured': info['packets'],
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen']
            })
        
        print("\n" + "=" * 70)
        print("JSON Output:")
        print("=" * 70)
        print(json.dumps(devices_list, indent=2))


if __name__ == "__main__":
    import sys
    
    duration = 10
    if len(sys.argv) > 1:
        duration = int(sys.argv[1])
    
    monitor = PassiveMITMMonitor()
    
    if monitor.monitor(duration):
        monitor.output_json()
    else:
        print("\nPlease run as Administrator:")
        print("Right-click PowerShell -> Run as Administrator")
        print("Then run: python mitm_packet_sniffer.py 10")
