#!/usr/bin/env python3
"""
Hybrid Router Manager - C++ for device listing, Python for blocking
Best of both worlds!
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import subprocess
import json
import os
from router_manager import RouterManager
from datetime import datetime

class HybridRouterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 NetWatch Pro - Complete Network Visibility & Management")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        # Router manager for blocking
        self.router = RouterManager()
        
        # Device storage
        self.devices = []
        self.blocked_macs = []
        self.quick_scan_devices = []  # Store devices from quick scan for MITM merge
        
        # Track scan mode for dynamic column headers
        self.last_scan_mode = "normal"  # "normal" or "mitm"
        
        # MITM Browser Monitor
        self.mitm_monitor = None
        self.mitm_monitor_thread = None
        
        # Create UI
        self.create_widgets()
        
        # Auto-scan on startup
        self.root.after(1000, self.scan_devices)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title = tk.Label(main_frame, 
                        text="🔍 NetWatch Pro\nComplete Network Visibility & Management", 
                        font=('Arial', 18, 'bold'), bg='#2b2b2b', fg='#00ff00')
        title.pack(pady=10)
        
        # Status
        self.status_label = tk.Label(main_frame, text="Status: Ready", 
                                     font=('Arial', 10), bg='#2b2b2b', fg='#00ff00')
        self.status_label.pack()
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Tab 1: Device Management (existing content)
        device_tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(device_tab, text='📱 Device Management')
        
        # Tab 2: MITM Browser Monitor (new)
        mitm_tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(mitm_tab, text='🕵️ Browsing Monitor (MITM)')
        
        # Create device management content (move existing to tab)
        self._create_device_tab(device_tab)
        
        # Create MITM browser monitor tab
        self._create_mitm_tab(mitm_tab)
        
        # Bottom - Logs (outside tabs)
        log_frame = tk.Frame(main_frame, bg='#2b2b2b')
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        tk.Label(log_frame, text="📋 Activity Log", bg='#2b2b2b', fg='#00ff00',
                font=('Arial', 12, 'bold')).pack()
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, 
                                                  bg='#1b1b1b', fg='#00ff00',
                                                  font=('Courier', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    def _create_device_tab(self, parent):
        """Create device management tab content"""
        # Main content area
        content_frame = tk.Frame(parent, bg='#2b2b2b')
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Device list (full width)
        left_frame = tk.Frame(content_frame, bg='#2b2b2b')
        left_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        
        tk.Label(left_frame, text="📱 Connected Devices (ARP Scan)", 
                bg='#2b2b2b', fg='#00ff00', font=('Arial', 12, 'bold')).pack()
        
        # Device treeview
        tree_frame = tk.Frame(left_frame, bg='#2b2b2b')
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.devices_tree = ttk.Treeview(tree_frame, 
                                        columns=('IP', 'MAC', 'Manufacturer', 'Type', 'OS', 'Status'),
                                        show='tree headings', height=15)
        
        self.devices_tree.heading('#0', text='Hostname / Username')
        self.devices_tree.heading('IP', text='IP Address')
        self.devices_tree.heading('MAC', text='MAC Address')
        self.devices_tree.heading('Manufacturer', text='Manufacturer')
        self.devices_tree.heading('Type', text='Device Type')
        self.devices_tree.heading('OS', text='OS')
        self.devices_tree.heading('Status', text='Status')
        
        self.devices_tree.column('#0', width=180)
        self.devices_tree.column('IP', width=100)
        self.devices_tree.column('MAC', width=130)
        self.devices_tree.column('Manufacturer', width=100)
        self.devices_tree.column('Type', width=110)
        self.devices_tree.column('OS', width=80)
        self.devices_tree.column('Status', width=80)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add right-click context menu for renaming
        self.devices_tree.bind("<Button-3>", self.show_context_menu)
        
        # Buttons
        btn_frame = tk.Frame(left_frame, bg='#2b2b2b')
        btn_frame.pack(fill=tk.X, pady=5)
        
        tk.Button(btn_frame, text="🔄 Quick Scan", command=self.scan_devices,
                 bg='#0066cc', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🔍 Complete Discovery", command=self.complete_discovery,
                 bg='#0066cc', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🕵️ MITM Scan", command=self.mitm_scan,
                 bg='#dc3545', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🚫 Block Selected (Python)", command=self.block_selected,
                 bg='#cc0000', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="✅ Unblock Selected", command=self.unblock_selected,
                 bg='#00aa00', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        # Manual MAC entry
        manual_frame = tk.Frame(left_frame, bg='#2b2b2b')
        manual_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(manual_frame, text="Manual MAC:", bg='#2b2b2b', fg='#00ff00',
                font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        self.manual_mac_entry = tk.Entry(manual_frame, font=('Courier', 10), width=20)
        self.manual_mac_entry.pack(side=tk.LEFT, padx=5)
        self.manual_mac_entry.insert(0, "AA:BB:CC:DD:EE:FF")
        
        tk.Button(manual_frame, text="🚫 Block", command=self.block_manual,
                 bg='#cc0000', fg='white', font=('Arial', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=2)
        
        tk.Button(manual_frame, text="✅ Unblock", command=self.unblock_manual,
                 bg='#00aa00', fg='white', font=('Arial', 9, 'bold'),
                 padx=10, pady=5).pack(side=tk.LEFT, padx=2)
    
    def _create_mitm_tab(self, parent):
        """Create MITM real-time traffic monitoring tab"""
        # Top control panel
        control_frame = tk.Frame(parent, bg='#2b2b2b')
        control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(control_frame, text="🕵️ MITM Traffic Monitor - Live Network Activity", 
                bg='#2b2b2b', fg='#ff6600', font=('Arial', 14, 'bold')).pack()
        
        tk.Label(control_frame, text="⚠️ Shows real-time traffic between router and all connected devices", 
                bg='#2b2b2b', fg='#ffaa00', font=('Arial', 9)).pack(pady=5)
        
        # Control buttons
        btn_frame = tk.Frame(control_frame, bg='#2b2b2b')
        btn_frame.pack(pady=10)
        
        self.mitm_start_btn = tk.Button(btn_frame, text="▶️ Start MITM Monitor", 
                                        command=self.start_mitm_monitor,
                                        bg='#00aa00', fg='white', 
                                        font=('Arial', 11, 'bold'),
                                        padx=20, pady=10)
        self.mitm_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.mitm_stop_btn = tk.Button(btn_frame, text="⏹️ Stop Monitor", 
                                       command=self.stop_mitm_monitor,
                                       bg='#cc0000', fg='white', 
                                       font=('Arial', 11, 'bold'),
                                       padx=20, pady=10, state=tk.DISABLED)
        self.mitm_stop_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🗑️ Clear History", 
                 command=self.clear_browsing_history,
                 bg='#666666', fg='white', 
                 font=('Arial', 11, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="💾 Export to JSON", 
                 command=self.export_browsing_history,
                 bg='#0066cc', fg='white', 
                 font=('Arial', 11, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        self.mitm_status_label = tk.Label(control_frame, 
                                          text="Status: Idle", 
                                          bg='#2b2b2b', fg='#888888',
                                          font=('Arial', 10, 'bold'))
        self.mitm_status_label.pack(pady=5)
        
        # Statistics panel
        stats_frame = tk.Frame(parent, bg='#3b3b3b', relief=tk.RAISED, borderwidth=2)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(stats_frame, text="📊 Network Statistics", 
                bg='#3b3b3b', fg='#00ff00', 
                font=('Arial', 11, 'bold')).pack(pady=5)
        
        stats_inner = tk.Frame(stats_frame, bg='#3b3b3b')
        stats_inner.pack(fill=tk.X, padx=10, pady=5)
        
        self.mitm_stats_label = tk.Label(stats_inner, 
                                         text="Devices: 0 | Total Packets: 0 | Upload: 0 KB | Download: 0 KB",
                                         bg='#3b3b3b', fg='#00ffff',
                                         font=('Courier', 10, 'bold'))
        self.mitm_stats_label.pack()
        
        # Device traffic table (replaces browsing history)
        traffic_frame = tk.Frame(parent, bg='#2b2b2b')
        traffic_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        tk.Label(traffic_frame, text="📡 Real-time Device Traffic (Router ↔ Devices)", 
                bg='#2b2b2b', fg='#00ff00', 
                font=('Arial', 12, 'bold')).pack(pady=5)
        
        # Create treeview for device traffic
        tree_container = tk.Frame(traffic_frame, bg='#2b2b2b')
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        self.traffic_tree = ttk.Treeview(tree_container,
                                         columns=('Device', 'IP', 'MAC', 'Upload', 'Download', 'Packets', 'Connections', 'Last Activity'),
                                         show='headings', height=20)
        
        self.traffic_tree.heading('Device', text='Device Name')
        self.traffic_tree.heading('IP', text='IP Address')
        self.traffic_tree.heading('MAC', text='MAC Address')
        self.traffic_tree.heading('Upload', text='↑ Upload (KB)')
        self.traffic_tree.heading('Download', text='↓ Download (KB)')
        self.traffic_tree.heading('Packets', text='Total Packets')
        self.traffic_tree.heading('Connections', text='Connections')
        self.traffic_tree.heading('Last Activity', text='Last Activity')
        
        self.traffic_tree.column('Device', width=150)
        self.traffic_tree.column('IP', width=100)
        self.traffic_tree.column('MAC', width=130)
        self.traffic_tree.column('Upload', width=100)
        self.traffic_tree.column('Download', width=100)
        self.traffic_tree.column('Packets', width=100)
        self.traffic_tree.column('Connections', width=90)
        self.traffic_tree.column('Last Activity', width=150)
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.traffic_tree.xview)
        self.traffic_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.traffic_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Right-click menu for device traffic
        self.traffic_tree.bind("<Button-3>", self.show_traffic_context_menu)
    
    def log(self, message, level="INFO"):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {"INFO": "#00ff00", "SUCCESS": "#00ff00", "ERROR": "#ff0000", "WARNING": "#ffaa00"}
        
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        self.log_text.update()
    
    def update_status(self, text):
        """Update status label"""
        self.status_label.config(text=f"Status: {text}")
        self.status_label.update()
    
    def run_in_thread(self, func, *args):
        """Run function in background thread"""
        thread = threading.Thread(target=func, args=args, daemon=True)
        thread.start()
    
    def scan_devices(self):
        """Scan devices using Python Router API"""
        self.log("🔍 Scanning devices from router...", "INFO")
        self.update_status("Scanning network...")
        self.run_in_thread(self._scan_devices_thread)
    
    def _scan_devices_thread(self):
        """Background thread for scanning"""
        try:
            # Set scan mode to normal
            self.last_scan_mode = "normal"
            
            # Note: Router API /uajax/landevice_json.htm requires ADMIN access
            # User account only has limited access, so we use ARP scanning
            self.log("⚠ Note: User account has limited router API access", "WARNING")
            self.log("Using network ARP scan to find devices...", "INFO")
            
            # Use ARP scanner (works without admin access)
            self._scan_devices_arp()
            
        except Exception as e:
            self.log(f"✗ Scan error: {e}", "ERROR")
    
    def complete_discovery(self):
        """Complete device discovery using all methods"""
        self.log("🔍 Starting complete discovery (NetBIOS + mDNS + SSDP + MAC DB)...", "INFO")
        self.update_status("Running complete discovery...")
        self.run_in_thread(self._complete_discovery_thread)
    
    def _complete_discovery_thread(self):
        """Background complete discovery"""
        try:
            # Set scan mode to normal
            self.last_scan_mode = "normal"
            
            self.log("Running comprehensive device discovery...", "INFO")
            self.log("Methods: NetBIOS, mDNS, SSDP, Enhanced MAC Database", "INFO")
            
            result = subprocess.run(['python', 'complete_device_discovery.py'], 
                                  capture_output=True, text=True, timeout=60)
            
            self.log(f"Discovery completed with return code: {result.returncode}", "INFO")
            
            if result.returncode == 0:
                # Extract JSON from output (it's at the end after "JSON Output:")
                output = result.stdout
                
                # Debug: Save full output
                self.log(f"Output length: {len(output)} characters", "INFO")
                
                json_start = output.rfind('[')
                if json_start >= 0:
                    json_data = output[json_start:]
                    self.log(f"Found JSON at position {json_start}", "INFO")
                    
                    try:
                        devices = json.loads(json_data)
                        self.devices = devices
                        self.log(f"✓ Complete discovery found {len(devices)} device(s)", "SUCCESS")
                        
                        # Show discovery methods used
                        for dev in devices:
                            name_source = dev.get('name_source', 'Unknown')
                            self.log(f"  {dev.get('hostname', 'Unknown')} - {name_source}", "INFO")
                        
                        self.root.after(0, self._update_device_tree)
                        self.root.after(0, lambda: self.update_status(f"Found {len(devices)} devices"))
                    except json.JSONDecodeError as e:
                        self.log(f"✗ JSON parse error: {e}", "ERROR")
                        self.log(f"JSON data preview: {json_data[:200]}...", "ERROR")
                else:
                    self.log("✗ Could not find JSON in output", "ERROR")
                    self.log(f"Output preview: {output[:500]}...", "ERROR")
            else:
                self.log(f"✗ Discovery failed with code {result.returncode}", "ERROR")
                self.log(f"Error: {result.stderr[:500]}", "ERROR")
                
        except subprocess.TimeoutExpired:
            self.log("✗ Discovery timeout", "ERROR")
        except json.JSONDecodeError as e:
            self.log(f"✗ Failed to parse discovery output: {e}", "ERROR")
        except Exception as e:
            self.log(f"✗ Discovery error: {e}", "ERROR")
    
    def mitm_scan(self):
        """Run MITM passive network scan to detect ALL devices"""
        self.log("🕵️ Starting MITM Passive Network Scan...", "INFO")
        self.log("⚠️ This requires Administrator privileges!", "WARNING")
        self.log("📡 Will intercept network traffic for 30 seconds...", "INFO")
        self.log("🔍 Detects ALL devices, even silent/sleeping ones", "INFO")
        self.update_status("MITM scanning...")
        self.run_in_thread(self._mitm_scan_thread)
    
    def _mitm_scan_thread(self):
        """Background MITM scanning"""
        try:
            # Set scan mode to MITM
            self.last_scan_mode = "mitm"
            
            # Check if running as admin on Windows
            if os.name == 'nt':
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    self.log("✗ ERROR: Not running as Administrator!", "ERROR")
                    self.log("💡 Right-click run_gui_as_admin_mitm.bat and select 'Run as Administrator'", "INFO")
                    self.root.after(0, lambda: messagebox.showerror("Admin Required",
                        "MITM scan requires Administrator privileges!\n\n"
                        "Please run: run_gui_as_admin_mitm.bat"))
                    return
            
            # Import MITM scanner
            try:
                from mitm_passive_scanner import MITMNetworkScanner
            except ImportError:
                self.log("✗ ERROR: mitm_passive_scanner.py not found", "ERROR")
                return
            
            # Get router IP
            router_ip = "192.168.1.1"  # Default, can be configured
            
            # Create scanner
            self.log(f"Initializing MITM scanner for gateway {router_ip}...", "INFO")
            scanner = MITMNetworkScanner(router_ip=router_ip)
            
            self.log(f"✓ Interface: {scanner.interface}", "SUCCESS")
            self.log(f"✓ Gateway: {scanner.router_ip} ({scanner.gateway_mac})", "SUCCESS")
            self.log(f"✓ My IP: {scanner.my_ip}", "SUCCESS")
            self.log("", "INFO")
            self.log("🔄 Enabling IP forwarding...", "INFO")
            self.log("🎯 Starting ARP poisoning...", "INFO")
            self.log("📶 Capturing packets for 30 seconds...", "INFO")
            self.log("", "INFO")
            
            # Run scan (30 seconds)
            scanner.start_passive_scan(duration=30)
            
            # Get results
            devices_dict = scanner.get_devices()
            
            self.log(f"✓ MITM scan complete - Found {len(devices_dict)} devices with traffic!", "SUCCESS")
            
            # Merge with Quick Scan devices to show ALL connected devices
            self.log(f"Merging with Quick Scan results ({len(self.quick_scan_devices)} devices)...", "INFO")
            
            # Create a dictionary of MITM devices by MAC
            mitm_devices_by_mac = {mac: device for mac, device in devices_dict.items()}
            
            # Convert to display format
            device_list = []
            all_macs = set()
            
            # First, add all devices from Quick Scan
            for quick_device in self.quick_scan_devices:
                mac = quick_device['mac']
                all_macs.add(mac)
                
                # Check if this device has MITM traffic data
                if mac in mitm_devices_by_mac:
                    mitm_device = mitm_devices_by_mac[mac]
                    traffic_info = mitm_device.get('traffic', {})
                    protocols = traffic_info.get('protocols', [])
                    traffic_types = ', '.join(protocols) if protocols else 'No Traffic'
                    
                    device_list.append({
                        'ip': quick_device.get('ip', mitm_device.get('ip', 'Unknown')),
                        'mac': mac,
                        'hostname': quick_device.get('hostname', mitm_device.get('hostname', 'Unknown')),
                        'manufacturer': traffic_types,  # Show traffic types
                        'type': quick_device.get('type', mitm_device.get('type', 'Unknown Device')),
                        'os': mitm_device.get('os', quick_device.get('os', 'Unknown')),
                        'name_source': 'MITM + Quick Scan',
                        'traffic_sent': traffic_info.get('bytes_sent', 0),
                        'traffic_recv': traffic_info.get('bytes_recv', 0),
                        'packets': traffic_info.get('packets', 0),
                        'connected': True,
                    })
                else:
                    # Device found in Quick Scan but NO traffic in MITM
                    device_list.append({
                        'ip': quick_device.get('ip', 'Unknown'),
                        'mac': mac,
                        'hostname': quick_device.get('hostname', 'Unknown'),
                        'manufacturer': 'No Traffic (Silent)',  # No traffic detected
                        'type': quick_device.get('type', 'Unknown Device'),
                        'os': quick_device.get('os', 'Unknown'),
                        'name_source': 'Quick Scan Only',
                        'traffic_sent': 0,
                        'traffic_recv': 0,
                        'packets': 0,
                        'connected': True,
                    })
            
            # Add any MITM-only devices (not in Quick Scan)
            for mac, mitm_device in devices_dict.items():
                if mac not in all_macs:
                    traffic_info = mitm_device.get('traffic', {})
                    protocols = traffic_info.get('protocols', [])
                    traffic_types = ', '.join(protocols) if protocols else 'No Traffic'
                    
                    device_list.append({
                        'ip': mitm_device.get('ip', 'Unknown'),
                        'mac': mac,
                        'hostname': mitm_device.get('hostname', 'Unknown'),
                        'manufacturer': traffic_types,
                        'type': mitm_device.get('type', 'Unknown Device'),
                        'os': mitm_device.get('os', 'Unknown'),
                        'name_source': 'MITM Only',
                        'traffic_sent': traffic_info.get('bytes_sent', 0),
                        'traffic_recv': traffic_info.get('bytes_recv', 0),
                        'packets': traffic_info.get('packets', 0),
                        'connected': True,
                    })
            
            self.log(f"✓ Total devices in combined view: {len(device_list)}", "SUCCESS")
            active_count = sum(1 for d in device_list if d['packets'] > 0)
            silent_count = len(device_list) - active_count
            self.log(f"  - {active_count} devices with traffic", "INFO")
            self.log(f"  - {silent_count} devices silent (connected but no traffic)", "INFO")
            
            # Sort by IP
            device_list.sort(key=lambda x: self._ip_sort_key(x.get('ip', '0.0.0.0')))
            
            # Update display
            self.devices = device_list
            self.root.after(0, self._update_device_tree)
            self.root.after(0, lambda: self.update_status(f"MITM scan found {len(device_list)} devices"))
            
            # Log device details
            for dev in device_list:
                if dev['packets'] > 0:
                    traffic = f"↑{dev['traffic_sent']}B ↓{dev['traffic_recv']}B ({dev['packets']} pkts) - {dev['manufacturer']}"
                    self.log(f"  ✓ {dev['hostname']} ({dev['ip']}) - {traffic}", "SUCCESS")
                else:
                    self.log(f"  ⚠ {dev['hostname']} ({dev['ip']}) - Connected but silent (no traffic)", "WARNING")
            
            # Save to file
            with open('mitm_devices.json', 'w') as f:
                json.dump(devices_dict, f, indent=2)
            
            self.log("✓ Results saved to mitm_devices.json", "SUCCESS")
            self.log("", "INFO")
            self.log("🎉 MITM scan completed successfully!", "SUCCESS")
            
        except Exception as e:
            self.log(f"✗ MITM scan error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
    
    def _ip_sort_key(self, ip_str):
        """Convert IP string to sortable tuple"""
        try:
            return tuple(int(part) for part in ip_str.split('.'))
        except:
            return (999, 999, 999, 999)
    
    def passive_monitor(self):
        """Monitor network passively for 10 seconds"""
        self.log("🔍 Starting passive network monitor (10 seconds)...", "INFO")
        self.update_status("Monitoring network traffic...")
        self.run_in_thread(self._passive_monitor_thread)
    
    def _passive_monitor_thread(self):
        """Background passive monitoring"""
        try:
            # Set scan mode to normal
            self.last_scan_mode = "normal"
            
            if not os.path.exists('passive_monitor.exe'):
                self.log("✗ Passive monitor not found", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Error",
                    "passive_monitor.exe not found!\n\nPlease rebuild the project."))
                return
            
            self.log("Monitoring network for 10 seconds...", "INFO")
            self.log("Tip: Use your devices to see them appear!", "INFO")
            
            result = subprocess.run(['passive_monitor.exe', '10'], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                devices = json.loads(result.stdout)
                self.devices = devices
                self.log(f"✓ Passive monitor found {len(devices)} device(s)", "SUCCESS")
                
                self.root.after(0, self._update_device_tree)
                self.root.after(0, lambda: self.update_status(f"Found {len(devices)} devices (passive)"))
            else:
                self.log(f"✗ Monitor failed: {result.stderr}", "ERROR")
                
        except subprocess.TimeoutExpired:
            self.log("✗ Monitor timeout", "ERROR")
        except json.JSONDecodeError as e:
            self.log(f"✗ Failed to parse monitor output", "ERROR")
        except Exception as e:
            self.log(f"✗ Monitor error: {e}", "ERROR")
    
    def _scan_devices_arp(self):
        """Scan devices using ARP table"""
        try:
            if not os.path.exists('device_scanner.exe'):
                self.log("⚠ Building C++ ARP scanner...", "WARNING")
                
                # Try to build it
                result = subprocess.run(['g++', 'device_scanner_cli.cpp', '-o', 'device_scanner.exe',
                                       '-liphlpapi', '-lws2_32', '-static'],
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    self.log("✗ Failed to build scanner", "ERROR")
                    self.log("Error: g++ (MinGW) not found or build error", "ERROR")
                    self.root.after(0, lambda: messagebox.showwarning("Scanner Not Available",
                        "C++ device scanner could not be built.\n\n"
                        "Device scanning requires admin router access OR g++ (MinGW) to build the ARP scanner.\n\n"
                        "You can still use block/unblock features!"))
                    return
            
            self.log("Running ARP scanner...", "INFO")
            result = subprocess.run(['device_scanner.exe'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                devices = json.loads(result.stdout)
                self.devices = devices
                self.quick_scan_devices = devices  # Store for MITM merge
                self.log(f"✓ Found {len(devices)} device(s) via ARP scan", "SUCCESS")
                self.root.after(0, self._update_device_tree)
                self.root.after(0, lambda: self.update_status(f"Found {len(devices)} devices"))
            else:
                self.log(f"✗ Scanner error: {result.stderr}", "ERROR")
            
        except subprocess.TimeoutExpired:
            self.log("✗ Scanner timeout", "ERROR")
        except json.JSONDecodeError as e:
            self.log(f"✗ Failed to parse scanner output", "ERROR")
        except Exception as e:
            self.log(f"✗ ARP scan failed: {e}", "ERROR")
    
    def _load_known_devices(self):
        """Load known devices from JSON database"""
        try:
            if os.path.exists('known_devices.json'):
                with open('known_devices.json', 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            self.log(f"⚠ Could not load known devices: {e}", "WARNING")
            return {}
    
    def _update_device_tree(self):
        """Update device treeview (main thread only)"""
        # Load known devices database
        known_devices = self._load_known_devices()
        
        # Update column header based on scan mode
        if self.last_scan_mode == "mitm":
            self.devices_tree.heading('Manufacturer', text='Traffic Type')
        else:
            self.devices_tree.heading('Manufacturer', text='Manufacturer')
        
        # Clear current items
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Add devices
        for device in self.devices:
            mac = device['mac']
            hostname = device.get('hostname', '')
            username = device.get('username', '')
            
            # Check if we have a custom name/type for this device
            custom_data = known_devices.get(mac, {})
            custom_name = custom_data.get('name')
            custom_type = custom_data.get('type')
            
            # Build display name - prioritize custom name
            if custom_name:
                # Use original hostname/username in the name column
                if username and username != hostname:
                    display_name = f"{hostname} [{username}]"
                elif hostname:
                    display_name = hostname
                else:
                    display_name = f"Device {device['ip'].split('.')[-1]}"
                
                # Show custom name in device type column
                device_type = custom_name
                self.log(f"📌 Using custom name '{custom_name}' for {mac} in Device Type column", "INFO")
            else:
                # No custom name - use default logic
                if username and username != hostname:
                    display_name = f"{hostname} [{username}]"
                elif not hostname:
                    if device.get('is_router'):
                        display_name = "WiFi Router"
                    else:
                        display_name = f"Device {device['ip'].split('.')[-1]}"
                else:
                    display_name = hostname
                
                # Use custom type if available, otherwise use detected type
                if custom_type:
                    device_type = custom_type
                    self.log(f"📌 Using saved type for {mac}: {custom_type}", "INFO")
                else:
                    device_type = device.get('device_type', device.get('type', 'Unknown'))
            
            # Get enhanced info
            manufacturer = device.get('manufacturer', 'Unknown')
            
            os_info = device.get('os', 'Unknown')
            
            # Check if blocked
            is_blocked = mac in self.blocked_macs
            status = "🚫 Blocked" if is_blocked else "✓ Active"
            
            # Add icon
            icon = '🌐' if device.get('is_router') else '📱'
            
            # Add to tree with all enhanced details (including custom name/type)
            self.devices_tree.insert('', tk.END, text=f"{icon} {display_name}",
                                    values=(device['ip'], device['mac'], 
                                           manufacturer, device_type, os_info, status))
    
    def block_selected(self):
        """Block selected device using Python router API"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to block")
            return
        
        # Get device info
        item = self.devices_tree.item(selection[0])
        hostname = item['text']
        mac = item['values'][1]
        ip = item['values'][0]
        
        # Check if router
        if ip in ['192.168.1.1', '192.168.0.1']:
            messagebox.showerror("Cannot Block", "Cannot block the router!")
            return
        
        # Confirm
        confirm = messagebox.askyesno("Confirm Block",
                                      f"Block device?\n\n"
                                      f"Name: {hostname}\n"
                                      f"MAC: {mac}\n"
                                      f"IP: {ip}\n\n"
                                      f"This will disconnect the device from WiFi.")
        
        if confirm:
            self.log(f"🚫 Blocking {hostname} ({mac})...", "INFO")
            self.run_in_thread(self._block_device_thread, mac, hostname)
    
    def _block_device_thread(self, mac, hostname):
        """Block device in background"""
        # Login first
        if not self.router.logged_in:
            self.log("Logging into router...", "INFO")
            if not self.router.login():
                self.log("✗ Login failed!", "ERROR")
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to login to router!"))
                return
        
        # Block device
        success, msg = self.router.block_device(mac)
        
        if success:
            self.log(f"✓ {msg}", "SUCCESS")
            self.blocked_macs.append(mac)
            
            # Update UI
            self.root.after(0, self._update_device_tree)
            self.root.after(0, lambda: messagebox.showinfo("Success", 
                f"Device blocked!\n\n{hostname}\nMAC: {mac}\n\n"
                "The device has been disconnected from WiFi."))
        else:
            self.log(f"✗ {msg}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to block device:\n{msg}"))
    
    def unblock_selected(self):
        """Unblock selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a blocked device")
            return
        
        item = self.devices_tree.item(selection[0])
        hostname = item['text']
        mac = item['values'][1]
        
        if mac not in self.blocked_macs:
            messagebox.showinfo("Not Blocked", "This device is not blocked")
            return
        
        confirm = messagebox.askyesno("Confirm Unblock",
                                      f"Unblock device?\n\n"
                                      f"Name: {hostname}\n"
                                      f"MAC: {mac}")
        
        if confirm:
            self.log(f"✅ Unblocking {hostname} ({mac})...", "INFO")
            self.run_in_thread(self._unblock_device_thread, mac, hostname)
    
    def _unblock_device_thread(self, mac, hostname):
        """Unblock device in background"""
        success, msg = self.router.unblock_device(mac)
        
        if success:
            self.log(f"✓ {msg}", "SUCCESS")
            if mac in self.blocked_macs:
                self.blocked_macs.remove(mac)
            
            self.root.after(0, self._update_device_tree)
            self.root.after(0, lambda: messagebox.showinfo("Success",
                f"Device unblocked!\n\n{hostname}\nMAC: {mac}"))
        else:
            self.log(f"✗ {msg}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to unblock:\n{msg}"))
    
    def block_manual(self):
        """Block device by manually entered MAC"""
        mac = self.manual_mac_entry.get().strip().upper()
        
        if not mac or len(mac) < 12:
            messagebox.showwarning("Invalid MAC", "Please enter a valid MAC address")
            return
        
        confirm = messagebox.askyesno("Confirm Block",
                                      f"Block device with MAC address?\n\n{mac}\n\n"
                                      f"This will disconnect the device from WiFi.")
        
        if confirm:
            self.log(f"🚫 Blocking {mac}...", "INFO")
            self.run_in_thread(self._block_device_thread, mac, f"Manual Entry ({mac})")
    
    def unblock_manual(self):
        """Unblock device by manually entered MAC"""
        mac = self.manual_mac_entry.get().strip().upper()
        
        if not mac or len(mac) < 12:
            messagebox.showwarning("Invalid MAC", "Please enter a valid MAC address")
            return
        
        confirm = messagebox.askyesno("Confirm Unblock",
                                      f"Unblock device with MAC address?\n\n{mac}")
        
        if confirm:
            self.log(f"✅ Unblocking {mac}...", "INFO")
            self.run_in_thread(self._unblock_device_thread, mac, f"Manual Entry ({mac})")
    
    
    def refresh_blocked(self):
        """Refresh blocked devices list from router"""
        self.log("Refreshing blocked devices list...", "INFO")
        self.run_in_thread(self._refresh_blocked_thread)
    
    def _refresh_blocked_thread(self):
        """Background thread for refreshing blocked list"""
        if not self.router.logged_in:
            if not self.router.login():
                self.log("✗ Login failed", "ERROR")
                return
        
        success, blocked = self.router.get_mac_filter_list()
        
        if success:
            self.blocked_macs = [device['mac'] for device in blocked]
            self.log(f"✓ Found {len(self.blocked_macs)} blocked device(s)", "SUCCESS")
            
            # Update UI
            self.root.after(0, self._update_device_tree)
        else:
            self.log(f"✗ Failed to get blocked list: {blocked}", "ERROR")
    
    def show_context_menu(self, event):
        """Show right-click context menu on device"""
        # Get selected item
        item_id = self.devices_tree.identify_row(event.y)
        if not item_id:
            return
        
        # Select the item
        self.devices_tree.selection_set(item_id)
        
        # Create context menu
        menu = tk.Menu(self.root, tearoff=0, bg='#2b2b2b', fg='white', 
                      activebackground='#0066cc', activeforeground='white')
        menu.add_command(label="✏️ Rename Device", command=self.rename_device)
        menu.add_command(label="🏷️ Set Device Type", command=self.set_device_type)
        menu.add_separator()
        menu.add_command(label="📋 Copy MAC Address", command=self.copy_mac)
        menu.add_command(label="📋 Copy IP Address", command=self.copy_ip)
        
        # Show menu
        menu.post(event.x_root, event.y_root)
    
    def rename_device(self):
        """Rename selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            return
        
        # Get device info
        item = self.devices_tree.item(selection[0])
        current_name = item['text'].replace('🌐 ', '').replace('📱 ', '')
        mac = item['values'][1]
        ip = item['values'][0]
        
        # Create rename dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Rename Device")
        dialog.geometry("400x200")
        dialog.configure(bg='#2b2b2b')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Content
        tk.Label(dialog, text="Rename Device", font=('Arial', 14, 'bold'),
                bg='#2b2b2b', fg='#00ff00').pack(pady=10)
        
        tk.Label(dialog, text=f"MAC: {mac}\nIP: {ip}", font=('Arial', 9),
                bg='#2b2b2b', fg='#888888').pack(pady=5)
        
        tk.Label(dialog, text="New Name:", font=('Arial', 10),
                bg='#2b2b2b', fg='white').pack(pady=5)
        
        name_entry = tk.Entry(dialog, font=('Arial', 12), width=30)
        name_entry.pack(pady=5)
        name_entry.insert(0, current_name)
        name_entry.select_range(0, tk.END)
        name_entry.focus()
        
        def save_rename():
            new_name = name_entry.get().strip()
            if new_name:
                if self._save_device_name(mac, new_name):
                    dialog.destroy()
                    self.log(f"✓ Renamed device {mac} to '{new_name}'", "SUCCESS")
                    self.log(f"💾 Name saved permanently to known_devices.json", "SUCCESS")
                    # Refresh display to show new name
                    self.root.after(100, self._update_device_tree)
                else:
                    messagebox.showerror("Save Error", "Failed to save device name!")
        
        def cancel():
            dialog.destroy()
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg='#2b2b2b')
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="💾 Save", command=save_rename,
                 bg='#00aa00', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="❌ Cancel", command=cancel,
                 bg='#666666', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Enter to save
        name_entry.bind('<Return>', lambda e: save_rename())
        dialog.bind('<Escape>', lambda e: cancel())
    
    def set_device_type(self):
        """Set device type for selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            return
        
        # Get device info
        item = self.devices_tree.item(selection[0])
        hostname = item['text'].replace('🌐 ', '').replace('📱 ', '')
        mac = item['values'][1]
        current_type = item['values'][3]
        
        # Create type selection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Device Type")
        dialog.geometry("400x450")
        dialog.configure(bg='#2b2b2b')
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Content
        tk.Label(dialog, text="Set Device Type", font=('Arial', 14, 'bold'),
                bg='#2b2b2b', fg='#00ff00').pack(pady=10)
        
        tk.Label(dialog, text=f"{hostname}\nMAC: {mac}", font=('Arial', 9),
                bg='#2b2b2b', fg='#888888').pack(pady=5)
        
        tk.Label(dialog, text="Select Device Type:", font=('Arial', 10),
                bg='#2b2b2b', fg='white').pack(pady=10)
        
        # Device type options
        device_types = [
            "iPhone", "iPad", "Android Phone", "Android Tablet",
            "Windows PC", "Windows Laptop", "Mac", "MacBook",
            "Linux PC", "Raspberry Pi",
            "Smart TV", "Samsung TV", "LG TV", "Sony TV",
            "Gaming Console", "PlayStation", "Xbox", "Nintendo Switch",
            "Smart Speaker", "Amazon Echo", "Google Home",
            "Smart Home Device", "Security Camera", "Smart Bulb",
            "Router", "Network Switch", "Access Point",
            "Printer", "Scanner",
            "Unknown Device", "Other"
        ]
        
        # Listbox for selection
        list_frame = tk.Frame(dialog, bg='#2b2b2b')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        type_listbox = tk.Listbox(list_frame, font=('Arial', 10), height=15,
                                  bg='#1b1b1b', fg='white',
                                  yscrollcommand=scrollbar.set,
                                  selectmode=tk.SINGLE)
        type_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=type_listbox.yview)
        
        # Populate listbox
        for dtype in device_types:
            type_listbox.insert(tk.END, dtype)
            if dtype == current_type:
                type_listbox.selection_set(type_listbox.size() - 1)
                type_listbox.see(type_listbox.size() - 1)
        
        def save_type():
            selection = type_listbox.curselection()
            if selection:
                new_type = type_listbox.get(selection[0])
                if self._save_device_type(mac, new_type):
                    dialog.destroy()
                    self.log(f"✓ Set device type for {mac} to '{new_type}'", "SUCCESS")
                    self.log(f"💾 Type saved permanently to known_devices.json", "SUCCESS")
                    # Refresh display to show new type
                    self.root.after(100, self._update_device_tree)
                else:
                    messagebox.showerror("Save Error", "Failed to save device type!")
        
        def cancel():
            dialog.destroy()
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg='#2b2b2b')
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="💾 Save", command=save_type,
                 bg='#00aa00', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="❌ Cancel", command=cancel,
                 bg='#666666', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Double-click or Enter to save
        type_listbox.bind('<Double-Button-1>', lambda e: save_type())
        type_listbox.bind('<Return>', lambda e: save_type())
        dialog.bind('<Escape>', lambda e: cancel())
    
    def copy_mac(self):
        """Copy MAC address to clipboard"""
        selection = self.devices_tree.selection()
        if not selection:
            return
        
        item = self.devices_tree.item(selection[0])
        mac = item['values'][1]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(mac)
        self.log(f"📋 Copied MAC address: {mac}", "INFO")
    
    def copy_ip(self):
        """Copy IP address to clipboard"""
        selection = self.devices_tree.selection()
        if not selection:
            return
        
        item = self.devices_tree.item(selection[0])
        ip = item['values'][0]
        
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        self.log(f"📋 Copied IP address: {ip}", "INFO")
    
    def _save_device_name(self, mac, name):
        """Save device name to known_devices.json"""
        try:
            # Load existing database
            if os.path.exists('known_devices.json'):
                with open('known_devices.json', 'r') as f:
                    known_devices = json.load(f)
            else:
                known_devices = {}
            
            # Update device name
            if mac not in known_devices:
                known_devices[mac] = {}
            
            known_devices[mac]['name'] = name
            
            # Save back
            with open('known_devices.json', 'w') as f:
                json.dump(known_devices, f, indent=2)
            
            return True
        except Exception as e:
            self.log(f"✗ Failed to save device name: {e}", "ERROR")
            return False
    
    def _save_device_type(self, mac, device_type):
        """Save device type to known_devices.json"""
        try:
            # Load existing database
            if os.path.exists('known_devices.json'):
                with open('known_devices.json', 'r') as f:
                    known_devices = json.load(f)
            else:
                known_devices = {}
            
            # Update device type
            if mac not in known_devices:
                known_devices[mac] = {}
            
            known_devices[mac]['type'] = device_type
            
            # Save back
            with open('known_devices.json', 'w') as f:
                json.dump(known_devices, f, indent=2)
            
            return True
        except Exception as e:
            self.log(f"✗ Failed to save device type: {e}", "ERROR")
            return False
    
    # ==================== MITM Browser Monitor Functions ====================
    
    def start_mitm_monitor(self):
        """Start MITM browser monitoring"""
        self.log("🕵️ Starting MITM Browser Monitor...", "INFO")
        self.log("⚠️ This requires Administrator privileges!", "WARNING")
        self.log("📡 Will intercept HTTP/HTTPS traffic and show browsing activity", "INFO")
        
        # Check if running as admin on Windows
        if os.name == 'nt':
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                self.log("✗ ERROR: Not running as Administrator!", "ERROR")
                self.log("💡 Right-click run_gui_as_admin_mitm.bat and select 'Run as Administrator'", "INFO")
                messagebox.showerror("Admin Required",
                    "MITM Browser Monitor requires Administrator privileges!\n\n"
                    "Please run: run_gui_as_admin_mitm.bat")
                return
        
        # Update UI
        self.mitm_start_btn.config(state=tk.DISABLED)
        self.mitm_stop_btn.config(state=tk.NORMAL)
        self.mitm_status_label.config(text="Status: 🟢 Monitoring Active", fg='#00ff00')
        
        # Start monitor in background thread
        self.run_in_thread(self._start_mitm_monitor_thread)
    
    def _start_mitm_monitor_thread(self):
        """Background thread for MITM monitoring"""
        try:
            # Import MITM browser monitor
            try:
                from mitm_browser_monitor import MITMBrowserMonitor
            except ImportError:
                self.log("✗ ERROR: mitm_browser_monitor.py not found", "ERROR")
                self.root.after(0, self._mitm_monitor_stopped)
                return
            
            # Get router IP
            router_ip = "192.168.1.1"  # Default, can be configured
            
            # Create monitor
            self.log(f"Initializing MITM browser monitor for gateway {router_ip}...", "INFO")
            self.mitm_monitor = MITMBrowserMonitor(router_ip=router_ip)
            
            self.log(f"✓ Interface: {self.mitm_monitor.interface}", "SUCCESS")
            self.log(f"✓ Gateway: {self.mitm_monitor.router_ip} ({self.mitm_monitor.gateway_mac})", "SUCCESS")
            self.log(f"✓ My IP: {self.mitm_monitor.my_ip}", "SUCCESS")
            self.log("", "INFO")
            self.log("🔄 Enabling IP forwarding...", "INFO")
            self.log("🎯 Starting ARP poisoning...", "INFO")
            self.log("📶 Capturing HTTP/HTTPS traffic...", "INFO")
            self.log("🌐 Browsing activity will appear below in real-time!", "INFO")
            self.log("", "INFO")
            
            # Start monitoring (continuous until stopped)
            self.mitm_monitor.start_monitoring(
                duration=None,  # Continuous
                callback_new_url=self._on_new_url_captured,
                callback_device_update=self._on_device_update
            )
            
        except Exception as e:
            self.log(f"✗ MITM monitor error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
        finally:
            self.root.after(0, self._mitm_monitor_stopped)
    
    def stop_mitm_monitor(self):
        """Stop MITM browser monitoring"""
        self.log("⏹️ Stopping MITM Browser Monitor...", "INFO")
        
        if self.mitm_monitor:
            self.mitm_monitor.stop()
            self.mitm_monitor = None
        
        self._mitm_monitor_stopped()
    
    def _mitm_monitor_stopped(self):
        """Called when MITM monitor stops (UI updates)"""
        self.mitm_start_btn.config(state=tk.NORMAL)
        self.mitm_stop_btn.config(state=tk.DISABLED)
        self.mitm_status_label.config(text="Status: ⚫ Idle", fg='#888888')
        self.log("✓ MITM Browser Monitor stopped", "SUCCESS")
    
    def _on_new_url_captured(self, entry):
        """Callback when new URL is captured (called from monitor thread)"""
        # Not used in traffic view, but keep for compatibility
        pass
    
    def _on_device_update(self, mac, device_info):
        """Callback when device info is updated (called from monitor thread)"""
        # Update traffic display on main thread
        self.root.after(0, self._update_traffic_display)
    
    def _update_traffic_display(self):
        """Update the traffic display table (main thread only)"""
        if not self.mitm_monitor:
            return
        
        devices = self.mitm_monitor.get_devices()
        
        # Clear existing items
        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)
        
        # Add devices with traffic info
        total_upload = 0
        total_download = 0
        total_packets = 0
        
        for mac, device in devices.items():
            # Skip router and our own device
            if device.get('ip') in ['192.168.1.1', '192.168.0.1', self.mitm_monitor.my_ip]:
                continue
            
            traffic = device.get('traffic', {})
            upload_kb = traffic.get('bytes_sent', 0) / 1024
            download_kb = traffic.get('bytes_recv', 0) / 1024
            packets = traffic.get('packets', 0)
            
            total_upload += upload_kb
            total_download += download_kb
            total_packets += packets
            
            # Count connections (HTTP + HTTPS requests)
            connections = traffic.get('http_requests', 0) + traffic.get('https_requests', 0)
            
            # Last activity time
            last_seen = device.get('last_seen', '')
            if last_seen:
                try:
                    from datetime import datetime
                    last_time = datetime.fromisoformat(last_seen)
                    last_activity = last_time.strftime('%H:%M:%S')
                except:
                    last_activity = 'Unknown'
            else:
                last_activity = 'Unknown'
            
            # Device name
            device_name = device.get('hostname', 'Unknown')
            if device_name == 'Unknown':
                device_name = f"Device-{device.get('ip', '').split('.')[-1]}"
            
            # Add to tree
            self.traffic_tree.insert('', tk.END,
                                    values=(
                                        device_name,
                                        device.get('ip', 'Unknown'),
                                        mac,
                                        f"{upload_kb:.2f}",
                                        f"{download_kb:.2f}",
                                        packets,
                                        connections,
                                        last_activity
                                    ))
        
        # Update statistics
        self._update_mitm_stats(len(devices), total_packets, total_upload, total_download)
    
    def _update_mitm_stats(self, device_count=0, total_packets=0, upload_kb=0, download_kb=0):
        """Update MITM statistics display"""
        stats_text = f"Devices: {device_count} | Total Packets: {total_packets} | Upload: {upload_kb:.2f} KB | Download: {download_kb:.2f} KB"
        self.mitm_stats_label.config(text=stats_text)
    
    def clear_browsing_history(self):
        """Clear traffic display"""
        # Clear treeview
        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)
        
        # Reset monitor statistics if running
        if self.mitm_monitor:
            with self.mitm_monitor.device_lock:
                for mac in self.mitm_monitor.devices:
                    self.mitm_monitor.traffic_stats[mac] = {
                        'bytes_sent': 0,
                        'bytes_recv': 0,
                        'packets': 0,
                        'http_requests': 0,
                        'https_requests': 0,
                        'dns_queries': 0
                    }
        
        # Update stats
        self._update_mitm_stats(0, 0, 0, 0)
        
        self.log("🗑️ Traffic statistics cleared", "INFO")
    
    def export_browsing_history(self):
        """Export traffic data to JSON file"""
        if not self.mitm_monitor:
            messagebox.showwarning("No Data", "MITM monitor is not running. No data to export.")
            return
        
        devices = self.mitm_monitor.get_devices()
        
        if not devices:
            messagebox.showinfo("No Data", "No traffic data captured yet.")
            return
        
        # Calculate totals
        total_upload = sum(d.get('traffic', {}).get('bytes_sent', 0) for d in devices.values())
        total_download = sum(d.get('traffic', {}).get('bytes_recv', 0) for d in devices.values())
        total_packets = sum(d.get('traffic', {}).get('packets', 0) for d in devices.values())
        
        # Create export data
        export_data = {
            'export_time': datetime.now().isoformat(),
            'total_devices': len(devices),
            'total_upload_bytes': total_upload,
            'total_download_bytes': total_download,
            'total_packets': total_packets,
            'devices': devices
        }
        
        # Save to file
        filename = f"traffic_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.log(f"✓ Exported traffic data for {len(devices)} devices to {filename}", "SUCCESS")
            messagebox.showinfo("Export Successful", 
                              f"Traffic data exported to:\n{filename}\n\n"
                              f"Devices: {len(devices)}\n"
                              f"Total Upload: {total_upload/1024:.2f} KB\n"
                              f"Total Download: {total_download/1024:.2f} KB\n"
                              f"Total Packets: {total_packets}")
        except Exception as e:
            self.log(f"✗ Export failed: {e}", "ERROR")
            messagebox.showerror("Export Failed", f"Failed to export:\n{e}")
    
    def show_traffic_context_menu(self, event):
        """Show right-click context menu on traffic display"""
        # Get selected item
        item_id = self.traffic_tree.identify_row(event.y)
        if not item_id:
            return
        
        # Select the item
        self.traffic_tree.selection_set(item_id)
        
        # Create context menu
        menu = tk.Menu(self.root, tearoff=0, bg='#2b2b2b', fg='white',
                      activebackground='#0066cc', activeforeground='white')
        menu.add_command(label="📋 Copy MAC Address", command=self.copy_traffic_mac)
        menu.add_command(label="📋 Copy IP Address", command=self.copy_traffic_ip)
        menu.add_separator()
        menu.add_command(label="🚫 Block This Device", command=self.block_from_traffic)
        menu.add_command(label="🔄 Reset Traffic Stats", command=self.reset_device_stats)
        
        # Show menu
        menu.post(event.x_root, event.y_root)
    
    def copy_traffic_mac(self):
        """Copy MAC from traffic display to clipboard"""
        selection = self.traffic_tree.selection()
        if not selection:
            return
        
        item = self.traffic_tree.item(selection[0])
        mac = item['values'][2]  # MAC column
        
        self.root.clipboard_clear()
        self.root.clipboard_append(mac)
        self.log(f"📋 Copied MAC: {mac}", "INFO")
    
    def copy_traffic_ip(self):
        """Copy IP from traffic display to clipboard"""
        selection = self.traffic_tree.selection()
        if not selection:
            return
        
        item = self.traffic_tree.item(selection[0])
        ip = item['values'][1]  # IP column
        
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        self.log(f"📋 Copied IP: {ip}", "INFO")
    
    def reset_device_stats(self):
        """Reset traffic statistics for selected device"""
        selection = self.traffic_tree.selection()
        if not selection:
            return
        
        item = self.traffic_tree.item(selection[0])
        mac = item['values'][2]
        device_name = item['values'][0]
        
        if self.mitm_monitor:
            self.mitm_monitor.traffic_stats[mac] = {
                'bytes_sent': 0,
                'bytes_recv': 0,
                'packets': 0,
                'http_requests': 0,
                'https_requests': 0,
                'dns_queries': 0
            }
            self._update_traffic_display()
            self.log(f"🔄 Reset traffic stats for {device_name}", "INFO")
    
    def block_from_traffic(self):
        """Block device selected from traffic display"""
        selection = self.traffic_tree.selection()
        if not selection:
            return
        
        item = self.traffic_tree.item(selection[0])
        device_name = item['values'][0]
        device_ip = item['values'][1]
        device_mac = item['values'][2]
        
        # Check if router
        if device_ip in ['192.168.1.1', '192.168.0.1']:
            messagebox.showerror("Cannot Block", "Cannot block the router!")
            return
        
        # Confirm
        confirm = messagebox.askyesno("Confirm Block",
                                      f"Block this device?\n\n"
                                      f"Name: {device_name}\n"
                                      f"IP: {device_ip}\n"
                                      f"MAC: {device_mac}\n\n"
                                      f"This will disconnect the device from WiFi.")
        
        if confirm:
            self.log(f"🚫 Blocking {device_name} ({device_mac})...", "INFO")
            self.run_in_thread(self._block_device_thread, device_mac, device_name)


def main():
    root = tk.Tk()
    app = HybridRouterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
