#!/usr/bin/env python3
"""
Router Management GUI - Modern Interface for Complete Router Control
Uses Tkinter for cross-platform GUI
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
from router_manager import RouterManager
from datetime import datetime

class RouterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Router Management Center - China Telecom TG2212")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Router manager instance
        self.router = RouterManager()
        
        # Data storage
        self.connected_devices = []
        self.blocked_devices = []
        
        # Create UI
        self.create_widgets()
        
        # Run connection test on startup, then auto-refresh
        self.root.after(500, self.run_startup_test)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title = tk.Label(main_frame, text="🌐 Router Management Center", 
                        font=('Arial', 24, 'bold'), bg='#2b2b2b', fg='#00ff00')
        title.pack(pady=10)
        
        # Notebook (tabs)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2b2b2b', borderwidth=0)
        style.configure('TNotebook.Tab', background='#3b3b3b', foreground='white', 
                       padding=[20, 10], font=('Arial', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#00aa00')], 
                 foreground=[('selected', 'white')])
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Create tabs
        self.create_devices_tab()
        self.create_wifi_tab()
        self.create_security_tab()
        self.create_router_tab()
        self.create_log_tab()
        
    def create_devices_tab(self):
        """Tab 1: Device Management"""
        tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(tab, text='📱 Devices')
        
        # Top buttons
        btn_frame = tk.Frame(tab, bg='#2b2b2b')
        btn_frame.pack(fill=tk.X, pady=10, padx=10)
        
        tk.Button(btn_frame, text="🔄 Refresh Devices", command=self.refresh_devices,
                 bg='#00aa00', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="🚫 Block Selected", command=self.block_selected_device,
                 bg='#cc0000', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="✅ Unblock Selected", command=self.unblock_selected_device,
                 bg='#0066cc', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=10).pack(side=tk.LEFT, padx=5)
        
        # Device list
        list_frame = tk.Frame(tab, bg='#2b2b2b')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connected devices
        left_frame = tk.Frame(list_frame, bg='#2b2b2b')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        tk.Label(left_frame, text="Connected Devices", bg='#2b2b2b', fg='#00ff00',
                font=('Arial', 12, 'bold')).pack()
        
        self.devices_tree = ttk.Treeview(left_frame, columns=('Hostname', 'IP', 'MAC', 'Status'),
                                         show='tree headings', height=20)
        self.devices_tree.heading('Hostname', text='Device Name')
        self.devices_tree.heading('IP', text='IP Address')
        self.devices_tree.heading('MAC', text='MAC Address')
        self.devices_tree.heading('Status', text='Status')
        
        self.devices_tree.column('#0', width=50)
        self.devices_tree.column('Hostname', width=200)
        self.devices_tree.column('IP', width=150)
        self.devices_tree.column('MAC', width=150)
        self.devices_tree.column('Status', width=100)
        
        scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        self.devices_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Blocked devices
        right_frame = tk.Frame(list_frame, bg='#2b2b2b')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        tk.Label(right_frame, text="Blocked Devices", bg='#2b2b2b', fg='#ff0000',
                font=('Arial', 12, 'bold')).pack()
        
        self.blocked_tree = ttk.Treeview(right_frame, columns=('MAC',), show='tree headings', height=20)
        self.blocked_tree.heading('MAC', text='MAC Address')
        self.blocked_tree.column('#0', width=50)
        self.blocked_tree.column('MAC', width=300)
        
        scrollbar2 = ttk.Scrollbar(right_frame, orient=tk.VERTICAL, command=self.blocked_tree.yview)
        self.blocked_tree.configure(yscrollcommand=scrollbar2.set)
        self.blocked_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar2.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_wifi_tab(self):
        """Tab 2: WiFi Settings"""
        tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(tab, text='📶 WiFi')
        
        # Container
        container = tk.Frame(tab, bg='#3b3b3b', relief=tk.RAISED, borderwidth=2)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(container, text="WiFi Configuration", bg='#3b3b3b', fg='#00ff00',
                font=('Arial', 16, 'bold')).pack(pady=20)
        
        # Current settings
        settings_frame = tk.Frame(container, bg='#3b3b3b')
        settings_frame.pack(fill=tk.X, padx=40, pady=10)
        
        # SSID
        tk.Label(settings_frame, text="Network Name (SSID):", bg='#3b3b3b', fg='white',
                font=('Arial', 12)).grid(row=0, column=0, sticky='w', pady=10)
        self.ssid_var = tk.StringVar()
        self.ssid_entry = tk.Entry(settings_frame, textvariable=self.ssid_var, width=30,
                                   font=('Arial', 12))
        self.ssid_entry.grid(row=0, column=1, padx=10, pady=10)
        
        tk.Button(settings_frame, text="Change SSID", command=self.change_ssid,
                 bg='#0066cc', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=5).grid(row=0, column=2, padx=10)
        
        # Password
        tk.Label(settings_frame, text="WiFi Password:", bg='#3b3b3b', fg='white',
                font=('Arial', 12)).grid(row=1, column=0, sticky='w', pady=10)
        self.wifi_pass_var = tk.StringVar()
        self.wifi_pass_entry = tk.Entry(settings_frame, textvariable=self.wifi_pass_var, width=30,
                                        font=('Arial', 12), show='*')
        self.wifi_pass_entry.grid(row=1, column=1, padx=10, pady=10)
        
        tk.Button(settings_frame, text="Change Password", command=self.change_wifi_password,
                 bg='#0066cc', fg='white', font=('Arial', 10, 'bold'),
                 padx=15, pady=5).grid(row=1, column=2, padx=10)
        
        # Show password checkbox
        self.show_pass_var = tk.BooleanVar()
        tk.Checkbutton(settings_frame, text="Show Password", variable=self.show_pass_var,
                      bg='#3b3b3b', fg='white', selectcolor='#2b2b2b',
                      font=('Arial', 10), command=self.toggle_password).grid(row=2, column=1, sticky='w')
        
        # Refresh button
        tk.Button(container, text="🔄 Refresh WiFi Info", command=self.refresh_wifi,
                 bg='#00aa00', fg='white', font=('Arial', 12, 'bold'),
                 padx=30, pady=15).pack(pady=20)
        
        # WiFi info display
        info_frame = tk.Frame(container, bg='#2b2b2b', relief=tk.SUNKEN, borderwidth=2)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        self.wifi_info_text = scrolledtext.ScrolledText(info_frame, height=15, width=80,
                                                        bg='#1b1b1b', fg='#00ff00',
                                                        font=('Courier', 10))
        self.wifi_info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_security_tab(self):
        """Tab 3: Security & Firewall"""
        tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(tab, text='🔒 Security')
        
        container = tk.Frame(tab, bg='#3b3b3b', relief=tk.RAISED, borderwidth=2)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(container, text="Security & Firewall Settings", bg='#3b3b3b', fg='#00ff00',
                font=('Arial', 16, 'bold')).pack(pady=20)
        
        # MAC Filtering Section
        mac_frame = tk.LabelFrame(container, text="MAC Address Filtering", bg='#3b3b3b',
                                 fg='white', font=('Arial', 12, 'bold'), padx=20, pady=20)
        mac_frame.pack(fill=tk.X, padx=40, pady=10)
        
        tk.Label(mac_frame, text="Block device by MAC address:", bg='#3b3b3b', fg='white',
                font=('Arial', 11)).pack(anchor='w', pady=5)
        
        mac_input_frame = tk.Frame(mac_frame, bg='#3b3b3b')
        mac_input_frame.pack(fill=tk.X, pady=10)
        
        self.mac_block_var = tk.StringVar()
        tk.Entry(mac_input_frame, textvariable=self.mac_block_var, width=25,
                font=('Arial', 11)).pack(side=tk.LEFT, padx=5)
        
        tk.Label(mac_input_frame, text="(e.g., AA:BB:CC:DD:EE:FF)", bg='#3b3b3b',
                fg='#888888', font=('Arial', 9)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(mac_frame, text="🚫 Block This Device", command=self.block_by_mac,
                 bg='#cc0000', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=8).pack(pady=10)
        
        # Admin Password Section
        admin_frame = tk.LabelFrame(container, text="Admin Password", bg='#3b3b3b',
                                   fg='white', font=('Arial', 12, 'bold'), padx=20, pady=20)
        admin_frame.pack(fill=tk.X, padx=40, pady=10)
        
        tk.Label(admin_frame, text="Old Password:", bg='#3b3b3b', fg='white',
                font=('Arial', 11)).grid(row=0, column=0, sticky='w', pady=5)
        self.old_pass_var = tk.StringVar()
        tk.Entry(admin_frame, textvariable=self.old_pass_var, show='*', width=25,
                font=('Arial', 11)).grid(row=0, column=1, padx=10, pady=5)
        
        tk.Label(admin_frame, text="New Password:", bg='#3b3b3b', fg='white',
                font=('Arial', 11)).grid(row=1, column=0, sticky='w', pady=5)
        self.new_pass_var = tk.StringVar()
        tk.Entry(admin_frame, textvariable=self.new_pass_var, show='*', width=25,
                font=('Arial', 11)).grid(row=1, column=1, padx=10, pady=5)
        
        tk.Label(admin_frame, text="Confirm Password:", bg='#3b3b3b', fg='white',
                font=('Arial', 11)).grid(row=2, column=0, sticky='w', pady=5)
        self.confirm_pass_var = tk.StringVar()
        tk.Entry(admin_frame, textvariable=self.confirm_pass_var, show='*', width=25,
                font=('Arial', 11)).grid(row=2, column=1, padx=10, pady=5)
        
        tk.Button(admin_frame, text="🔑 Change Admin Password", command=self.change_admin_password,
                 bg='#cc6600', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=8).grid(row=3, column=0, columnspan=2, pady=15)
    
    def create_router_tab(self):
        """Tab 4: Router Information & Control"""
        tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(tab, text='⚙️ Router')
        
        container = tk.Frame(tab, bg='#3b3b3b', relief=tk.RAISED, borderwidth=2)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(container, text="Router Information & Control", bg='#3b3b3b', fg='#00ff00',
                font=('Arial', 16, 'bold')).pack(pady=20)
        
        # Router info display
        info_frame = tk.Frame(container, bg='#2b2b2b', relief=tk.SUNKEN, borderwidth=2)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        self.router_info_text = scrolledtext.ScrolledText(info_frame, height=20, width=80,
                                                          bg='#1b1b1b', fg='#00ff00',
                                                          font=('Courier', 11))
        self.router_info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control buttons
        btn_frame = tk.Frame(container, bg='#3b3b3b')
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="🔄 Refresh Info", command=self.refresh_router_info,
                 bg='#00aa00', fg='white', font=('Arial', 12, 'bold'),
                 padx=30, pady=15).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame, text="🔌 Reboot Router", command=self.reboot_router,
                 bg='#cc0000', fg='white', font=('Arial', 12, 'bold'),
                 padx=30, pady=15).pack(side=tk.LEFT, padx=10)
    
    def create_log_tab(self):
        """Tab 5: Activity Log"""
        tab = tk.Frame(self.notebook, bg='#2b2b2b')
        self.notebook.add(tab, text='📋 Logs')
        
        container = tk.Frame(tab, bg='#3b3b3b', relief=tk.RAISED, borderwidth=2)
        container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(container, text="Activity Log", bg='#3b3b3b', fg='#00ff00',
                font=('Arial', 16, 'bold')).pack(pady=20)
        
        # Log display
        log_frame = tk.Frame(container, bg='#2b2b2b', relief=tk.SUNKEN, borderwidth=2)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=30, width=100,
                                                  bg='#1b1b1b', fg='#00ff00',
                                                  font=('Courier', 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Clear button
        tk.Button(container, text="🗑️ Clear Log", command=self.clear_log,
                 bg='#666666', fg='white', font=('Arial', 10, 'bold'),
                 padx=20, pady=10).pack(pady=10)
    
    # ========== HELPER METHODS ==========
    
    def log(self, message, level="INFO"):
        """Add message to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
    
    def clear_log(self):
        """Clear the log"""
        self.log_text.delete(1.0, tk.END)
        self.log("Log cleared", "INFO")
    
    def run_in_thread(self, func, *args):
        """Run function in background thread"""
        thread = threading.Thread(target=func, args=args, daemon=True)
        thread.start()
    
    # ========== DEVICE MANAGEMENT ==========
    
    def refresh_devices(self):
        """Refresh device lists"""
        self.log("Refreshing device list...", "INFO")
        self.run_in_thread(self._refresh_devices_thread)
    
    def _refresh_devices_thread(self):
        """Background thread for refreshing devices"""
        # Get connected devices
        success, devices = self.router.get_connected_devices()
        if success:
            self.connected_devices = devices
            self.root.after(0, self._update_device_tree)
            self.log(f"Found {len(devices)} connected device(s)", "SUCCESS")
        else:
            self.log("Failed to get connected devices", "ERROR")
        
        # Get blocked devices
        success, blocked = self.router.get_mac_filter_list()
        if success:
            self.blocked_devices = blocked
            self.root.after(0, self._update_blocked_tree)
            self.log(f"Found {len(blocked)} blocked device(s)", "SUCCESS")
        else:
            self.log("Failed to get blocked devices list", "ERROR")
    
    def _update_device_tree(self):
        """Update device treeview (must run in main thread)"""
        self.devices_tree.delete(*self.devices_tree.get_children())
        for i, device in enumerate(self.connected_devices, 1):
            status = "Active" if device['active'] else "Inactive"
            self.devices_tree.insert('', tk.END, text=str(i),
                                    values=(device['hostname'], device['ip'], 
                                           device['mac'], status))
    
    def _update_blocked_tree(self):
        """Update blocked devices treeview (must run in main thread)"""
        self.blocked_tree.delete(*self.blocked_tree.get_children())
        for i, device in enumerate(self.blocked_devices, 1):
            self.blocked_tree.insert('', tk.END, text=str(i),
                                    values=(device['mac'],))
    
    def block_selected_device(self):
        """Block the selected device"""
        selection = self.devices_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to block")
            return
        
        item = self.devices_tree.item(selection[0])
        mac = item['values'][2]  # MAC is 3rd column
        hostname = item['values'][0]
        
        confirm = messagebox.askyesno("Confirm Block", 
                                      f"Block device '{hostname}' ({mac})?")
        if confirm:
            self.log(f"Blocking device {mac}...", "INFO")
            self.run_in_thread(self._block_device_thread, mac)
    
    def _block_device_thread(self, mac):
        """Background thread for blocking device"""
        success, msg = self.router.block_device(mac)
        if success:
            self.log(msg, "SUCCESS")
            messagebox.showinfo("Success", msg)
            self.root.after(1000, self.refresh_devices)
        else:
            self.log(msg, "ERROR")
            messagebox.showerror("Error", msg)
    
    def unblock_selected_device(self):
        """Unblock the selected device"""
        selection = self.blocked_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a blocked device to unblock")
            return
        
        item = self.blocked_tree.item(selection[0])
        mac = item['values'][0]
        
        confirm = messagebox.askyesno("Confirm Unblock", 
                                      f"Unblock device {mac}?")
        if confirm:
            self.log(f"Unblocking device {mac}...", "INFO")
            self.run_in_thread(self._unblock_device_thread, mac)
    
    def _unblock_device_thread(self, mac):
        """Background thread for unblocking device"""
        success, msg = self.router.unblock_device(mac)
        if success:
            self.log(msg, "SUCCESS")
            messagebox.showinfo("Success", msg)
            self.root.after(1000, self.refresh_devices)
        else:
            self.log(msg, "ERROR")
            messagebox.showerror("Error", msg)
    
    def block_by_mac(self):
        """Block device by manually entered MAC"""
        mac = self.mac_block_var.get().strip()
        if not mac:
            messagebox.showwarning("Empty MAC", "Please enter a MAC address")
            return
        
        confirm = messagebox.askyesno("Confirm Block", f"Block device {mac}?")
        if confirm:
            self.log(f"Blocking device {mac}...", "INFO")
            self.run_in_thread(self._block_device_thread, mac)
            self.mac_block_var.set("")
    
    # ========== WIFI MANAGEMENT ==========
    
    def refresh_wifi(self):
        """Refresh WiFi information"""
        self.log("Refreshing WiFi settings...", "INFO")
        self.run_in_thread(self._refresh_wifi_thread)
    
    def _refresh_wifi_thread(self):
        """Background thread for refreshing WiFi"""
        # Get WiFi settings
        success, wifi = self.router.get_wifi_settings()
        if success:
            self.root.after(0, lambda: self.ssid_var.set(wifi['ssid']))
            
            info = f"""
╔══════════════════════════════════════════════════════════╗
║              WiFi Network Information                    ║
╚══════════════════════════════════════════════════════════╝

Network Name (SSID):      {wifi['ssid']}
Hidden Network:           {wifi['ssid_hidden']}
Channel:                  {wifi['channel']}
WiFi Mode:                {wifi['mode']}
Security Mode:            {wifi['security_mode']}
Encryption:               {wifi['encryption']}
WiFi Enabled:             {wifi['enabled']}
"""
            self.root.after(0, lambda: self._display_wifi_info(info))
            self.log("WiFi settings retrieved", "SUCCESS")
        else:
            self.log("Failed to get WiFi settings", "ERROR")
        
        # Get WiFi password
        success, password = self.router.get_wifi_password()
        if success:
            self.root.after(0, lambda: self.wifi_pass_var.set(password))
            self.log("WiFi password retrieved", "SUCCESS")
        else:
            self.log("Failed to get WiFi password", "ERROR")
    
    def _display_wifi_info(self, info):
        """Display WiFi info in text widget"""
        self.wifi_info_text.delete(1.0, tk.END)
        self.wifi_info_text.insert(1.0, info)
    
    def toggle_password(self):
        """Toggle password visibility"""
        if self.show_pass_var.get():
            self.wifi_pass_entry.config(show='')
        else:
            self.wifi_pass_entry.config(show='*')
    
    def change_ssid(self):
        """Change WiFi SSID"""
        new_ssid = self.ssid_var.get().strip()
        if not new_ssid:
            messagebox.showwarning("Empty SSID", "Please enter a new SSID")
            return
        
        confirm = messagebox.askyesno("Confirm Change", 
                                      f"Change WiFi name to '{new_ssid}'?\n\n"
                                      "You may need to reconnect to the network.")
        if confirm:
            self.log(f"Changing SSID to '{new_ssid}'...", "INFO")
            self.run_in_thread(self._change_ssid_thread, new_ssid)
    
    def _change_ssid_thread(self, new_ssid):
        """Background thread for changing SSID"""
        success, msg = self.router.set_wifi_ssid(new_ssid)
        if success:
            self.log(msg, "SUCCESS")
            messagebox.showinfo("Success", msg + "\n\nReconnect to the new network name.")
        else:
            self.log(msg, "ERROR")
            messagebox.showerror("Error", msg)
    
    def change_wifi_password(self):
        """Change WiFi password"""
        new_password = self.wifi_pass_var.get().strip()
        if not new_password:
            messagebox.showwarning("Empty Password", "Please enter a new password")
            return
        
        if len(new_password) < 8:
            messagebox.showwarning("Weak Password", "Password must be at least 8 characters")
            return
        
        confirm = messagebox.askyesno("Confirm Change", 
                                      "Change WiFi password?\n\n"
                                      "All devices will be disconnected.")
        if confirm:
            self.log("Changing WiFi password...", "INFO")
            self.run_in_thread(self._change_wifi_password_thread, new_password)
    
    def _change_wifi_password_thread(self, new_password):
        """Background thread for changing WiFi password"""
        success, msg = self.router.set_wifi_password(new_password)
        if success:
            self.log(msg, "SUCCESS")
            messagebox.showinfo("Success", msg + "\n\nReconnect with the new password.")
        else:
            self.log(msg, "ERROR")
            messagebox.showerror("Error", msg)
    
    # ========== SECURITY ==========
    
    def change_admin_password(self):
        """Change router admin password"""
        old_pass = self.old_pass_var.get()
        new_pass = self.new_pass_var.get()
        confirm_pass = self.confirm_pass_var.get()
        
        if not all([old_pass, new_pass, confirm_pass]):
            messagebox.showwarning("Missing Fields", "Please fill all password fields")
            return
        
        if new_pass != confirm_pass:
            messagebox.showwarning("Password Mismatch", "New passwords don't match")
            return
        
        if len(new_pass) < 8:
            messagebox.showwarning("Weak Password", "Password must be at least 8 characters")
            return
        
        confirm = messagebox.askyesno("Confirm Change", 
                                      "Change router admin password?")
        if confirm:
            self.log("Changing admin password...", "INFO")
            self.run_in_thread(self._change_admin_password_thread, old_pass, new_pass)
    
    def _change_admin_password_thread(self, old_pass, new_pass):
        """Background thread for changing admin password"""
        success, msg = self.router.change_admin_password(old_pass, new_pass)
        if success:
            self.log(msg, "SUCCESS")
            messagebox.showinfo("Success", msg)
            # Clear fields
            self.root.after(0, lambda: [self.old_pass_var.set(""),
                                       self.new_pass_var.set(""),
                                       self.confirm_pass_var.set("")])
        else:
            self.log(msg, "ERROR")
            messagebox.showerror("Error", msg)
    
    # ========== ROUTER CONTROL ==========
    
    def refresh_router_info(self):
        """Refresh router information"""
        self.log("Refreshing router info...", "INFO")
        self.run_in_thread(self._refresh_router_info_thread)
    
    def _refresh_router_info_thread(self):
        """Background thread for refreshing router info"""
        success, info = self.router.get_router_info()
        if success:
            router_info = f"""
╔══════════════════════════════════════════════════════════╗
║           Router System Information                      ║
╚══════════════════════════════════════════════════════════╝

Model:                    {info['model']}
Firmware Version:         {info['firmware']}
Hardware Version:         {info['hardware']}
System Uptime:            {info['uptime']}

WAN IP Address:           {info['wan_ip']}
LAN IP Address:           {info['lan_ip']}
Router MAC Address:       {info['mac']}

╔══════════════════════════════════════════════════════════╗
║           Connection Information                         ║
╚══════════════════════════════════════════════════════════╝

Status:                   Connected
Access:                   Full Access Granted
Last Update:              {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
            self.root.after(0, lambda: self._display_router_info(router_info))
            self.log("Router info retrieved successfully", "SUCCESS")
        else:
            self.log("Failed to get router info", "ERROR")
    
    def _display_router_info(self, info):
        """Display router info in text widget"""
        self.router_info_text.delete(1.0, tk.END)
        self.router_info_text.insert(1.0, info)
    
    def reboot_router(self):
        """Reboot the router"""
        confirm = messagebox.askyesno("Confirm Reboot", 
                                      "Reboot the router?\n\n"
                                      "Internet will be unavailable for 1-2 minutes.")
        if confirm:
            self.log("Rebooting router...", "INFO")
            self.run_in_thread(self._reboot_router_thread)
    
    def _reboot_router_thread(self):
        """Background thread for rebooting router"""
        success, msg = self.router.reboot_router()
        if success:
            self.log(msg, "SUCCESS")
            messagebox.showinfo("Rebooting", msg)
        else:
            self.log(msg, "ERROR")
            messagebox.showerror("Error", msg)
    
    def refresh_all(self):
        """Refresh all information"""
        self.log("Starting full refresh...", "INFO")
        self.refresh_devices()
        self.refresh_wifi()
        self.refresh_router_info()
    
    def run_startup_test(self):
        """Run connection test on startup"""
        self.log("="*60, "INFO")
        self.log("ROUTER CONNECTION TEST - Starting...", "INFO")
        self.log("="*60, "INFO")
        self.run_in_thread(self._startup_test_thread)
    
    def _startup_test_thread(self):
        """Background thread for startup connection test"""
        test_results = []
        
        # Test 1: Router info
        self.log("[Test 1/4] Checking router connection...", "INFO")
        success, info = self.router.get_router_info()
        if success:
            self.log(f"✓ SUCCESS - Router: {info.get('model', 'Unknown')}", "SUCCESS")
            self.log(f"  Firmware: {info.get('firmware', 'N/A')}", "INFO")
            test_results.append(True)
        else:
            self.log("✗ FAILED - Cannot connect to router", "ERROR")
            self.log(f"  Error: {info}", "ERROR")
            test_results.append(False)
        
        # Test 2: WiFi settings
        self.log("[Test 2/4] Checking WiFi settings access...", "INFO")
        success, wifi = self.router.get_wifi_settings()
        if success:
            self.log(f"✓ SUCCESS - WiFi SSID: {wifi.get('ssid', 'Unknown')}", "SUCCESS")
            test_results.append(True)
        else:
            self.log("✗ FAILED - Cannot access WiFi settings", "ERROR")
            test_results.append(False)
        
        # Test 3: Connected devices
        self.log("[Test 3/4] Checking device list access...", "INFO")
        success, devices = self.router.get_connected_devices()
        if success:
            self.log(f"✓ SUCCESS - Found {len(devices)} connected device(s)", "SUCCESS")
            test_results.append(True)
        else:
            self.log("✗ FAILED - Cannot get device list", "ERROR")
            test_results.append(False)
        
        # Test 4: MAC filter list
        self.log("[Test 4/4] Checking MAC filter access...", "INFO")
        success, blocked = self.router.get_mac_filter_list()
        if success:
            self.log(f"✓ SUCCESS - Found {len(blocked)} blocked device(s)", "SUCCESS")
            test_results.append(True)
        else:
            self.log("✗ FAILED - Cannot access MAC filter list", "ERROR")
            test_results.append(False)
        
        # Summary
        passed = sum(test_results)
        total = len(test_results)
        
        self.log("="*60, "INFO")
        if passed == total:
            self.log(f"CONNECTION TEST COMPLETE - ALL TESTS PASSED ({passed}/{total})", "SUCCESS")
            self.log("✓ Full router access confirmed!", "SUCCESS")
            self.log("="*60, "INFO")
            self.log("Loading router data...", "INFO")
            # Auto-refresh after successful test
            self.root.after(1000, self.refresh_all)
        else:
            self.log(f"CONNECTION TEST COMPLETE - {passed}/{total} TESTS PASSED", "ERROR")
            self.log("⚠ Some features may not work correctly", "ERROR")
            self.log("="*60, "INFO")
            self.log("Check your router connection and credentials", "ERROR")
            # Show error message to user
            self.root.after(0, lambda: messagebox.showwarning(
                "Connection Test Failed",
                f"Connection test: {passed}/{total} tests passed\n\n"
                "Some router features may not be accessible.\n\n"
                "Please check:\n"
                "• Router IP address is correct (192.168.1.1)\n"
                "• You are connected to the router's WiFi\n"
                "• Username and password are correct\n\n"
                "See the Logs tab for details."
            ))


def main():
    """Main entry point"""
    root = tk.Tk()
    app = RouterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

