#!/usr/bin/env python3
"""
Device Manager GUI - Manually identify unknown devices
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json

class DeviceManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Known Device Manager")
        self.root.geometry("700x500")
        
        self.known_devices = self.load_devices()
        
        self.create_widgets()
        self.refresh_list()
    
    def load_devices(self):
        """Load known devices from JSON"""
        try:
            with open('known_devices.json', 'r') as f:
                data = json.load(f)
                return data.get('devices', {})
        except:
            return {}
    
    def save_devices(self):
        """Save known devices to JSON"""
        data = {
            'comment': 'Manual device database for devices with randomized/unknown MACs',
            'devices': self.known_devices
        }
        with open('known_devices.json', 'w') as f:
            json.dump(data, f, indent=2)
    
    def create_widgets(self):
        """Create GUI widgets"""
        
        # Title
        title = tk.Label(self.root, text="Known Device Manager", 
                        font=('Arial', 16, 'bold'))
        title.pack(pady=10)
        
        # Device list
        list_frame = tk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.device_tree = ttk.Treeview(list_frame, 
                                       columns=('MAC', 'Name', 'Type', 'OS'),
                                       show='headings', 
                                       yscrollcommand=scrollbar.set)
        
        self.device_tree.heading('MAC', text='MAC Address')
        self.device_tree.heading('Name', text='Device Name')
        self.device_tree.heading('Type', text='Type')
        self.device_tree.heading('OS', text='OS')
        
        self.device_tree.column('MAC', width=150)
        self.device_tree.column('Name', width=200)
        self.device_tree.column('Type', width=150)
        self.device_tree.column('OS', width=100)
        
        self.device_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.device_tree.yview)
        
        # Add/Edit form
        form_frame = tk.LabelFrame(self.root, text="Add/Edit Device", padx=10, pady=10)
        form_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(form_frame, text="MAC Address:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.mac_entry = tk.Entry(form_frame, width=20)
        self.mac_entry.grid(row=0, column=1, pady=2)
        
        tk.Label(form_frame, text="Device Name:").grid(row=0, column=2, sticky=tk.W, padx=(20,0), pady=2)
        self.name_entry = tk.Entry(form_frame, width=25)
        self.name_entry.grid(row=0, column=3, pady=2)
        
        tk.Label(form_frame, text="Type:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.type_entry = tk.Entry(form_frame, width=20)
        self.type_entry.grid(row=1, column=1, pady=2)
        
        tk.Label(form_frame, text="OS:").grid(row=1, column=2, sticky=tk.W, padx=(20,0), pady=2)
        self.os_entry = tk.Entry(form_frame, width=25)
        self.os_entry.grid(row=1, column=3, pady=2)
        
        # Buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Add Device", command=self.add_device,
                 bg='#28a745', fg='white', padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Update Selected", command=self.update_device,
                 bg='#007bff', fg='white', padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Delete Selected", command=self.delete_device,
                 bg='#dc3545', fg='white', padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Load from Scan", command=self.load_from_scan,
                 bg='#17a2b8', fg='white', padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        # Bind selection
        self.device_tree.bind('<<TreeviewSelect>>', self.on_select)
    
    def refresh_list(self):
        """Refresh device list"""
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        for mac, info in self.known_devices.items():
            self.device_tree.insert('', 'end', values=(
                mac,
                info.get('name', 'Unknown'),
                info.get('type', 'Unknown'),
                info.get('os', 'Unknown')
            ))
    
    def on_select(self, event):
        """Handle device selection"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            values = item['values']
            
            self.mac_entry.delete(0, tk.END)
            self.mac_entry.insert(0, values[0])
            
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, values[1])
            
            self.type_entry.delete(0, tk.END)
            self.type_entry.insert(0, values[2])
            
            self.os_entry.delete(0, tk.END)
            self.os_entry.insert(0, values[3])
    
    def add_device(self):
        """Add new device"""
        mac = self.mac_entry.get().strip().upper()
        name = self.name_entry.get().strip()
        
        if not mac or not name:
            messagebox.showwarning("Invalid Input", "MAC and Name are required!")
            return
        
        self.known_devices[mac] = {
            'name': name,
            'type': self.type_entry.get().strip() or 'Unknown',
            'os': self.os_entry.get().strip() or 'Unknown',
            'notes': 'Manually added'
        }
        
        self.save_devices()
        self.refresh_list()
        messagebox.showinfo("Success", f"Device {name} added!")
        
        # Clear form
        self.mac_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        self.type_entry.delete(0, tk.END)
        self.os_entry.delete(0, tk.END)
    
    def update_device(self):
        """Update selected device"""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to update!")
            return
        
        mac = self.mac_entry.get().strip().upper()
        name = self.name_entry.get().strip()
        
        if mac in self.known_devices:
            self.known_devices[mac] = {
                'name': name,
                'type': self.type_entry.get().strip() or 'Unknown',
                'os': self.os_entry.get().strip() or 'Unknown',
                'notes': 'Manually updated'
            }
            
            self.save_devices()
            self.refresh_list()
            messagebox.showinfo("Success", f"Device {name} updated!")
    
    def delete_device(self):
        """Delete selected device"""
        selection = self.device_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to delete!")
            return
        
        item = self.device_tree.item(selection[0])
        mac = item['values'][0]
        
        if messagebox.askyesno("Confirm Delete", f"Delete device {mac}?"):
            del self.known_devices[mac]
            self.save_devices()
            self.refresh_list()
            messagebox.showinfo("Success", "Device deleted!")
    
    def load_from_scan(self):
        """Load unknown devices from last scan"""
        try:
            import subprocess
            result = subprocess.run(['device_scanner.exe'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                devices = json.loads(result.stdout)
                
                unknown_count = 0
                for device in devices:
                    mac = device['mac'].upper()
                    manufacturer = device.get('manufacturer', 'Unknown')
                    
                    # Only add truly unknown devices
                    if manufacturer == 'Unknown' and mac not in self.known_devices:
                        self.known_devices[mac] = {
                            'name': f"Device {device['ip'].split('.')[-1]}",
                            'type': 'Network Device',
                            'os': 'Unknown',
                            'notes': 'Auto-added from scan - Please update with real name'
                        }
                        unknown_count += 1
                
                if unknown_count > 0:
                    self.save_devices()
                    self.refresh_list()
                    messagebox.showinfo("Success", f"Added {unknown_count} unknown device(s)!\n\nPlease update with real names.")
                else:
                    messagebox.showinfo("Info", "No new unknown devices found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = DeviceManagerGUI(root)
    root.mainloop()
