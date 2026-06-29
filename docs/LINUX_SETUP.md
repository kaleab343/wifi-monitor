# NetWatch Pro - Linux Setup Guide

Complete guide for installing and running NetWatch Pro on Linux systems.

## 📋 Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Desktop Integration](#desktop-integration)
- [Troubleshooting](#troubleshooting)

## 🖥️ System Requirements

- **OS**: Linux (any distribution)
- **Python**: 3.7 or higher
- **Network**: WiFi or Ethernet connection
- **Privileges**: Root access for MITM features (optional)

### Tested Distributions

✅ Ubuntu 20.04+
✅ Debian 11+
✅ Fedora 35+
✅ Arch Linux
✅ Linux Mint 20+
✅ Pop!_OS 21.04+

## 📦 Installation

### Debian/Ubuntu/Mint

```bash
# Update package list
sudo apt-get update

# Install system dependencies
sudo apt-get install -y python3 python3-pip python3-tk

# Optional: For MITM features
sudo apt-get install -y libpcap-dev python3-scapy

# Navigate to project directory
cd /path/to/wifi-monitor

# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh
chmod +x launch.py
```

### Fedora/RHEL/CentOS

```bash
# Install system dependencies
sudo dnf install -y python3 python3-pip python3-tkinter

# Optional: For MITM features
sudo dnf install -y libpcap-devel python3-scapy

# Navigate to project directory
cd /path/to/wifi-monitor

# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh
chmod +x launch.py
```

### Arch Linux/Manjaro

```bash
# Install system dependencies
sudo pacman -S python python-pip tk

# Optional: For MITM features
sudo pacman -S libpcap python-scapy

# Navigate to project directory
cd /path/to/wifi-monitor

# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh
chmod +x launch.py
```

### Quick Setup Script

You can use the provided setup script:

```bash
cd scripts
./setup_mitm_scanner.sh
```

This will automatically detect your distribution and install dependencies.

## 🚀 Running the Application

### Method 1: Cross-Platform Launcher (Recommended)

```bash
# Normal mode (basic scanning)
python3 launch.py

# Root mode (full features including MITM)
sudo python3 launch.py
```

### Method 2: Shell Scripts

```bash
# Normal mode
./scripts/launch_wifi_monitor.sh

# Root mode with auto-elevation
./scripts/launch_wifi_monitor_admin.sh
```

### Method 3: Direct Python

```bash
# Normal mode
python3 run.py

# Root mode
sudo python3 run.py
```

## 🔐 Privilege Management

### Why Root Access?

Root privileges are required for:
- **MITM Passive Scanning** - Deep packet inspection
- **Traffic Monitoring** - Real-time traffic analysis
- **Raw Socket Access** - Low-level network operations

Basic device scanning works without root.

### Running Without Root

```bash
# Basic scanning (no MITM)
python3 launch.py
```

### Running With Root

```bash
# Full features
sudo python3 launch.py
```

### Using Capabilities (More Secure)

Instead of running as root, grant specific capabilities:

```bash
# Grant network capabilities to Python
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Now run without sudo
python3 launch.py
```

**Warning**: This affects all Python scripts on your system. Remove with:
```bash
sudo setcap -r $(which python3)
```

## 🖥️ Desktop Integration

### Create Desktop Shortcut

1. Copy the desktop entry:
```bash
cp assets/NetWatchPro.desktop ~/.local/share/applications/
```

2. Edit the file to set correct paths:
```bash
nano ~/.local/share/applications/NetWatchPro.desktop
```

3. Update these lines:
```
Exec=/full/path/to/wifi-monitor/launch.py
Icon=/full/path/to/wifi-monitor/assets/app_icon.png
```

4. Make it executable:
```bash
chmod +x ~/.local/share/applications/NetWatchPro.desktop
```

### Create Desktop Icon (Ubuntu/GNOME)

```bash
# Copy to desktop
cp ~/.local/share/applications/NetWatchPro.desktop ~/Desktop/

# Make executable
chmod +x ~/Desktop/NetWatchPro.desktop

# Trust the launcher (GNOME)
gio set ~/Desktop/NetWatchPro.desktop metadata::trusted true
```

### Create Application Menu Entry (All Desktop Environments)

After copying to `~/.local/share/applications/`, the app will appear in your application menu automatically.

### Create Root-Enabled Launcher

For MITM features, create a separate launcher with sudo:

```bash
nano ~/.local/share/applications/NetWatchPro-Root.desktop
```

Content:
```
[Desktop Entry]
Version=2.0
Type=Application
Name=NetWatch Pro (Root)
Comment=WiFi Monitor with MITM Features
Exec=pkexec python3 /full/path/to/wifi-monitor/launch.py
Icon=/full/path/to/wifi-monitor/assets/app_icon.png
Terminal=false
Categories=Network;System;Monitor;
```

## 🔧 Troubleshooting

### "ModuleNotFoundError: No module named 'tkinter'"

```bash
# Debian/Ubuntu
sudo apt-get install python3-tk

# Fedora/RHEL
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

### "Permission denied" when running scripts

```bash
# Make scripts executable
chmod +x scripts/*.sh
chmod +x launch.py
```

### "Scapy not found" or MITM features not working

```bash
# Install scapy and libpcap
# Debian/Ubuntu
sudo apt-get install python3-scapy libpcap-dev

# Fedora
sudo dnf install python3-scapy libpcap-devel

# Arch
sudo pacman -S python-scapy libpcap

# Or via pip
pip3 install scapy
```

### "Operation not permitted" during network scanning

You need root privileges:
```bash
sudo python3 launch.py
```

### GUI doesn't appear or crashes

```bash
# Check if DISPLAY is set
echo $DISPLAY

# If empty, set it
export DISPLAY=:0

# Try running again
python3 launch.py
```

### Network interface not found

```bash
# List available interfaces
ip link show

# Or
ifconfig

# Note the name (e.g., wlan0, eth0, enp3s0)
# The app will auto-detect, but you can set it manually in the code
```

### Firewall blocking network scanning

```bash
# Temporarily disable firewall (Ubuntu/Debian)
sudo ufw disable

# Re-enable after scanning
sudo ufw enable

# Or allow specific operations
sudo ufw allow from 192.168.1.0/24
```

## 📝 Configuration

### Router Settings

Edit `src/utils/router_manager.py`:

```python
self.router_ip = "192.168.1.1"    # Your router IP
self.username = "admin"            # Router username
self.password = "password"         # Router password
```

### Network Interface

Most Linux distributions use predictable network interface names:
- `wlan0`, `wlan1` - Wireless interfaces
- `eth0`, `eth1` - Ethernet interfaces
- `enp3s0`, `wlp2s0` - Systemd predictable names

The application will auto-detect your active interface.

## 🐛 Known Issues

### Issue: Scapy on Python 3.11+

Some distributions have compatibility issues with Scapy on Python 3.11+.

**Solution**:
```bash
pip3 install --upgrade scapy
```

### Issue: Wayland Session

Some features may not work properly on Wayland.

**Solution**: Use X11 session or enable X11 compatibility:
```bash
# Force X11
export GDK_BACKEND=x11
python3 launch.py
```

### Issue: Virtual Environments

If using a virtual environment, tkinter may not be available.

**Solution**:
```bash
# Create venv with system packages
python3 -m venv --system-site-packages venv
source venv/bin/activate
```

## 🔗 Additional Resources

- [Main Documentation](README.md)
- [Blocking Guide](docs/BLOCKING_STATUS.md)
- [Troubleshooting](docs/WHY_BLOCKING_DOESNT_WORK.md)

## 💡 Tips

### Running at Startup

Create a systemd service:

```bash
sudo nano /etc/systemd/system/netwatchpro.service
```

Content:
```
[Unit]
Description=NetWatch Pro WiFi Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/wifi-monitor
ExecStart=/usr/bin/python3 /path/to/wifi-monitor/launch.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable netwatchpro
sudo systemctl start netwatchpro
```

### Creating an Alias

Add to `~/.bashrc` or `~/.zshrc`:

```bash
alias netwatchpro='python3 /path/to/wifi-monitor/launch.py'
alias netwatchpro-root='sudo python3 /path/to/wifi-monitor/launch.py'
```

Reload:
```bash
source ~/.bashrc
```

Now run with:
```bash
netwatchpro
netwatchpro-root
```

## 🆘 Support

If you encounter issues:
1. Check this guide's troubleshooting section
2. Review the main README.md
3. Check logs in the GUI activity log
4. Open an issue on GitHub with:
   - Linux distribution and version
   - Python version (`python3 --version`)
   - Error messages
   - Steps to reproduce

---

**Version**: 2.0  
**Platform**: Linux (All Distributions)  
**Last Updated**: June 29, 2026
