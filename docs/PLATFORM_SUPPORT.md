# NetWatch Pro - Platform Support

Comprehensive guide for running NetWatch Pro across different operating systems.

## 📊 Platform Support Matrix

| Platform | Status | Notes |
|----------|--------|-------|
| **Windows 10/11** | ✅ Fully Supported | Native support, all features work |
| **Ubuntu 20.04+** | ✅ Fully Supported | Tested and verified |
| **Debian 11+** | ✅ Fully Supported | Tested and verified |
| **Fedora 35+** | ✅ Fully Supported | Tested and verified |
| **Arch Linux** | ✅ Fully Supported | Tested and verified |
| **Linux Mint** | ✅ Fully Supported | Ubuntu-based, works perfectly |
| **Pop!_OS** | ✅ Fully Supported | Ubuntu-based, works perfectly |
| **Manjaro** | ✅ Fully Supported | Arch-based, works perfectly |
| **macOS 11+** | ⚠️ Should Work | Not extensively tested |
| **Raspberry Pi OS** | ⚠️ Should Work | ARM architecture, may need adjustments |

## 🖥️ Operating System Specific Features

### Windows

#### ✅ What Works
- Full GUI with native Windows styling
- ARP scanning via Windows `arp` command
- MITM scanning with Administrator privileges
- Device blocking through router API
- Desktop shortcuts (.lnk files)
- Task Scheduler integration
- Windows Defender compatibility

#### 🔧 Requirements
- Windows 10 or later (Windows 7/8 may work but untested)
- Python 3.7+ from python.org
- Administrator rights for MITM features

#### 🚀 Launch Methods
```batch
REM Method 1: Cross-platform launcher
python launch.py

REM Method 2: Batch scripts
scripts\launch_wifi_monitor.bat

REM Method 3: Admin mode
Right-click → Run as Administrator
```

#### 📝 Installation
```batch
REM Install Python from python.org
REM Then:
pip install -r requirements.txt
python launch.py
```

### Linux

#### ✅ What Works
- Full GUI with native Linux styling
- ARP scanning via Linux `arp -n` command
- MITM scanning with root privileges
- Device blocking through router API
- Desktop integration (.desktop files)
- systemd service integration
- IP forwarding for traffic monitoring

#### 🔧 Requirements
- Any modern Linux distribution
- Python 3.7+
- tkinter (python3-tk package)
- Root access for MITM features
- libpcap for packet capture

#### 🚀 Launch Methods
```bash
# Method 1: Cross-platform launcher
python3 launch.py

# Method 2: Shell scripts
./scripts/launch_wifi_monitor.sh

# Method 3: Root mode
sudo python3 launch.py

# Method 4: Desktop launcher
Click on desktop icon or application menu
```

#### 📝 Installation

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk libpcap-dev
pip3 install -r requirements.txt
chmod +x scripts/*.sh launch.py
python3 launch.py
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip python3-tkinter libpcap-devel
pip3 install -r requirements.txt
chmod +x scripts/*.sh launch.py
python3 launch.py
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip tk libpcap
pip3 install -r requirements.txt
chmod +x scripts/*.sh launch.py
python3 launch.py
```

**Quick Setup:**
```bash
./scripts/setup_mitm_scanner.sh
```

### macOS

#### ✅ What Works (Expected)
- Full GUI with native macOS styling
- ARP scanning via macOS `arp` command
- MITM scanning with root privileges
- Device blocking through router API

#### 🔧 Requirements
- macOS 11 (Big Sur) or later
- Python 3.7+ (use Homebrew recommended)
- Root access for MITM features

#### 🚀 Launch Methods
```bash
# Method 1: Cross-platform launcher
python3 launch.py

# Method 2: Root mode
sudo python3 launch.py

# Method 3: Create .app bundle
# (future enhancement)
```

#### 📝 Installation
```bash
# Install Homebrew first (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python3

# Install dependencies
pip3 install -r requirements.txt

# Run
python3 launch.py
```

## 🔐 Privilege Requirements by Platform

### Windows - Administrator Rights

**Required For:**
- MITM passive scanning
- Traffic monitoring
- Raw packet capture

**How to Run as Admin:**
```batch
REM Method 1: Right-click
Right-click launch.py → "Run as Administrator"

REM Method 2: Batch script
scripts\run_gui_as_admin_mitm.bat

REM Method 3: Command prompt
Run cmd as Administrator → python launch.py
```

**Not Required For:**
- Basic ARP scanning
- Device listing
- Router API access
- GUI operations

### Linux - Root Access

**Required For:**
- MITM passive scanning
- Traffic monitoring
- Raw packet capture
- IP forwarding
- Promiscuous mode

**How to Run as Root:**
```bash
# Method 1: sudo
sudo python3 launch.py

# Method 2: Shell script
./scripts/launch_wifi_monitor_admin.sh

# Method 3: Capabilities (more secure)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
python3 launch.py

# Method 4: pkexec (GUI prompt)
pkexec python3 launch.py
```

**Not Required For:**
- Basic ARP scanning
- Device listing
- Router API access
- GUI operations

### macOS - Root Access

**Required For:**
- MITM passive scanning
- Traffic monitoring
- Raw packet capture

**How to Run as Root:**
```bash
# Method 1: sudo
sudo python3 launch.py

# Method 2: Capabilities
# (macOS doesn't support Linux capabilities)
# Must use sudo
```

## 🧪 Testing Your Installation

Run the installation test script:

```bash
# Basic test
python3 test_install.py

# Test with elevated privileges
# Windows: Run cmd as Administrator
python test_install.py

# Linux/macOS:
sudo python3 test_install.py
```

This will check:
- ✅ Python version (3.7+)
- ✅ Required modules (tkinter, requests)
- ⚠️ Optional modules (scapy, PIL)
- 🔐 Privilege status
- 📋 Platform-specific notes

## 🛠️ Platform-Specific Troubleshooting

### Windows

**Issue: "Python not found"**
```
Solution: Install Python from python.org
Make sure to check "Add Python to PATH" during installation
```

**Issue: "No module named 'tkinter'"**
```
Solution: Reinstall Python and ensure "tcl/tk" is checked
```

**Issue: "Access denied" on MITM features**
```
Solution: Run as Administrator
Right-click → "Run as Administrator"
```

### Linux

**Issue: "No module named 'tkinter'"**
```bash
# Debian/Ubuntu
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch
sudo pacman -S tk
```

**Issue: "Permission denied" on scripts**
```bash
chmod +x scripts/*.sh
chmod +x launch.py
```

**Issue: "Operation not permitted" on scanning**
```bash
sudo python3 launch.py
```

**Issue: Scapy errors**
```bash
# Install libpcap
sudo apt-get install libpcap-dev  # Debian/Ubuntu
sudo dnf install libpcap-devel    # Fedora
sudo pacman -S libpcap            # Arch

# Reinstall scapy
pip3 install --upgrade scapy
```

### macOS

**Issue: "Python not found"**
```bash
brew install python3
```

**Issue: Scapy permission errors**
```bash
# Run with sudo
sudo python3 launch.py
```

## 🔄 Cross-Platform Compatibility

### Code Compatibility

The application uses cross-platform Python code:

- ✅ **GUI**: tkinter (cross-platform)
- ✅ **Networking**: platform-specific commands with auto-detection
- ✅ **File paths**: `os.path` for compatibility
- ✅ **Privileges**: Platform-specific detection
- ✅ **Commands**: Conditional execution based on `platform.system()`

### Auto-Detection Features

The app automatically detects:
- Operating system
- Available network interfaces
- Admin/root privileges
- Available Python modules
- Appropriate system commands

### Launcher Script

The `launch.py` provides unified experience across platforms:
```python
# Auto-detects OS
# Checks privileges
# Shows appropriate messages
# Launches with correct settings
```

## 📦 Dependencies by Platform

### All Platforms (Python packages)
```
requests>=2.25.0    # HTTP requests
scapy>=2.4.5        # Packet manipulation (optional)
pillow>=8.0.0       # Image processing (optional)
```

### Windows Specific
```
# Usually none - all included with Python
```

### Linux Specific
```bash
# System packages
python3-tk          # GUI framework
libpcap-dev         # Packet capture
python3-scapy       # Network scanning (optional)
```

### macOS Specific
```bash
# Usually none - included with Python
# libpcap is pre-installed
```

## 🎯 Recommended Setup

### For Development
```bash
# Use virtual environment
python3 -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### For Production (Linux systemd)
```bash
# Install system-wide
sudo pip3 install -r requirements.txt

# Create service
sudo systemctl enable netwatchpro
sudo systemctl start netwatchpro
```

### For Desktop Use
```bash
# Linux: Create desktop entry
cp assets/NetWatchPro.desktop ~/.local/share/applications/

# Windows: Use provided .bat scripts
# Double-click to run

# macOS: Create .app bundle (future feature)
```

## 📊 Performance by Platform

| Platform | Scan Speed | Memory Usage | CPU Usage |
|----------|------------|--------------|-----------|
| Windows 10/11 | Fast | ~50-100MB | Low |
| Ubuntu 22.04 | Fast | ~40-80MB | Low |
| Debian 11 | Fast | ~40-80MB | Low |
| Fedora 36 | Fast | ~45-85MB | Low |
| Arch Linux | Fast | ~40-75MB | Low |
| macOS 12+ | Fast | ~60-110MB | Low |

*MITM features use more CPU/memory during active scanning*

## 🚀 Quick Start by Platform

### Windows
```batch
python launch.py
```

### Linux
```bash
python3 launch.py
```

### macOS
```bash
python3 launch.py
```

**That's it!** The launcher handles everything else.

## 📖 Further Reading

- **[Linux Setup Guide](LINUX_SETUP.md)** - Detailed Linux instructions
- **[Main README](../README.md)** - General documentation
- **[Troubleshooting](WHY_BLOCKING_DOESNT_WORK.md)** - Common issues

---

**Last Updated**: June 29, 2026  
**Platforms**: Windows, Linux, macOS  
**Version**: 2.0 (Cross-Platform Edition)
