# 🚀 One-Click Launch Script Guide

## What is `run.sh`?

`run.sh` is a simple one-click launcher for NetWatch Pro that works on Linux, macOS, and Windows (Git Bash/WSL).

---

## 📦 What's Included

**File Created**: `run.sh` - Universal one-click launcher script

---

## 🎯 How to Use

### On Linux/macOS

```bash
# Option 1: Double-click the file (if your file manager supports it)

# Option 2: Run from terminal
./run.sh

# Option 3: If not executable yet
bash run.sh
```

### On Windows

```bash
# If using Git Bash
./run.sh

# If using WSL (Windows Subsystem for Linux)
./run.sh

# If using standard Windows terminal (use launch.py instead)
python launch.py
```

---

## 🔧 First-Time Setup (Linux/macOS)

Make the script executable:

```bash
chmod +x run.sh
```

Now you can just double-click or run `./run.sh`!

---

## ✨ What Does It Do?

The `run.sh` script:

1. ✅ Automatically detects the script directory
2. ✅ Checks if Python 3 is installed
3. ✅ Shows which Python version is being used
4. ✅ Launches NetWatch Pro via `launch.py`
5. ✅ Keeps the terminal open if there's an error
6. ✅ Provides helpful error messages

---

## 🎨 Desktop Integration

### Linux Desktop Shortcut

Create a desktop launcher:

```bash
# Copy the desktop file
cp assets/NetWatchPro.desktop ~/.local/share/applications/

# Edit the file to set correct paths
nano ~/.local/share/applications/NetWatchPro.desktop
```

Update the `Exec` line to:
```
Exec=/full/path/to/run.sh
```

### macOS Alias

Add to your `~/.zshrc` or `~/.bash_profile`:

```bash
alias nwp="/path/to/wifi-monitor/run.sh"
```

Then just type `nwp` to launch!

---

## 🆚 Comparison: Different Launch Methods

| Method | Platform | Admin/Root? | Command |
|--------|----------|-------------|---------|
| **run.sh** | Linux/Mac/Git Bash | No | `./run.sh` |
| **launch.py** | All | No | `python3 launch.py` |
| **run.py** | All | No | `python3 run.py` |
| **Shell Scripts** | Linux | No | `./scripts/launch_wifi_monitor.sh` |
| **Batch Scripts** | Windows | No | `scripts\launch_wifi_monitor.bat` |

### With Admin/Root Privileges

For MITM features:

```bash
# Linux/macOS
sudo ./run.sh

# Or
sudo python3 launch.py

# Windows (Git Bash as Administrator)
./run.sh

# Windows (PowerShell as Administrator)
python launch.py
```

---

## 🔥 Quick Examples

### Example 1: Normal Launch
```bash
./run.sh
```

### Example 2: With Root (MITM Features)
```bash
sudo ./run.sh
```

### Example 3: Check if Working
```bash
bash -x run.sh  # Debug mode to see what's happening
```

---

## 🐛 Troubleshooting

### Problem: "Permission denied"

**Solution:**
```bash
chmod +x run.sh
```

---

### Problem: "Python 3 is not installed"

**Solution:**

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install python3
```

**Linux (Fedora):**
```bash
sudo dnf install python3
```

**macOS:**
```bash
brew install python3
```

---

### Problem: Script doesn't find Python

**Solution:**

Check your Python installation:
```bash
which python3
python3 --version
```

If Python is installed but not found, edit `run.sh` and update the Python path.

---

### Problem: "No such file or directory: launch.py"

**Solution:**

Make sure you're in the correct directory:
```bash
cd /path/to/wifi-monitor
./run.sh
```

Or the script will automatically change to its own directory.

---

## 💡 Pro Tips

### Tip 1: Create a Global Command

```bash
# Add to ~/.bashrc or ~/.zshrc
alias netwatchpro="/path/to/wifi-monitor/run.sh"

# Reload
source ~/.bashrc

# Now launch from anywhere!
netwatchpro
```

### Tip 2: Add to System PATH

```bash
# Create a symbolic link
sudo ln -s /full/path/to/run.sh /usr/local/bin/netwatchpro

# Now run from anywhere
netwatchpro
```

### Tip 3: Desktop Icon (Linux)

```bash
# Create a custom desktop launcher
cat > ~/.local/share/applications/netwatchpro.desktop << EOF
[Desktop Entry]
Type=Application
Name=NetWatch Pro
Comment=WiFi Network Monitor
Exec=/path/to/wifi-monitor/run.sh
Icon=/path/to/wifi-monitor/assets/app_icon.ico
Terminal=true
Categories=Network;Utility;
EOF
```

---

## 📊 Feature Comparison

### run.sh vs launch.py

| Feature | run.sh | launch.py |
|---------|:------:|:---------:|
| One-click launch | ✅ | ✅ |
| Linux/macOS | ✅ | ✅ |
| Windows native | ❌ | ✅ |
| Git Bash/WSL | ✅ | ✅ |
| Shows Python version | ✅ | ✅ |
| Auto error handling | ✅ | ✅ |
| Keeps terminal open on error | ✅ | ❌ |
| Can be double-clicked | ✅ | Depends |

**Recommendation**: Use `run.sh` on Linux/macOS/Git Bash, use `launch.py` everywhere else.

---

## 🎯 Best Practices

### For Linux Users
1. Make `run.sh` executable: `chmod +x run.sh`
2. Create a desktop shortcut or alias
3. Use `sudo ./run.sh` for MITM features

### For macOS Users
1. Make `run.sh` executable: `chmod +x run.sh`
2. Create an alias in your shell config
3. Use `sudo ./run.sh` for MITM features

### For Windows Users
1. Use `launch.py` directly for best compatibility
2. Or use Git Bash with `run.sh`
3. Right-click → "Run as Administrator" for MITM

---

## 📚 Related Files

- **run.sh** - This one-click launcher
- **launch.py** - Cross-platform Python launcher
- **run.py** - Legacy launcher
- **scripts/launch_wifi_monitor.sh** - Detailed Linux script
- **scripts/launch_wifi_monitor.bat** - Windows batch script

---

## ✅ Quick Checklist

Before using `run.sh`:

- [ ] Python 3.7+ installed
- [ ] Dependencies installed (`pip3 install -r requirements.txt`)
- [ ] Script is executable (`chmod +x run.sh`)
- [ ] In correct directory or using full path
- [ ] Connected to network

All checked? **You're ready!**

```bash
./run.sh
```

---

## 🎊 Success!

Your one-click launcher is ready to use. Enjoy hassle-free launching of NetWatch Pro!

**Next Steps:**
1. Run `./run.sh`
2. Try a Quick Scan
3. Explore the features

---

**Created**: June 29, 2026  
**Version**: 1.0  
**Compatible with**: NetWatch Pro v2.0+

---

*Happy monitoring! 🔍📡*
