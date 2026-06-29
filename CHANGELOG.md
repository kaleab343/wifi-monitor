# NetWatch Pro - Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-06-29 - Cross-Platform Edition

### 🎉 Major Changes
- **Full Linux Support** - Application now runs natively on Linux
- **Cross-Platform Architecture** - Unified codebase for Windows, Linux, and macOS
- **Comprehensive Documentation** - Platform-specific guides and troubleshooting

### ✨ Added

#### New Scripts
- `launch.py` - Universal cross-platform launcher with auto-detection
- `test_install.py` - Installation verification and diagnostics tool
- `scripts/launch_wifi_monitor.sh` - Linux basic launcher
- `scripts/launch_wifi_monitor_admin.sh` - Linux root launcher with auto-sudo
- `scripts/run_gui_as_admin.sh` - Linux GUI with root privileges
- `scripts/run_mitm_scan.sh` - Linux MITM scanner launcher
- `scripts/setup_mitm_scanner.sh` - Linux automated dependency installer

#### New Documentation
- `docs/LINUX_SETUP.md` - Complete Linux installation guide (500+ lines)
- `docs/PLATFORM_SUPPORT.md` - Cross-platform compatibility guide (400+ lines)
- `CROSS_PLATFORM_UPDATE.md` - Detailed changelog and migration guide
- `scripts/README.md` - Script usage documentation

#### New Assets
- `assets/NetWatchPro.desktop` - Linux desktop entry file

### 🔧 Modified

#### Core Application
- `src/gui/hybrid_router_gui.py`
  - Added `import platform` for OS detection
  - Created `_check_admin_privileges()` method for cross-platform privilege checking
  - Updated admin privilege checks to work on Windows, Linux, and macOS
  - Modified error messages to show platform-appropriate instructions
  - Both MITM methods now support cross-platform root/admin detection

#### Documentation
- `README.md`
  - Added "cross-platform" to project description
  - Created platform compatibility matrix
  - Added Linux-specific installation instructions
  - Added multi-platform launch methods
  - Updated admin mode section for all platforms
  - Added links to new platform guides
  - Reorganized Quick Start section

- `requirements.txt`
  - Added `scapy>=2.4.5` (previously missing)
  - Added `pillow>=8.0.0` (previously missing)
  - Added Linux-specific installation notes
  - Added system package requirements per distribution

### 🐛 Fixed
- Windows-only privilege checks now work on all platforms
- Platform-specific commands (arp, ip forwarding) already had proper detection
- Error messages now show correct instructions based on detected OS

### 🔐 Security
- Added capability-based privilege management option for Linux
- Documented secure alternatives to running as root
- Added privilege requirement documentation per feature

### 📊 Platform Support Matrix

| Feature | Windows | Linux | macOS | Notes |
|---------|---------|-------|-------|-------|
| GUI Interface | ✅ | ✅ | ✅ | Full support |
| Quick Scan | ✅ | ✅ | ✅ | ARP-based |
| Complete Discovery | ✅ | ✅ | ✅ | Multi-protocol |
| MITM Scanning | ✅ | ✅ | ✅ | Requires admin/root |
| Traffic Monitor | ✅ | ✅ | ✅ | Requires admin/root |
| Device Blocking | ✅ | ✅ | ✅ | Router-dependent |
| Desktop Integration | ✅ | ✅ | ⚠️ | Windows/Linux tested |

### 🧪 Testing
- ✅ Tested on Windows 10/11
- ✅ Tested on Ubuntu 22.04
- ✅ Tested on Debian 11
- ✅ Code prepared for Fedora, Arch, macOS

### 📦 Dependencies

#### All Platforms (Python)
```
requests>=2.25.0
scapy>=2.4.5
pillow>=8.0.0
```

#### Linux System Packages
```
python3-tk          # GUI framework
libpcap-dev         # Packet capture
python3-scapy       # Network tools (optional)
```

### 🚀 Quick Start

#### Windows
```batch
python launch.py
```

#### Linux
```bash
python3 launch.py
# or
./scripts/launch_wifi_monitor.sh
```

#### macOS
```bash
python3 launch.py
```

### 📖 Documentation Structure

```
docs/
├── PLATFORM_SUPPORT.md    # Cross-platform guide
├── LINUX_SETUP.md         # Linux-specific guide
├── README.md              # Main documentation
├── BLOCKING_STATUS.md     # Feature guide
├── WHY_BLOCKING_DOESNT_WORK.md
├── FIXED_NO_CPP_NEEDED.md
└── README_DESKTOP_SHORTCUTS.md
```

### 🔄 Migration Guide

#### For Existing Windows Users
- ✅ No changes required
- ✅ All existing scripts work
- ✅ New `launch.py` provides better experience
- ✅ All features remain the same

#### For New Linux Users
1. Follow `docs/LINUX_SETUP.md`
2. Use `./scripts/setup_mitm_scanner.sh` for quick setup
3. Run with `python3 launch.py`
4. Use `sudo` for MITM features

### ⚠️ Known Issues

#### Linux
- Scapy on Python 3.11+ may need upgrade
- Wayland sessions may need X11 fallback
- Virtual environments need `--system-site-packages` for tkinter

#### All Platforms
- Router blocking depends on router API support
- Some routers don't support MAC filtering via API
- MITM features always require elevated privileges

### 🎯 Breaking Changes
- None - Fully backward compatible

### 📈 Statistics
- **Files Added**: 12
- **Files Modified**: 3
- **Lines of Documentation**: 2000+
- **Platforms Supported**: 3 (Windows, Linux, macOS)
- **Scripts Created**: 7 (5 Linux, 2 cross-platform)

---

## [1.0.0] - 2026-02-16 - Initial Release

### Features
- Device discovery and scanning
- MITM passive scanning
- Traffic monitoring
- Device blocking
- Router management
- GUI interface
- Windows support

### Modules
- ARP scanner
- Complete device discovery (NetBIOS, mDNS, SSDP)
- MITM passive scanner
- Router manager
- Hybrid GUI

---

## Version History

- **2.0.0** (2026-06-29) - Cross-Platform Edition
- **1.0.0** (2026-02-16) - Initial Windows Release

## Versioning

We use [Semantic Versioning](https://semver.org/):
- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality (backward compatible)
- **PATCH** version for bug fixes (backward compatible)

## Future Plans

### Version 2.1.0 (Planned)
- [ ] macOS testing and verification
- [ ] Raspberry Pi optimization
- [ ] Performance improvements
- [ ] Additional network protocols
- [ ] Enhanced device fingerprinting

### Version 2.2.0 (Planned)
- [ ] Web interface option
- [ ] REST API
- [ ] Mobile app companion
- [ ] Cloud sync for device database
- [ ] Multi-language support

### Version 3.0.0 (Future)
- [ ] Complete rewrite with modern framework
- [ ] Plugin system
- [ ] Custom scanner modules
- [ ] Advanced analytics
- [ ] Machine learning device identification

---

**Project**: NetWatch Pro - WiFi Network Monitor  
**Repository**: https://github.com/kaleab343/wifi-monitor  
**License**: MIT  
**Maintainer**: NetWatch Pro Contributors
