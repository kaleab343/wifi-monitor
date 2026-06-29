#!/bin/bash
# NetWatch Pro - Setup MITM Scanner Dependencies (Linux)

echo "================================"
echo "  MITM Scanner Setup (Linux)    "
echo "================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Some operations require root privileges"
    echo "💡 Run with: sudo ./setup_mitm_scanner.sh"
    echo ""
fi

echo "📦 Installing Python dependencies..."
pip3 install scapy requests --user

echo ""
echo "📦 Installing system dependencies..."
echo "   (This may require your password)"

# Detect package manager
if command -v apt-get &> /dev/null; then
    echo "   Detected: Debian/Ubuntu (apt)"
    sudo apt-get update
    sudo apt-get install -y python3-tk python3-scapy libpcap-dev
elif command -v dnf &> /dev/null; then
    echo "   Detected: Fedora/RHEL (dnf)"
    sudo dnf install -y python3-tkinter python3-scapy libpcap-devel
elif command -v yum &> /dev/null; then
    echo "   Detected: CentOS/RHEL (yum)"
    sudo yum install -y python3-tkinter python3-scapy libpcap-devel
elif command -v pacman &> /dev/null; then
    echo "   Detected: Arch Linux (pacman)"
    sudo pacman -S --noconfirm python-tkinter python-scapy libpcap
else
    echo "   ⚠️  Could not detect package manager"
    echo "   Please manually install: python3-tk, scapy, libpcap"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 You can now run:"
echo "   ./launch_wifi_monitor.sh          - Basic scanning"
echo "   ./launch_wifi_monitor_admin.sh    - Full features (root)"
