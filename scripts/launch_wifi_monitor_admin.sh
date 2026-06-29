#!/bin/bash
# NetWatch Pro - WiFi Monitor Launcher (Linux - Root Mode)
# Launches with sudo for MITM features

cd "$(dirname "$0")/.."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "🔐 Requesting root privileges for MITM features..."
    sudo python3 run.py
else
    python3 run.py
fi
