#!/bin/bash
# NetWatch Pro - Run GUI with Root Privileges (Linux)

cd "$(dirname "$0")/.."

echo "================================"
echo "  NetWatch Pro - WiFi Monitor  "
echo "================================"
echo ""
echo "🔐 Running with root privileges for full network access..."
echo ""

sudo python3 run.py
