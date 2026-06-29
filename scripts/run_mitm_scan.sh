#!/bin/bash
# NetWatch Pro - MITM Passive Scanner (Linux)
# Requires root privileges

cd "$(dirname "$0")/.."

echo "================================"
echo "  MITM Passive Network Scanner  "
echo "================================"
echo ""
echo "⚠️  This requires root privileges!"
echo "📡 Will intercept network traffic for 30 seconds..."
echo ""

if [ "$EUID" -ne 0 ]; then
    sudo python3 src/scanners/mitm_passive_scanner.py
else
    python3 src/scanners/mitm_passive_scanner.py
fi
