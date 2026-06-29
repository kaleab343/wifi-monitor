#!/bin/bash

# NetWatch Pro - One-Click Launcher
# Simple wrapper to launch the WiFi monitor application

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Change to the script directory
cd "$SCRIPT_DIR"

# Check if Python 3 is available
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo "❌ Error: Python 3 is not installed!"
    echo "Please install Python 3.7 or higher"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "🐍 Using Python $PYTHON_VERSION"

# Launch the application
echo "🚀 Starting NetWatch Pro..."
echo ""

$PYTHON_CMD launch.py

# Keep terminal open if there's an error
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Application exited with an error"
    echo "Press Enter to close..."
    read
fi
