#!/usr/bin/env python3
"""
NetWatch Pro - WiFi Monitor
Main launcher script for the organized project structure
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Launch GUI
from gui.hybrid_router_gui import main

if __name__ == "__main__":
    main()
