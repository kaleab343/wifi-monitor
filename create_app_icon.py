#!/usr/bin/env python3
"""
Create application icon for WiFi Router Manager
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_icon():
    """Create a simple WiFi icon"""
    
    # Create 256x256 image
    size = 256
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    # Background circle (dark blue)
    margin = 10
    draw.ellipse([margin, margin, size-margin, size-margin], 
                 fill=(0, 102, 204, 255), outline=(0, 51, 153, 255), width=5)
    
    # WiFi symbol (white arcs)
    center_x, center_y = size // 2, size // 2 + 20
    
    # Three WiFi arcs
    colors = [(255, 255, 255, 200), (255, 255, 255, 150), (255, 255, 255, 100)]
    arc_sizes = [60, 100, 140]
    
    for i, (arc_size, color) in enumerate(zip(arc_sizes, colors)):
        bbox = [center_x - arc_size, center_y - arc_size, 
                center_x + arc_size, center_y + arc_size]
        draw.arc(bbox, start=200, end=340, fill=color, width=15)
    
    # Center dot
    dot_size = 15
    draw.ellipse([center_x - dot_size, center_y - dot_size,
                  center_x + dot_size, center_y + dot_size],
                 fill=(255, 255, 255, 255))
    
    # Add lock symbol (for security)
    lock_x, lock_y = size // 2 + 70, size // 2 - 70
    lock_size = 25
    
    # Lock body
    draw.rectangle([lock_x - lock_size//2, lock_y,
                   lock_x + lock_size//2, lock_y + lock_size],
                  fill=(220, 53, 69, 255))
    
    # Lock shackle
    draw.arc([lock_x - lock_size//2, lock_y - lock_size,
             lock_x + lock_size//2, lock_y + 5],
            start=0, end=180, fill=(220, 53, 69, 255), width=5)
    
    # Save as ICO
    icon_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save('app_icon.ico', format='ICO', sizes=icon_sizes)
    
    # Also save as PNG
    img.save('app_icon.png', format='PNG')
    
    print("✅ Icon created: app_icon.ico")
    print("✅ Icon created: app_icon.png")
    
    return 'app_icon.ico'

if __name__ == "__main__":
    try:
        create_icon()
        print("\n🎨 Application icon created successfully!")
    except ImportError:
        print("Installing Pillow...")
        import subprocess
        import sys
        subprocess.run([sys.executable, "-m", "pip", "install", "pillow"])
        print("\nPlease run this script again.")
