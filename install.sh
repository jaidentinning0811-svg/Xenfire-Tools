#!/bin/bash
# Xenfire Tools - Setup Script
set -e

echo "=== Xenfire Tools Installer ==="
echo "Installing dependencies..."

sudo apt update
sudo apt install -y python3 python3-pip python3-tk libimobiledevice-1.0-6 libimobiledevice-utils ideviceinstaller usbmuxd

pip3 install --user --break-system-packages Pillow Flask qrcode

chmod +x xenfire_tools.py

echo ""
echo "Setup complete."
echo "Plug your iPhone into this Chromebook via USB, tap 'Trust This Computer' on the phone, then run:"
echo "  ./xenfire_tools.py"
