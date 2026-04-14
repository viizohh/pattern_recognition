#!/bin/bash

echo "========================================="
echo "VCU Network Traffic Analyzer - Installer"
echo "========================================="
echo ""

# Check if we're in the vcu directory
if [ ! -f "setup.py" ]; then
    echo "Error: Please run this script from the vcu directory"
    exit 1
fi

# Create virtual environment
echo "[1/4] Creating virtual environment..."
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo "Error: Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
echo "[2/4] Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "[3/4] Installing dependencies..."
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "Error: Failed to install dependencies"
    exit 1
fi

# Install vcu
echo "[4/4] Installing vcu..."
pip install -e .
if [ $? -ne 0 ]; then
    echo "Error: Failed to install vcu"
    exit 1
fi

echo ""
echo "========================================="
echo "✓ Installation complete!"
echo "========================================="
echo ""
echo "To run vcu:"
echo "  1. Activate the virtual environment:"
echo "     source venv/bin/activate"
echo ""
echo "  2. Run vcu with sudo (required for packet capture):"
echo "     sudo vcu"
echo ""
echo "Or run directly:"
echo "  sudo venv/bin/python -m net_watch.cli"
echo ""
