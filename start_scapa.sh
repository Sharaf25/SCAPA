#!/bin/bash
# SCAPA Launcher Script
# Automatically handles permissions and starts SCAPA

cd "$(dirname "$0")"

echo "🚀 SCAPA Network Security Tool"
echo "=============================="

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
    PYTHON_CMD="python3"
else
    PYTHON_CMD="python3"
fi

# Check if we can capture packets without sudo
if $PYTHON_CMD -c "
import socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.close()
    print('PACKET_CAPTURE_OK')
except PermissionError:
    print('PACKET_CAPTURE_NEEDS_SUDO')
except Exception as e:
    print(f'PACKET_CAPTURE_ERROR: {e}')
" 2>/dev/null | grep -q "PACKET_CAPTURE_OK"; then
    echo "✓ Packet capture permissions OK"
    $PYTHON_CMD main.py
else
    echo "⚠️  Packet capture requires elevated privileges"
    echo ""
    echo "SCAPA needs raw socket access for packet capture."
    echo "This requires either:"
    echo "  1. Running with sudo (recommended)"
    echo "  2. Setting capabilities on Python (advanced)"
    echo ""
    
    read -p "Run with sudo? [Y/n]: " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        echo "Starting SCAPA with sudo..."
        if [ -d "venv" ]; then
            sudo $(pwd)/venv/bin/python3 main.py
        else
            sudo $PYTHON_CMD main.py
        fi
    else
        echo "To run without sudo, you can set Python capabilities:"
        if [ -d "venv" ]; then
            echo "  sudo setcap cap_net_raw,cap_net_admin=eip $(realpath venv/bin/python3)"
        else
            echo "  sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)"
        fi
        echo ""
        echo "Then run: $PYTHON_CMD main.py"
        exit 1
    fi
fi
