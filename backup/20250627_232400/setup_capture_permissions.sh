#!/bin/bash
# SCAPA Packet Capture Setup Script
# Fixes common packet capture permission issues

echo "🔧 SCAPA Packet Capture Setup"
echo "================================"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "✓ Running with root privileges"
else
    echo "⚠️  Not running as root - some fixes may require sudo"
fi

echo ""
echo "🔍 Checking current packet capture capabilities..."

# Check if user is in wireshark group
if groups $USER | grep -q '\bwireshark\b'; then
    echo "✓ User is in wireshark group"
else
    echo "❌ User not in wireshark group"
    echo "   To fix: sudo usermod -a -G wireshark $USER"
    echo "   Then log out and log back in"
fi

# Check dumpcap capabilities
if command -v dumpcap &> /dev/null; then
    DUMPCAP_CAPS=$(getcap /usr/bin/dumpcap 2>/dev/null)
    if [[ "$DUMPCAP_CAPS" == *"cap_net_admin,cap_net_raw"* ]]; then
        echo "✓ dumpcap has proper capabilities: $DUMPCAP_CAPS"
    else
        echo "❌ dumpcap missing capabilities"
        echo "   Current: $DUMPCAP_CAPS"
        echo "   To fix: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap"
    fi
else
    echo "❌ dumpcap not found - wireshark-common package may not be installed"
fi

echo ""
echo "🚀 SCAPA Launch Options:"
echo "========================"

echo ""
echo "Option 1: Run with sudo (Recommended for full functionality)"
echo "   sudo python3 main.py"

echo ""
echo "Option 2: Set Python capabilities (Advanced users)"
PYTHON_PATH=$(which python3)
echo "   sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_PATH"
echo "   python3 main.py"
echo "   Warning: This affects all Python scripts system-wide"

echo ""
echo "Option 3: Use tcpdump backend (Alternative method)"
echo "   Modify scapy configuration to use tcpdump"
echo "   May require additional setup"

echo ""
echo "🔧 Quick Fix Commands:"
echo "======================"
echo "# Add user to wireshark group:"
echo "sudo usermod -a -G wireshark \$USER"
echo ""
echo "# Set dumpcap capabilities:"
echo "sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap"
echo ""
echo "# Set Python capabilities (use with caution):"
echo "sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_PATH"
echo ""
echo "# Reset Python capabilities if needed:"
echo "sudo setcap -r $PYTHON_PATH"

echo ""
echo "📝 Note: After group changes, you need to log out and log back in"
echo "     or run 'newgrp wireshark' to apply group membership"

echo ""
echo "🎯 For SCAPA specifically, the easiest solution is:"
echo "   sudo python3 main.py"
