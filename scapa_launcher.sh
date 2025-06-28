#!/bin/bash
# SCAPA Launcher with Full Network Capture (Sudo by Default)
# This script automatically runs with elevated privileges for complete packet capture

echo "🚀 SCAPA (Smart Contract Attack Prevention Application) Launcher"
echo "🔥 Full Network Capture Mode (Running with elevated privileges)"
echo "=============================================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "✅ Running as root - full network capture enabled"
   PYTHON_CMD="./venv/bin/python"
else
   echo "🔐 Requesting elevated privileges for full network capture..."
   echo "💡 You may be prompted for your password"
   echo ""
   
   # Re-run this script with sudo, preserving the environment
   exec sudo -E "$0" "$@"
fi

# Check if virtual environment exists
if [ ! -f "./venv/bin/python" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run the installer first: python3 install.py"
    exit 1
fi

# Check if main.py exists
if [ ! -f "main.py" ]; then
    echo "❌ main.py not found!"
    echo "Please ensure you're in the SCAPA directory"
    exit 1
fi

echo "🔧 Activating virtual environment..."
echo "🚀 Starting SCAPA..."
echo ""
echo "💡 Tips:"
echo "   - The GUI will open in a new window"
echo "   - Close the GUI window to stop SCAPA"
echo "   - ML model warnings are expected and non-critical"
echo "   - Full network capture is enabled with root privileges"
echo ""

# Launch SCAPA with warning suppression
echo "📊 Loading ML models and starting GUI interface..."
export PYTHONWARNINGS="ignore"
$PYTHON_CMD main.py 2>/dev/null &
SCAPA_PID=$!

echo "✅ SCAPA is starting (PID: $SCAPA_PID)"
echo "🖥️  GUI should appear in a few seconds..."
echo "📡 Network monitoring: FULL CAPTURE ENABLED (root mode)"
echo ""
echo "💡 To stop SCAPA:"
echo "   - Close the GUI window, or"
echo "   - Press Ctrl+C in this terminal"

# Wait for the process
wait $SCAPA_PID

echo ""
echo "👋 SCAPA has been stopped"
