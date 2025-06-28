# SCAPA Production Deployment Guide

## Overview
SCAPA (Smart Capture and Packet Analysis) is now production-ready with enhanced security, performance monitoring, and robust error handling.

## Quick Start

### Option 1: Automatic Launcher (Recommended)
```bash
./start_scapa.sh
```

### Option 2: Manual Launch with Sudo
```bash
sudo python3 main.py
```

### Option 3: Production Wrapper
```bash
python3 scapa_production.py
```

## Key Features ✅

### Core Functionality
- ✅ Real-time packet capture and analysis
- ✅ Machine learning-based threat detection
- ✅ Custom rule engine for network security
- ✅ HTTP/HTTPS stream analysis
- ✅ TCP stream reconstruction
- ✅ Performance monitoring

### Security Enhancements
- ✅ Safe pickle loading with size validation
- ✅ Input sanitization for rules and IPs
- ✅ Secure file creation with proper permissions
- ✅ Enhanced error handling and logging
- ✅ Cross-platform compatibility

### Performance Features
- ✅ Real-time CPU and memory monitoring
- ✅ Packet processing rate tracking
- ✅ Batched ML predictions
- ✅ Smart packet filtering
- ✅ Performance optimization suggestions

### Bug Fixes
- ✅ PyShark/tshark permission issues resolved
- ✅ File permission handling fixed
- ✅ Cross-platform path compatibility
- ✅ Packet capture initialization improved
- ✅ ML model loading stabilized

## System Requirements

### Dependencies
- Python 3.8+
- PySimpleGUI
- Scapy
- PyShark
- Scikit-learn
- Psutil

### System Packages
- tshark (wireshark-common)
- tcpdump

### Permissions
- Raw socket access (requires sudo or capabilities)
- User in 'wireshark' group (recommended)

## File Structure

```
SCAPA/
├── main.py                    # Main application
├── start_scapa.sh            # Production launcher
├── scapa_production.py       # Production wrapper
├── error_handling.py         # Enhanced error handling
├── network_utils.py          # Network utilities
├── performance_monitor.py    # Performance monitoring
├── rules_engine.py           # Rules processing
├── config.ini               # Configuration
├── model.pkl                # ML model
├── fmap.pkl                 # Feature mapping
├── pmap.pkl                 # Protocol mapping
├── rules.txt                # Detection rules
├── Requirements.txt         # Dependencies
├── venv/                    # Virtual environment
├── logs/                    # Log files
├── temp/                    # Temporary files
└── savedpcap/              # Saved captures
```

## Usage Instructions

1. **Start SCAPA**:
   ```bash
   ./start_scapa.sh
   ```

2. **Begin Packet Capture**:
   - GUI will open automatically
   - Packet capture starts immediately
   - Click "Start Capture" to begin processing

3. **Monitor Performance**:
   - Real-time stats in GUI
   - Click "Performance" button for detailed view

4. **Analyze Threats**:
   - View suspicious packets in "Alerted Packets" tab
   - Check ML predictions in "ML Analysis" tab
   - Examine TCP streams for detailed analysis

## Troubleshooting

### Packet Capture Issues
```bash
# Check permissions
./start_scapa.sh

# Manual permission fix
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### Performance Issues
- Monitor CPU/Memory in Performance tab
- Adjust packet filtering in rules.txt
- Check logs/ directory for errors

### File Permission Errors
- Ensure proper ownership of SCAPA directory
- Check temp/ and logs/ directory permissions

## Production Notes

- All enhancements have been tested and validated
- Comprehensive error handling prevents crashes
- Performance monitoring provides real-time insights
- Secure file handling prevents permission issues
- Cross-platform compatibility ensured

## Support

For issues or questions:
1. Check logs/ directory for error details
2. Review backup/\* directories for original files
3. Use `python3 scapa_production.py` for enhanced diagnostics

---

**SCAPA v2.0 - Production Ready** 🚀
