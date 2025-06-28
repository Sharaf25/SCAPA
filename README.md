# SCAPA - Smart Contract Attack Prevention Application

## Overview
SCAPA (Smart Contract Attack Prevention Application) is a **cross-platform** real-time Network Intrusion Detection System (NIDS) designed to monitor and analyze network traffic for suspicious activities. It combines rule-based detection with machine learning to identify potential threats and predict attack types. SCAPA provides a modern, user-friendly interface for capturing, analyzing, and decoding network packets, making it a powerful tool for network security professionals.

### 🚀 **Latest Updates (v2.0):**
- **✅ Full Cross-Platform Support**: Native support for Windows, Linux, and macOS
- **🔧 Enhanced Installation**: Automated setup with dependency management
- **🖥️ Improved GUI**: Updated PySimpleGUI interface with better error handling
- **📡 Smart Network Detection**: Platform-aware network interface detection
- **🔔 Multi-Platform Alerts**: Desktop notifications and audio alerts across all platforms
- **🔒 Intelligent Permission Handling**: Automatic privilege escalation for packet capture
- **⚡ Performance Optimizations**: Enhanced packet processing and memory management

### Key Features:
- **Real-Time Packet Capture**: Continuously monitors network traffic and captures packets
- **Cross-Platform Compatibility**: Runs natively on Windows, Linux, and macOS
- **Rule-Based Detection**: Uses customizable rules to flag suspicious packets
- **Machine Learning Integration**: Predicts attack types using a pre-trained machine learning model
- **HTTP Header Decoding**: Extracts and displays HTTP headers and payloads
- **TCP/HTTP2 Stream Analysis**: Allows users to load and analyze TCP and HTTP2 streams
- **Packet Saving**: Save captured packets and alerts for further analysis
- **Modern GUI**: Built with PySimpleGUI for an intuitive and interactive experience
- **Smart Alerts**: Desktop notifications with cross-platform audio alerts

---

## Installation

### Prerequisites
- **Python 3.8 or higher**
- **Git** (for cloning the repository)

### Quick Installation (Recommended)

#### Method 1: Automated Installer
```bash
# Clone the repository
git clone https://github.com/Sharaf25/SCAPA.git
cd SCAPA

# Run the automated installer
python3 install_fixed.py
```

#### Method 2: Manual Installation
```bash
# Clone the repository
git clone https://github.com/Sharaf25/SCAPA.git
cd SCAPA

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r Requirements.txt

# Install PySimpleGUI from official source
pip install --upgrade --extra-index-url https://PySimpleGUI.net/install PySimpleGUI
```

### System Dependencies

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install wireshark-common pulseaudio-utils
sudo usermod -a -G wireshark $USER  # For network capture permissions
```

#### macOS
```bash
# Install Wireshark from https://www.wireshark.org/
brew install wireshark
```

#### Windows
- Install Wireshark from https://www.wireshark.org/
- Ensure Wireshark is added to PATH during installation

5. Run the application:
   ```bash
   python main.py
   ```

---

## Usage

### Running SCAPA

#### Option 1: Enhanced Launcher (Recommended)
```bash
# Run with full network capture (requires sudo on Linux/macOS)
./scapa_launcher.sh
```

#### Option 2: Direct Execution
```bash
# Activate virtual environment first
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Run SCAPA
python main.py
```

#### Option 3: With Elevated Privileges (Full Network Capture)
```bash
# Linux/macOS
sudo ./venv/bin/python main.py

# Windows (Run as Administrator)
python main.py
```

### Using the GUI Interface
1. **Start Network Monitoring**: Click `STARTCAP` to begin packet capture
2. **Stop Monitoring**: Click `STOPCAP` to stop packet capture
3. **Refresh Rules**: Click `REFRESH RULES` to reload detection rules
4. **Analyze Streams**: Load and analyze TCP/HTTP2 streams from files
5. **Save Data**: Export captured packets and alerts for analysis

### Network Permissions
- **Linux**: Add user to wireshark group or run with sudo
- **macOS**: May require sudo for packet capture
- **Windows**: Run as Administrator for full network access

### Customizing Rules
- Modify the `rules.txt` file to add or update detection rules.
- Rules follow this format:
  ```
  alert <protocol> <sourceIP> <sourcePort> -> <destinationIP> <destinationPort> <message>
  ```
  Example:
  ```
  alert tcp any any -> 192.168.0.0/24 80 HTTP TRAFFIC
  ```

---

## Project Structure
```
SCAPA/
├── main.py                 # Main application entry point
├── scapa_launcher.sh       # Enhanced launcher script (Linux/macOS)
├── install_fixed.py        # Automated installation script
├── Requirements.txt        # Python dependencies
├── config.ini             # Configuration settings
├── rules.txt              # Network detection rules
├── error_handling.py      # Enhanced error handling system
├── network_utils.py       # Cross-platform network utilities
├── performance_monitor.py # System performance monitoring
├── rules_engine.py        # Advanced rules processing engine
├── ML_Model.ipynb         # Machine learning model training notebook
├── model.pkl              # Pre-trained ML model
├── fmap.pkl              # Feature mapping for ML model
├── pmap.pkl              # Protocol mapping for ML model
├── temp/                 # Temporary analysis files
│   └── decrypthttp2.py   # HTTP2 decryption utilities
├── savedpcap/            # Saved packet captures
├── logs/                 # Application logs
└── venv/                 # Virtual environment (created during installation)
```

### Key Components
- **Cross-Platform Core**: `main.py` with platform-aware networking
- **Enhanced Modules**: Modular design with specialized components
- **Automated Setup**: Smart installation with dependency resolution
- **Security Features**: Intelligent permission handling and error recovery

---
## Dataset
The machine learning model used in SCAPA is trained on the **KDD Cup 1999 Dataset**, a widely used dataset for network intrusion detection.

- Dataset Link: [KDD Cup 1999 Dataset on Kaggle](https://www.kaggle.com/datasets/galaxyh/kdd-cup-1999-data)

You can download the dataset and use it to retrain or fine-tune the machine learning model as needed.

---

## Contributing
Contributions are welcome! If you'd like to contribute:
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a detailed description of your changes.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Contact
For questions or support, please contact:
- **Email**: mostafaamrmedia@gmail.com
- **GitHub**: [Mostafa Sharaf](https://github.com/Sharaf25)