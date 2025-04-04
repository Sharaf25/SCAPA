# SCAPA

## Overview
SCAPA (Smart Capture and Packet Analysis) is a real-time Network Intrusion Detection System (NIDS) designed to monitor and analyze network traffic for suspicious activities. It combines rule-based detection with machine learning to identify potential threats and predict attack types. SCAPA provides a user-friendly interface for capturing, analyzing, and decoding network packets, making it a powerful tool for network security professionals.

### Key Features:
- **Real-Time Packet Capture**: Continuously monitors network traffic and captures packets.
- **Rule-Based Detection**: Uses customizable rules to flag suspicious packets.
- **Machine Learning Integration**: Predicts attack types using a pre-trained machine learning model.
- **HTTP Header Decoding**: Extracts and displays HTTP headers and payloads.
- **TCP/HTTP2 Stream Analysis**: Allows users to load and analyze TCP and HTTP2 streams.
- **Packet Saving**: Save captured packets and alerts for further analysis.
- **User-Friendly GUI**: Built with PySimpleGUI for an intuitive and interactive experience.

---

## Installation

### Prerequisites
Ensure you have the following installed on your system:
- **Python 3.8 or higher**
- **Pip** (Python package manager)

### Steps to Install
1. Clone the repository:
   ```bash
   git clone https://github.com/Sharaf25/SCAPA.git
   cd SCAPA
   ```

2. Install the required dependencies:
   ```bash
   pip install -r Requirements.txt
   ```

3. Ensure you have the following additional tools installed:
   - **Wireshark**: Required for PyShark to process `.pcap` files.
   - **Scapy**: For packet manipulation and analysis.

4. Place the following files in the project directory:
   - `model.pkl`: Pre-trained machine learning model.
   - `fmap.pkl`: Feature mapping for the ML model.
   - `pmap.pkl`: Protocol mapping for the ML model.

5. Run the application:
   ```bash
   python main.py
   ```

---

## Usage

### Running SCAPA
1. Start the application:
   ```bash
   python main.py
   ```

2. Use the GUI to:
   - Start capturing packets (`STARTCAP` button).
   - Stop capturing packets (`STOPCAP` button).
   - Refresh detection rules (`REFRESH RULES` button).
   - Load and analyze TCP/HTTP2 streams.
   - Save captured packets and alerts.

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

## File Structure
- `main.py`: The main application file.
- `rules.txt`: Contains the rules for detecting suspicious packets.
- `model.pkl`: Pre-trained machine learning model.
- `fmap.pkl`: Feature mapping for the ML model.
- `pmap.pkl`: Protocol mapping for the ML model.
- `ML_Model.ipynb`: Jupyter Notebook for training and evaluating the machine learning model.
- `savedpcap/`: Directory for saving captured packets.
- `temp/`: Temporary files for packet and stream analysis.

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