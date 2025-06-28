#!/usr/bin/env python3
"""
SCAPA - Smart Capture and Packet Analysis
Network Security Tool with ML-based Threat Detection

Version: 2.0 Production
Author: SCAPA Development Team
License: MIT
"""

# Standard library imports
import codecs
import glob
import ipaddress
import json
import logging
import os
import pickle
import platform
import pwd
import re
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict
from tkinter import Tk, messagebox

# Third-party imports
import numpy
import PySimpleGUI as sg
import pyshark
import scapy.all as scp
from plyer import notification
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from sklearn.ensemble import RandomForestClassifier

# Platform-specific imports
if platform.system() == "Windows":
    import scapy.arch.windows as scpwinarch
    try:
        import winsound
    except ImportError:
        winsound = None
else:
    winsound = None

# Enhanced SCAPA modules
try:
    from performance_monitor import monitor as performance_monitor
    from error_handling import handle_error, setup_logging, SCAPAError
    from network_utils import get_available_interfaces, validate_interface
    from rules_engine import RulesEngine
    ENHANCEMENTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some enhancements not available: {e}")
    ENHANCEMENTS_AVAILABLE = False
    # Fallback implementations
    performance_monitor = None
    def handle_error(func): return func
    def setup_logging(): pass
    class SCAPAError(Exception): pass

# Configure logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# SCAPA imports and setup

# PyShark configuration is now handled automatically via tshark-compatible pcap copying
logging.info("PyShark configuration handled via tshark-compatible file copying")

#rules ---->        instruction  protocol  sourceIP  sourcePort  direction  destinationIP  destinationPort  message

def alert_user(message):
    """Send desktop notification with sound - cross-platform"""
    try:
        # Cross-platform desktop notification
        from plyer import notification
        notification.notify(
            title="SCAPA Security Alert",
            message=message,
            timeout=10
        )
        
        # Cross-platform sound alert
        if platform.system() == "Windows" and winsound:
            # Windows system sound
            winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)
        else:
            # Unix-like systems - try different approaches
            try:
                # Try using system bell
                print('\a')  # ASCII bell character
                # Alternative: use paplay on Linux
                if platform.system() == "Linux":
                    subprocess.run(["paplay", "/usr/share/sounds/alsa/Front_Left.wav"], 
                                 check=False, timeout=1, capture_output=True)
                # Alternative: use afplay on macOS
                elif platform.system() == "Darwin":
                    subprocess.run(["afplay", "/System/Library/Sounds/Glass.aiff"], 
                                 check=False, timeout=1, capture_output=True)
            except Exception:
                pass  # Sound alert failed, but continue
        
        # Always show message box as fallback
        root = Tk()
        root.withdraw()  # Hide the main tkinter window
        messagebox.showinfo("Intrusion Detection Alert", message)
        root.destroy()
        
    except Exception as e:
        logging.error(f"Error showing alert: {e}")
        # Fallback to console output
        print(f"\n*** SECURITY ALERT ***\n{message}\n")

def readrules():
    """Read and validate rules from rules.txt with input sanitization"""
    rulefile = "rules.txt"
    ruleslist = []
    
    # Validate file exists and is readable
    if not os.path.exists(rulefile):
        logging.warning(f"Rules file {rulefile} not found")
        return []
    
    try:
        with open(rulefile, "r", encoding='utf-8') as rf:
            ruleslist = rf.readlines()
    except Exception as e:
        logging.error(f"Error reading rules file: {e}")
        return []
    
    rules_list = []
    for line_num, line in enumerate(ruleslist, 1):
        # Input sanitization
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
            
        # Basic validation for rule format
        if line.startswith("alert"):
            # Sanitize the rule line
            sanitized_line = sanitize_rule_input(line)
            if sanitized_line:
                rules_list.append(sanitized_line)
            else:
                logging.warning(f"Invalid rule format at line {line_num}: {line}")
    
    logging.info(f"Loaded {len(rules_list)} valid rules")
    return rules_list

def sanitize_rule_input(rule_line):
    """Sanitize rule input to prevent injection attacks"""
    # Remove potentially dangerous characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}']
    for char in dangerous_chars:
        if char in rule_line:
            logging.warning(f"Potentially dangerous character '{char}' found in rule")
            return None
    
    # Basic format validation: alert protocol src_ip src_port -> dst_ip dst_port message
    parts = rule_line.split()
    if len(parts) < 7:
        return None
    
    if parts[0] != "alert":
        return None
    
    if parts[4] != "->":
        return None
    
    # Validate IP addresses (basic check)
    src_ip = parts[2]
    dst_ip = parts[5]
    
    # Allow 'any' or basic IP validation
    if src_ip != "any" and not is_valid_ip_pattern(src_ip):
        return None
    
    if dst_ip != "any" and not is_valid_ip_pattern(dst_ip):
        return None
    
    return rule_line

def is_valid_ip_pattern(ip_str):
    """Basic IP pattern validation"""
    # Allow CIDR notation and wildcards
    if ip_str in ["any", "*"]:
        return True
    
    # Basic IPv4 pattern check
    import re
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    return bool(re.match(ipv4_pattern, ip_str))

alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsgs = []

def process_rules(rulelist): #function for processing each rule and add each segment of the rule to the right list at the right index, concatenation of the same index of each list will give us therule back
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs

    alertprotocols = []
    alertdestips = []
    alertsrcips = []
    alertsrcports = []
    alertdestports = []
    alertmsgs = []

    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")

        if rulewords[2] != "any":
            srcip = rulewords[2]
            alertsrcips.append(srcip.lower())
        else:
            alertsrcips.append("any")
        if rulewords[3] != "any":
            srcport = int(rulewords[3])
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")
        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")
        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")

        try:
            alertmsgs.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))  #join whatever is present after the destination ip and append it as a message
        except:
            alertmsgs.append("")
            pass

process_rules(readrules())

# Cross-platform file paths
def get_cross_platform_paths():
    """Get appropriate file paths for the current platform"""
    if platform.system() == "Windows":
        ssl_log_path = os.path.expanduser("~/ssl_keys.log")
        temp_dir = ".\\temp\\"
        saved_dir = ".\\savedpcap\\"
    else:
        ssl_log_path = os.path.expanduser("~/ssl_keys.log")
        temp_dir = "./temp/"
        saved_dir = "./savedpcap/"
    
    # Ensure directories exist
    os.makedirs(os.path.dirname(temp_dir) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(saved_dir) or ".", exist_ok=True)
    
    return ssl_log_path, temp_dir, saved_dir

def create_pcap_file_safely(filepath: str, packets: list) -> bool:
    """Safely create a pcap file with proper permissions for tshark access"""
    try:
        # Ensure directory exists with proper permissions
        dir_path = os.path.dirname(filepath)
        if dir_path:
            os.makedirs(dir_path, mode=0o755, exist_ok=True)
            
            # Fix directory permissions if running as root
            if ENHANCEMENTS_AVAILABLE:
                from error_handling import fix_file_permissions
                fix_file_permissions(dir_path, mode=0o755)
        
        # Get the original user if running as sudo
        original_user = os.environ.get('SUDO_USER')
        
        # Write the pcap file
        scp.wrpcap(filepath, packets)
        
        # Set file permissions to be readable by all (required for tshark)
        os.chmod(filepath, 0o644)
        
        # If we're running as root but original user exists, fix ownership
        if original_user and os.geteuid() == 0:
            try:
                user_info = pwd.getpwnam(original_user)
                os.chown(filepath, user_info.pw_uid, user_info.pw_gid)
                logging.debug(f"Fixed ownership of {filepath} to {original_user}")
            except (KeyError, OSError) as e:
                logging.debug(f"Could not fix ownership: {e}")
        
        # Verify file was created and is accessible
        if not os.path.exists(filepath):
            logging.error(f"Failed to create pcap file: {filepath}")
            return False
        
        if not os.access(filepath, os.R_OK):
            logging.error(f"Pcap file is not readable: {filepath}")
            if ENHANCEMENTS_AVAILABLE:
                from error_handling import handle_permission_error, PermissionError
                handle_permission_error(
                    PermissionError("File not readable"), 
                    filepath, 
                    "Ensure tshark has read access to temp directory"
                )
            return False
        
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            logging.warning(f"Pcap file is empty: {filepath}")
            return False
        
        logging.info(f"Pcap file created successfully: {filepath} ({file_size} bytes)")
        return True
        
    except Exception as e:
        logging.error(f"Error creating pcap file {filepath}: {e}")
        if ENHANCEMENTS_AVAILABLE:
            from error_handling import handle_error, handle_permission_error
            if "permission" in str(e).lower() or "access" in str(e).lower():
                handle_permission_error(e, filepath, "Try running SCAPA with sudo for full functionality")
            else:
                handle_error(e, f"pcap file creation: {filepath}")
        return False

def create_secure_pcap_file(filename, packet_list):
    """Create a pcap file with proper permissions that tshark can read"""
    try:
        # Get the original user if running as sudo
        original_user = os.environ.get('SUDO_USER')
        
        # Create the file
        scp.wrpcap(filename, packet_list)
        
        # Set permissions to be readable by all
        os.chmod(filename, 0o644)
        
        # If we're running as root but original user exists, fix ownership
        if original_user and os.geteuid() == 0:
            try:
                user_info = pwd.getpwnam(original_user)
                os.chown(filename, user_info.pw_uid, user_info.pw_gid)
                logging.debug(f"Fixed ownership of {filename} to {original_user}")
            except (KeyError, OSError) as e:
                logging.debug(f"Could not fix ownership: {e}")
        
        # Verify the file is readable
        if not os.access(filename, os.R_OK):
            raise PermissionError(f"Created file {filename} is not readable")
        
        logging.info(f"Pcap file created successfully: {filename} ({os.path.getsize(filename)} bytes)")
        return True
        
    except Exception as e:
        logging.error(f"Failed to create secure pcap file {filename}: {e}")
        return False

# Get platform-specific paths
SSLLOGFILEPATH, TEMP_DIR, SAVED_DIR = get_cross_platform_paths()


MLresult = []
pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
tcpstreams = []
http2streams=[]
logdecodedtls = True
httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []
updatepktlist = True  # Start capturing packets immediately


#--------------------------------------------------GUI-------------------------------------

sg.theme('Topanga')

layout = [[sg.Button('STARTCAP', key="-startcap-"),
           sg.Button('STOPCAP', key='-stopcap-'), sg.Button('SAVE ALERT', key='-savepcap-'),
           sg.Button('REFRESH RULES', key='-refreshrules-'),
           sg.Button('LOAD TCP/HTTP2 STREAMS', key='-showtcpstreamsbtn-'),
           sg.Button('LOAD HTTP STREAMS', key='-showhttpstreamsbtn-'),
           sg.Button('PERFORMANCE', key='-performance-'),
           ],
          [sg.Text("ALERT PACKETS", font=('Arial Bold', 14), size=(65, None), justification="left"),
           sg.Text("ALL PACKETS", font=('Arial Bold', 14), size=(60, None), justification="left")
           ],
          [sg.Listbox(key='-pkts-', size=(110,20), values=suspiciouspackets, enable_events=True),
           sg.Listbox(key='-pktsall-', size=(110,20), values=pktsummarylist, enable_events=True),
           ],
          [sg.Text("ALERT DECODED", font=('Arial Bold', 18), size=(35, None),justification="left"),
           sg.Text("HTTP2 STREAMS", font=('Arial Bold', 14),justification="left", pad = ((205, 0), 0)),
           sg.Text("TCP STREAMS", font=('Arial Bold', 14),justification="left", pad = ((40, 0), 0)),
           sg.Text("HTTP OBJECTS", font=('Arial Bold', 14),justification="left", pad = ((60, 0), 0)),
           sg.Text("ATTACK TYPE", font=('Arial Bold', 14),justification="left", pad = ((35, 0), 0))
           ],
          [sg.Multiline(size=(100,20), key='-payloaddecoded-'),
           sg.Listbox(key='-http2streams-', size=(25, 20), values=http2streams, enable_events=True),
           sg.Listbox(key='-tcpstreams-', size=(25,20), values=tcpstreams, enable_events=True),
           sg.Listbox(key='-httpobjects-', size=(25, 20), values=httpobjectindexes, enable_events=True),
           sg.Listbox(key='-ML-', size=(33, 20), values=MLresult, enable_events=True)
           ],
          [sg.Text("Performance Monitor:", font=('Arial Bold', 10)), 
           sg.Text("CPU: 0%", key='-cpu-', font=('Arial', 10)),
           sg.Text("Memory: 0MB", key='-memory-', font=('Arial', 10)),
           sg.Text("Packets: 0", key='-packets-', font=('Arial', 10)),
           sg.Text("Status: READY", key='-status-', font=('Arial', 10), text_color='orange'),
           sg.Push(),
           sg.Button('Exit')]]

# Initialize enhanced SCAPA modules
if ENHANCEMENTS_AVAILABLE:
    # Setup enhanced logging
    setup_logging()
    logging.info("SCAPA starting with enhanced modules")
    
    # Start performance monitoring
    if performance_monitor:
        performance_monitor.start_monitoring()
        logging.info("Performance monitoring started")
    
    # Initialize rules engine
    try:
        rules_engine = RulesEngine()
        logging.info("Enhanced rules engine initialized")
    except Exception as e:
        logging.warning(f"Failed to initialize enhanced rules engine: {e}")
        rules_engine = None
else:
    logging.warning("Running SCAPA in basic mode (enhancements not available)")
    rules_engine = None

window = sg.Window('SCAPA', layout, size=(1600,800), resizable=True)

pkt_list = []


def get_http_headers(http_payload):           #This function obtains the http headers from http payload
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]    #fetches the raw headers to parse
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw))

    except ValueError as err:
        logging.error('Could not find \\r\\n\\r\\n - %s' % err)
        return None
    except Exception as err:
        logging.error('Exception found trying to parse raw headers - %s' % err)
        logging.debug(str(http_payload))
        return None

    if b"Content-Type" not in headers:
        logging.debug('Content Type not present in headers')
        logging.debug(headers.keys())
        return None
    return headers

def extract_object(headers, http_payload): # This function extracts the http objects given pyloads and the headers
    object_extracted = None
    object_type = None

    content_type_filters = [b'application/x-msdownload', b'application/octet-stream']

    try:
        if b'Content-Type' in headers.keys():
            #if headers[b'Content-Type'] in content_type_filters:
            object_extracted = http_payload[http_payload.index(b"\r\n\r\n") +4:]
            object_type = object_extracted[:2]
            logging.info("Object Type: %s" % object_type)
        else:
            logging.info('No Content Type in Package')
            logging.debug(headers.keys())

        if b'Content-Length' in headers.keys():
            logging.info( "%s: %s" % (b'Content-Lenght', headers[b'Content-Length']))
    except Exception as err:
        logging.error('Exception found trying to parse headers - %s' % err)
        return None, None
    return object_extracted, object_type

def read_http():   #This function creats a temporary pcap file containing captured data in the temp folder then reads it and parses it to read http payloads
    objectlist = []
    objectsactual = []
    objectsactualtypes = []
    objectcount = 0
    global pkt_list
    try:
        os.remove(os.path.join(TEMP_DIR, "httpstreamread.pcap"))
    except:
        pass
    httppcapfile = os.path.join(TEMP_DIR, "httpstreamread.pcap")
    
    # Create HTTP pcap file safely with enhanced permission handling
    if not create_pcap_file_safely(httppcapfile, pkt_list):
        if ENHANCEMENTS_AVAILABLE:
            from error_handling import handle_permission_error, FileCreationError
            handle_permission_error(
                FileCreationError("HTTP pcap creation failed"), 
                httppcapfile, 
                "Check temp directory permissions and try running with sudo"
            )
        logging.error("Failed to create HTTP stream pcap file")
        return [], [], []
    pcap_flow = scp.rdpcap(httppcapfile)
    sessions_all = pcap_flow.sessions()

    for session in sessions_all:
        http_payload = bytes()
        for pkt in sessions_all[session]:
            if pkt.haslayer("TCP"):
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80 or pkt["TCP"].dport == 8080 or pkt["TCP"].sport == 8080:
                    if pkt["TCP"].payload:
                        payload = pkt["TCP"].payload
                        http_payload += scp.raw(payload)
        if len(http_payload):
            http_headers = get_http_headers(http_payload)

            if http_headers is None:
                continue

            object_found, object_type = extract_object(http_headers, http_payload)

            if object_found is not None and object_type is not None:
                objectcount += 1
                objectlist.append(objectcount-1)
                objectsactual.append(object_found)
                objectsactualtypes.append(object_type)

    return objectlist, objectsactual, objectsactualtypes


def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"
Alert_Lock = True
def check_rules_warning(pkt):      #function to check if the packet should be flagged according to the rules
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    global sus_readablepayloads
    global updatepktlist
    global proto
    global Alert_Lock
    
    # Use enhanced rules engine if available
    if ENHANCEMENTS_AVAILABLE and rules_engine:
        try:
            return rules_engine.evaluate_packet(pkt)
        except Exception as e:
            logging.error(f"Enhanced rules engine error: {e}")
            # Fall back to original implementation
    
    # Original rules checking logic (fallback)
    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()   #protocol number to protocol name
            sport = pkt['IP'].sport
            dport = pkt['IP'].dport

            for i in range(len(alertprotocols)):
                flagpacket = False
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest
                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src
                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport

                if "/" not in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (str(src).strip() == str(chksrcip).strip() and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" in str(chksrcip).strip() and "/" not in str(chkdestip).strip():
                    if (ipaddress.IPv4Address(str(src).strip()) in ipaddress.IPv4Network(str(chksrcip).strip()) and str(dest).strip() == str(chkdestip).strip() and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True
                if "/" not in str(chksrcip).strip() and "/" in str(chkdestip).strip():
                    if (str(src).strip() == str(chksrcip).strip() and ipaddress.IPv4Address(str(dest).strip()) in ipaddress.IPv4Network(str(chkdestip).strip()) and str(proto).strip() == str(chkproto).strip() and str(dport).strip() == str(chkdestport).strip() and str(sport).strip() == str(chksrcport).strip()):
                        flagpacket = True

                if flagpacket:
                    if Alert_Lock:
                        alert_user("ALERT !!!!!!!!!\nSuspicious Packet has been Captured")
                        Alert_Lock = False
                    if proto == "tcp":
                        try:
                            readable_payload = bytes(pkt['TCP'].payload).decode("utf-8", errors="replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode("utf-8", errors="replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting udp payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("NOT TCP PACKET!!")
                    if updatepktlist:
                        window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
                    return True, str(alertmsgs[i])
        except:
            pkt.show()

    return False, ""

# Track connection and error statistics
connections = defaultdict(list)  # Store connection data per IP
error_stats = defaultdict(lambda: {'syn_errors': 0, 'rej_errors': 0})  # Track errors
same_service_stats = defaultdict(lambda: {'same_service': 0, 'diff_service': 0})  # Track same/diff service connections
time_window = 2  # Time window in seconds for rate calculations

# Initialize global variables for capturing features
start_time = None
#protocol_type = ""
service = ""
src_bytes = 0
dst_bytes = 0
flag = ""
land = 0
wrong_fragment = 0
urgent = 0
num_outbound_cmds = 0
count = 0
srv_count = 0
serror_rate = 0
rerror_rate = 0
same_srv_rate = 0
diff_srv_rate = 0
srv_diff_host_rate = 0
duration = 0

# Safe model loading with validation
def load_ml_models():
    """Safely load ML models with validation"""
    required_files = ['model.pkl', 'fmap.pkl', 'pmap.pkl']
    
    for file_path in required_files:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Required ML model file not found: {file_path}")
    
    try:
        # Load with size limits for security
        with open('model.pkl', 'rb') as file:
            # Limit file size to prevent memory attacks
            file_size = os.path.getsize('model.pkl')
            if file_size > 100 * 1024 * 1024:  # 100MB limit
                raise ValueError("Model file too large, possible security risk")
            model = pickle.load(file)
            
        with open('fmap.pkl', 'rb') as file:
            file_size = os.path.getsize('fmap.pkl')
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError("Feature map file too large, possible security risk")
            fmap = pickle.load(file)
            
        with open('pmap.pkl', 'rb') as file:
            file_size = os.path.getsize('pmap.pkl')
            if file_size > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError("Protocol map file too large, possible security risk")
            pmap = pickle.load(file)
            
        logging.info("ML models loaded successfully")
        return model, fmap, pmap
        
    except Exception as e:
        logging.error(f"Failed to load ML models: {e}")
        raise

# Load models safely
try:
    model, fmap, pmap = load_ml_models()
except Exception as e:
    logging.error(f"ML models unavailable: {e}")
    model, fmap, pmap = None, None, None

# Performance optimization: batch ML predictions
ml_batch_queue = []
ml_batch_size = 10  # Process ML in batches of 10 packets
ml_last_process_time = time.time()

def should_analyze_with_ml(pkt):
    """Filter packets that need ML analysis"""
    # Only analyze TCP/UDP/ICMP packets
    if not (pkt.haslayer(TCP) or pkt.haslayer(UDP) or pkt.haslayer(ICMP)):
        return False
    
    # Skip local traffic
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        # Skip localhost traffic
        if src_ip.startswith('127.') or dst_ip.startswith('127.'):
            return False
        
        # Skip private network internal traffic (optional)
        # if src_ip.startswith('192.168.') and dst_ip.startswith('192.168.'):
        #     return False
    
    return True

def process_ml_batch():
    """Process accumulated ML predictions in batch"""
    global ml_batch_queue, MLresult
    
    if not ml_batch_queue or not model:
        return
    
    try:
        # Process all packets in batch
        batch_data = []
        for pkt_data in ml_batch_queue:
            batch_data.append(pkt_data['features'])
        
        # Batch prediction
        predictions = model.predict(numpy.array(batch_data))
        
        # Update results
        for i, prediction in enumerate(predictions):
            clean_prediction = str(prediction).strip("[]'\"")
            MLresult.append(f"{len(MLresult)} [{clean_prediction}]")
        
        # Clear the batch queue
        ml_batch_queue.clear()
        
    except Exception as e:
        logging.error(f"ML batch processing error: {e}")
        ml_batch_queue.clear()


def pkt_process(pkt):
    global deviceiplist
    global window
    global updatepktlist
    global suspiciouspackets
    global pktsummarylist
    global pkt_list
    global MLresult

    # Always log packet arrival for debugging
    logging.debug(f"Packet received: {pkt.summary()} - updatepktlist={updatepktlist}")

    if not updatepktlist:
        return

    # Performance monitoring - increment packet count
    if performance_monitor:
        performance_monitor.increment_packet_count()

    # Debug logging for packet capture
    logging.info(f"Processing packet {len(pktsummarylist) + 1}: {pkt.summary()}")

    pkt_summary = pkt.summary()
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)

    # Enhanced rule checking with error handling
    try:
        sus_pkt, sus_msg = check_rules_warning(pkt)
        if sus_pkt:
            suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
            suspacketactual.append(pkt)
    except Exception as e:
        if ENHANCEMENTS_AVAILABLE:
            logging.error(f"Error in rule checking: {e}")
        else:
            print(f"Rule checking error: {e}")

    global duration, service, start_time, src_bytes, dst_bytes, flag, land, urgent, wrong_fragment, num_outbound_cmds, count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate
    #global protocol_type
    # Calculate duration (in seconds)
    if start_time is None:
        start_time = time.time()
    duration = 0

    # Determine service (using ports for simplicity)
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        if pkt.sport == 80 or pkt.dport == 80:
            service = "http"
        elif pkt.sport == 443 or pkt.dport == 443:
            service = "https"
        elif pkt.sport == 53 or pkt.dport == 53:
            service = "dns"
        elif pkt.sport == 22 or pkt.dport == 22:
            service = "ssh"
        elif pkt.sport == 23 or pkt.dport == 23:
            service = "telnet"
        elif pkt.sport == 21 or pkt.dport == 21:
            service = "ftp"
            if pkt.haslayer(Raw) and b'PUT' in pkt[Raw].load:
                num_outbound_cmds += 1
        else:
            service = "other"

    # Source and destination bytes (size of packet payload)
    if pkt.haslayer(Raw):
        if pkt[IP].src == pkt[IP].dst:  # Check for land attack
            land = 1
        else:
            land = 0

        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            src_bytes = len(pkt[Raw].load)
            dst_bytes = len(pkt[Raw].load)

    # Flags (e.g., TCP flags for connection status)
    if pkt.haslayer(TCP):
        flags = pkt.sprintf('%TCP.flags%')
        if "S" in flags and "F" in flags:  # SYN and FIN flags both set
            flag = "SF"
        elif "S" in flags:  # SYN flag
            flag = "S"
        elif "F" in flags:  # FIN flag
            flag = "F"
        elif flags == 0x04:
            flag = "REJ"
        else:
            flag = flags  # Could be RST, ACK, PSH, etc.

    # Count number of urgent packets
    if pkt.haslayer(TCP) and pkt[TCP].urgptr > 0:
        urgent += 1

    # Wrong fragment
    if pkt.haslayer(IP) and pkt[IP].frag > 0:
        wrong_fragment += 1

    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        current_time = time.time()

        connections[src_ip] = [conn for conn in connections[src_ip] if current_time - conn['time'] <= time_window]

        # Add new connection
        connections[src_ip].append({'dst_ip': dst_ip, 'service': service, 'time': current_time})

        # Count the number of connections in the last 2 seconds
        count = len([conn for conn in connections[src_ip]])

        # Check for SYN and REJ errors (SYN = 0x02, RST = 0x04)
        if flag == 0x02:  # SYN flag set
            if not pkt[TCP].ack:
                error_stats[src_ip]['syn_errors'] += 1

        if flag == 0x04:  # REJ (RST) flag set
            error_stats[src_ip]['rej_errors'] += 1

        # Calculate error rates (SYN and REJ)
        total_connections = len(connections[src_ip])
        serror_rate = error_stats[src_ip]['syn_errors'] / total_connections if total_connections > 0 else 0
        rerror_rate = error_stats[src_ip]['rej_errors'] / total_connections if total_connections > 0 else 0

        # Calculate same/different service rates
        same_service_count = len([conn for conn in connections[src_ip] if conn['service'] == service])
        diff_service_count = total_connections - same_service_count
        same_srv_rate = same_service_count / total_connections if total_connections > 0 else 0
        diff_srv_rate = diff_service_count / total_connections if total_connections > 0 else 0

        # Track connections to the same service for the `srv_count`
        srv_count = len([conn for conn in connections[src_ip] if conn['service'] == service])

        # Track service error rates (for same service connections)
        srv_total_connections = srv_count

        # Track different host connections to the same service (srv_diff_host_rate)
        srv_diff_host_rate = len(set([conn['dst_ip'] for conn in connections[src_ip] if conn[
            'service'] == service])) / srv_total_connections if srv_total_connections > 0 else 0

    #print(proto)

    # Optimized ML processing - only analyze relevant packets
    if should_analyze_with_ml(pkt) and model and fmap and pmap:
        # Prepare packet features
        Pkt_Info_List = numpy.array([[duration, proto, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent,
                                      num_outbound_cmds, count, srv_count, serror_rate, rerror_rate, same_srv_rate,
                                      diff_srv_rate, round(srv_diff_host_rate,2)]])
        
        # Map features using dictionaries
        if flag not in fmap.keys():
            Pkt_Info_List[0][2] = 0
        else:
            Pkt_Info_List[0][2] = fmap[Pkt_Info_List[0][2]]

        Pkt_Info_List[0][1] = pmap[Pkt_Info_List[0][1]]
        
        # Add to batch queue instead of immediate prediction
        ml_batch_queue.append({
            'features': Pkt_Info_List[0],
            'packet_index': len(pktsummarylist) - 1
        })
        
        # Process batch if conditions are met
        global ml_last_process_time
        current_time = time.time()
        if (len(ml_batch_queue) >= ml_batch_size or 
            current_time - ml_last_process_time > 2.0):  # Process every 2 seconds max
            process_ml_batch()
            ml_last_process_time = current_time

    return

# Enhanced cross-platform network interface detection
def get_network_interfaces():
    """Get available network interfaces for the current platform"""
    try:
        if ENHANCEMENTS_AVAILABLE:
            # Use enhanced network utilities
            interfaces = get_available_interfaces()
            if interfaces:
                # Filter interfaces for scapy compatibility
                scapy_interfaces = []
                for iface in interfaces:
                    # Remove parenthetical descriptions for scapy
                    clean_iface = iface.split(' (')[0] if ' (' in iface else iface
                    if clean_iface not in ['any', 'bluetooth-monitor', 'nflog', 'nfqueue', 'dbus-system', 'dbus-session']:
                        scapy_interfaces.append(clean_iface)
                return scapy_interfaces[:3]  # Limit to 3 active interfaces
        
        # Fallback to original implementation
        if platform.system() == "Windows":
            # Windows-specific interface detection
            ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]
        else:
            # Unix-like systems (Linux, macOS)
            from scapy.all import get_if_list
            ifaces = get_if_list()
            # Filter out loopback and special interfaces
            ifaces = [iface for iface in ifaces if iface not in ['lo', 'any'] and not iface.startswith('docker')]
        
        logging.info(f"Available network interfaces for packet capture: {ifaces}")
        return ifaces[:3] if len(ifaces) > 3 else ifaces  # Limit to first 3 interfaces
    except Exception as e:
        logging.error(f"Error getting network interfaces: {e}")
        # Fallback to None to let scapy auto-detect
        return None

# Get interfaces and start packet capture
available_interfaces = get_network_interfaces()
logging.info(f"Initializing packet capture on interfaces: {available_interfaces}")

# Check if we have permission for packet capture
try:
    if os.geteuid() != 0 and platform.system() != "Windows":
        logging.warning("Not running as root - packet capture may be limited")
        logging.info("For full packet capture, run: sudo python main.py")
except:
    pass

# Start packet sniffer thread
try:
    # Choose the best interface for packet capture
    capture_interface = None
    if available_interfaces:
        # Prefer wlan/wifi interfaces, then ethernet, then others
        preferred_interfaces = ['wlp0s20f3', 'wlan0', 'wifi0', 'eth0', 'enp0s31f6']
        for preferred in preferred_interfaces:
            if preferred in available_interfaces:
                capture_interface = preferred
                break
        # If no preferred interface found, use the first non-loopback interface
        if not capture_interface:
            for iface in available_interfaces:
                if iface not in ['lo', 'any', 'bluetooth-monitor', 'nflog', 'nfqueue', 'dbus-system', 'dbus-session']:
                    capture_interface = iface
                    break
    
    # Last resort: use 'any' to capture on all interfaces
    if not capture_interface:
        capture_interface = 'any'
        logging.warning("No specific interface found, using 'any' for capture")
    
    logging.info(f"Starting packet capture on interface: {capture_interface}")
    
    # Test interface accessibility
    try:
        result = subprocess.run(['ip', 'link', 'show', capture_interface], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            logging.info(f"Interface {capture_interface} is available")
        else:
            logging.warning(f"Interface {capture_interface} may not be accessible")
    except Exception as e:
        logging.debug(f"Could not verify interface: {e}")
    
    sniffthread = threading.Thread(target=scp.sniff, kwargs={
        "prn": pkt_process, 
        "filter": "", 
        "iface": capture_interface,
        "store": False,  # Don't store packets in scapy's internal list
        "count": 0  # Capture indefinitely (0 = no limit)
    }, daemon=True)
    sniffthread.start()
    logging.info("Packet capture thread started successfully")
except PermissionError as e:
    logging.error("Permission denied for packet capture - raw socket access required")
    logging.info("Solution 1: Run with sudo: sudo python3 main.py")
    logging.info("Solution 2: Set capabilities: sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
    logging.info("Solution 3: Use the launcher: ./start_scapa.sh")
except Exception as e:
    logging.error(f"Failed to start packet capture: {e}")
    logging.info("Try running with elevated privileges or check network interface access")

def show_tcp_stream_openwin(tcpstreamtext):     #this function shows it's information in a separate window
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("TCPSTREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def show_http2_stream_openwin(tcpstreamtext):     #this function shows http2 informatiom in a seprate window
    layout = [[sg.Multiline(tcpstreamtext, size=(100,50), key="tcpnewwintext")]]
    window = sg.Window("HTTP2 STREAM", layout, modal=True, size=(1200, 600), resizable=True)
    choice = None
    while True:
        event, values = window.read()
        if event == "Exit" or event == sg.WIN_CLOSED:
            break
    window.close()

def load_tcp_streams(window):     #the fuction reads the latest packet capture after saving it in the temp folder
    """Enhanced TCP stream loading with comprehensive error handling"""
    global http2streams, http2_stream_id
    global logdecodedtls
    global tcpstreams
    
    try:
        # Enhanced error handling for TCP stream analysis
        from error_handling import handle_error
        
        # PyShark configuration is handled via tshark-compatible file copying
        logging.debug("Using tshark-compatible pcap files for PyShark analysis")
        
        # Initialize streams
        tcpstreams = []
        
        # Clean up old file
        try:
            os.remove(os.path.join(TEMP_DIR, "tcpstreamread.pcap"))
        except:
            pass
        
        # Write packet list to file with proper permissions
        tcpstreamfilename = os.path.join(TEMP_DIR, "tcpstreamread.pcap")
        
        if not create_pcap_file_safely(tcpstreamfilename, pkt_list):
            logging.error("Failed to create TCP stream pcap file")
            window["-tcpstreams-"].update(values=[])
            return
        
        try:
            # Use absolute path to avoid path resolution issues
            abs_tcpstreamfilename = os.path.abspath(tcpstreamfilename)
            
            # Create tshark-compatible copy to work around permission issues
            from error_handling import create_tshark_compatible_pcap, cleanup_temp_pcap
            tshark_pcap_path = create_tshark_compatible_pcap(abs_tcpstreamfilename)
            
            cap1 = pyshark.FileCapture(
                tshark_pcap_path,
                display_filter="tcp.seq==1 && tcp.ack==1 && tcp.len==0",
                keep_packets=True,
                tshark_path="/usr/bin/tshark")  # Direct path fallback
            
            number_of_streams = 0
            packet_count = 0
            
            for pkt in cap1:
                packet_count += 1
                if packet_count > 10000:  # Prevent infinite loops
                    logging.warning("Too many packets, limiting stream analysis")
                    break
                    
                if pkt.highest_layer.lower() == "tcp" or pkt.highest_layer.lower() == "tls":
                    try:
                        stream_num = int(pkt.tcp.stream)
                        if stream_num > number_of_streams:
                            number_of_streams = stream_num + 1
                    except (AttributeError, ValueError) as e:
                        logging.debug(f"Stream parsing error: {e}")
                        continue
            
            # Generate stream list
            for i in range(0, number_of_streams):
                tcpstreams.append(i)
                
            # Ensure file handle is closed
            try:
                cap1.close()
            except:
                pass
            
            # Cleanup temporary file
            cleanup_temp_pcap(tshark_pcap_path)
            
            logging.info(f"Loaded {len(tcpstreams)} TCP streams from {packet_count} packets")
            
        except Exception as pyshark_error:
            logging.error(f"PyShark TCP stream analysis failed: {pyshark_error}")
            handle_error(pyshark_error, "TCP stream analysis")
            # Fallback: provide empty streams
            tcpstreams = []
        
        # Update GUI safely
        try:
            window["-tcpstreams-"].update(values=[])
            window["-tcpstreams-"].update(values=tcpstreams)
        except Exception as gui_error:
            logging.error(f"GUI update failed: {gui_error}")
        
    except Exception as e:
        logging.error(f"Critical error in load_tcp_streams: {e}")
        try:
            from error_handling import handle_error
            handle_error(e, "load_tcp_streams")
        except:
            pass
        # Ensure GUI is updated even on error
        try:
            if 'window' in locals() and window:
                window["-tcpstreams-"].update(values=[])
        except:
            pass

    # HTTP2 stream analysis
    if logdecodedtls == True:
        try:
            http2streams = []
            
            # Verify file exists and is readable before HTTP2 analysis
            if not os.path.exists(tcpstreamfilename) or not os.access(tcpstreamfilename, os.R_OK):
                logging.warning("TCP stream file not accessible for HTTP2 analysis")
                window['-http2streams-'].update(values=[])
                return
            
            # Use absolute path for HTTP2 analysis too
            abs_tcpstreamfilename = os.path.abspath(tcpstreamfilename)
            
            # Create tshark-compatible copy for HTTP2 analysis
            from error_handling import create_tshark_compatible_pcap, cleanup_temp_pcap
            tshark_pcap_path = create_tshark_compatible_pcap(abs_tcpstreamfilename)
            
            cap2 = pyshark.FileCapture(tshark_pcap_path, 
                                     display_filter="http2.streamid",
                                     keep_packets=True,
                                     tshark_path="/usr/bin/tshark")  # Direct path fallback
            for pkt in cap2:
                field_names = pkt.http2._all_fields
                for field_name in field_names:
                    http2_stream_id = {val for key, val in field_names.items() if key == 'http2.streamid'}
                    http2_stream_id = "".join(http2_stream_id)
                if http2_stream_id not in http2streams:
                    http2streams.append(http2_stream_id)
            window['-http2streams-'].update(values=http2streams)
            cap2.close()
            
            # Cleanup temporary file for HTTP2
            cleanup_temp_pcap(tshark_pcap_path)
        except Exception as http2_error:
            logging.error(f"HTTP2 stream analysis failed: {http2_error}")
            http2streams = []
            window['-http2streams-'].update(values=http2streams)

def show_http2_stream(window, streamno):         #Show the selected hhp2 stream in a new window
    global SSLLOGFILEPATH
    tcpstreamfilename = os.path.join(TEMP_DIR, "tcpstreamread.pcap")
    abs_tcpstreamfilename = os.path.abspath(tcpstreamfilename)
    
    # Create tshark-compatible copy for HTTP2 stream display
    from error_handling import create_tshark_compatible_pcap, cleanup_temp_pcap
    tshark_pcap_path = create_tshark_compatible_pcap(abs_tcpstreamfilename)
    
    cap3 = pyshark.FileCapture(tshark_pcap_path, display_filter = f'http2.streamid eq {str(http2streamindex)}', override_prefs={'ssl.keylog_file': SSLLOGFILEPATH})
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        try:
            payload = pkt["TCP"].payload
            http_payload += scp.raw(payload)
        except:
            pass

        print(pkt.http2.stream)
        if ("DATA" not in pkt.http2.stream):
            http2headerdat = ''
            rawvallengthpassed = False
            print(pkt.http2._all_fields.items())
            for field, val in pkt.http2._all_fields.items():
                if rawvallengthpassed == False:
                    if field == 'http2.header.name.length':
                        rawvallengthpassed = True
                else:
                    http2headerdat += str(field.split(".")[-1]) + " : " + str(val) + " \n"
                    print(http2headerdat)
            dat += "\n" + http2headerdat

    if len(http_payload):
        http_headers = get_http_headers(http_payload)

        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)

            dat += object_type + "\n" + object_found + "\n"

    print(dat)
    formatteddat = dat
    print(formatteddat)
    show_http2_stream_openwin(formatteddat)
    
    # Cleanup temporary file for HTTP2 stream display
    cleanup_temp_pcap(tshark_pcap_path)
    pass

def show_tcpstream(window, streamno):  #pyshark filter tcp steams and check if it's decodable by cross checking with ssl log file
    global SSLLOGFILEPATH
    tcpstreamfilename = os.path.join(TEMP_DIR, "tcpstreamread.pcap")
    abs_tcpstreamfilename = os.path.abspath(tcpstreamfilename)
    streamnumber = streamno
    
    # Create tshark-compatible copy for TCP stream display
    from error_handling import create_tshark_compatible_pcap, cleanup_temp_pcap
    tshark_pcap_path = create_tshark_compatible_pcap(abs_tcpstreamfilename)
    
    cap = pyshark.FileCapture(
        tshark_pcap_path,
        display_filter = 'tcp.stream eq %d' % streamnumber,
        override_prefs={'ssl.keylog_file': SSLLOGFILEPATH}
    )

    dat = b""
    decode_hex = codecs.getdecoder("hex_codec")
    for pkt in cap:
        try:
            payload = pkt.tcp.payload
            encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            dat += encryptedapplicationdata_hex_decoded
        except Exception as ex:
            print(ex)

    formatteddat = str(dat, "ascii", "replace")

    if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
        sg.PopupAutoClose("No data")
    else:
        show_tcp_stream_openwin(formatteddat)
    
    # Cleanup temporary file for TCP stream display
    cleanup_temp_pcap(tshark_pcap_path)

def show_performance_window():
    """Show detailed performance statistics window"""
    if not performance_monitor:
        sg.popup("Performance monitoring not available")
        return
    
    stats = performance_monitor.get_current_stats()
    suggestions = performance_monitor.get_optimization_suggestions()
    
    if not stats:
        sg.popup("No performance data available yet")
        return
    
    # Create performance display layout
    perf_layout = [
        [sg.Text("SCAPA Performance Monitor", font=('Arial Bold', 16))],
        [sg.HorizontalSeparator()],
        [sg.Text("System Performance:", font=('Arial Bold', 12))],
        [sg.Text(f"Uptime: {stats['uptime']}")],
        [sg.Text(f"CPU Usage: {stats['cpu_current']:.1f}% (avg: {stats['cpu_average']:.1f}%, peak: {stats['cpu_peak']:.1f}%)")],
        [sg.Text(f"Memory Usage: {stats['memory_current']:.1f} MB (avg: {stats['memory_average']:.1f} MB, peak: {stats['memory_peak']:.1f} MB)")],
        [sg.Text(f"Packets Processed: {stats['total_packets']}")],
        [sg.Text(f"Processing Rate: {stats['packet_rate']:.1f} packets/sec")],
        [sg.HorizontalSeparator()],
        [sg.Text("Optimization Suggestions:", font=('Arial Bold', 12))],
    ]
    
    if suggestions:
        for i, suggestion in enumerate(suggestions, 1):
            perf_layout.append([sg.Text(f"{i}. {suggestion}")])
    else:
        perf_layout.append([sg.Text("No optimization suggestions - performance is good!")])
    
    perf_layout.extend([
        [sg.HorizontalSeparator()],
        [sg.Button("Export Report", key='-export-'), sg.Button("Close")]
    ])
    
    perf_window = sg.Window("SCAPA Performance Monitor", perf_layout, modal=True, size=(600, 400), resizable=True)
    
    while True:
        event, values = perf_window.read()
        if event in (None, 'Close'):
            break
        elif event == '-export-':
            try:
                filename = performance_monitor.export_stats()
                sg.popup(f"Performance report exported to:\n{filename}")
            except Exception as e:
                sg.popup_error(f"Failed to export report: {e}")
    
    perf_window.close()

while True:

    #print(suspiciouspackets)

    event, values = window.read(timeout=100)  # Add timeout for performance updates
    
    # Update performance display
    if ENHANCEMENTS_AVAILABLE and performance_monitor:
        try:
            stats = performance_monitor.get_current_stats()
            if stats:
                window['-cpu-'].update(f"CPU: {stats['cpu_current']:.1f}%")
                window['-memory-'].update(f"Memory: {stats['memory_current']:.0f}MB")
                window['-packets-'].update(f"Packets: {stats['total_packets']}")
        except Exception:
            pass  # Ignore performance update errors
    
    # Update capture status
    if updatepktlist:
        if len(pktsummarylist) > 0:
            window['-status-'].update(f"CAPTURING ({len(pktsummarylist)} pkts)", text_color='green')
        else:
            window['-status-'].update("CAPTURING", text_color='green')
    elif len(pktsummarylist) > 0:
        window['-status-'].update(f"STOPPED ({len(pktsummarylist)} pkts)", text_color='orange')
    else:
        window['-status-'].update("READY", text_color='orange')
    
    if event == '-refreshrules-':
        process_rules(readrules())
    if event == '-performance-' and ENHANCEMENTS_AVAILABLE and performance_monitor:
        show_performance_window()
    if event == "-startcap-":
        updatepktlist = True
        logging.info("Packet capture started by user")
        window['-status-'].update("CAPTURING", text_color='green')
        #clear out all lists when new packet capture is started
        MLresult = []
        incomingpacketlist = []
        inc_pkt_list = []
        suspiciouspackets = []
        suspacketactual = []
        pktsummarylist = []
        sus_readablepayloads = []
        while True:
            event, values = window.read(timeout=10)
            if event == "-stopcap-":  # User clicked Stop
                updatepktlist = False  # Stop capturing packets
                Alert_Lock = True
                logging.info("Packet capture stopped by user")
                window['-status-'].update("STOPPED", text_color='red')
                # Ensure packet data is retained and listboxes remain functional
                window["-pkts-"].update(values=suspiciouspackets)  # Retain suspicious packets list
                window["-ML-"].update(values=MLresult)  # Retain ML results list
                break

            if event == '-refreshrules-':
                process_rules(readrules())
            if event == sg.TIMEOUT_EVENT:
                window['-pkts-'].update(suspiciouspackets, scroll_to_index=len(suspiciouspackets))
                window['-pktsall-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                window["-ML-"].update(MLresult, scroll_to_index=len(MLresult))
            if event in (None, 'Exit'):
                sys.exit()


            if event == "-pkts-" and len(values["-pkts-"]):  # User clicked on an alerted packet
                selected_index = window["-pkts-"].get_indexes()[0]  # Get the index of the selected packet
                try:
                    # Fetch the corresponding packet
                    packet = suspacketactual[selected_index]  # Get the actual suspicious packet

                    # Decode packet details using Scapy's show() and raw payload
                    packet_headers = packet.show(dump=True)  # Get detailed packet headers
                    packet_payload = ""
                    if packet.haslayer("Raw"):  # Check for payload
                        packet_payload = packet["Raw"].load.decode("utf-8", errors="replace")

                    # Update the decoding section of the GUI dynamically
                    window["-payloaddecoded-"].update(value=f"{packet_headers}\n\nPayload:\n{packet_payload}")

                except IndexError:
                    sg.Popup("No corresponding packet found for the selected alert!", auto_close=True)

            if event == "-ML-" and len(values["-ML-"]):  # User clicked on an ML result
                selected_index = window["-ML-"].get_indexes()[0]  # Get the index of the selected ML result
                try:
                    # Fetch the corresponding packet
                    packet = pkt_list[selected_index]  # Get the ML-related packet

                    # Decode packet details using Scapy's show() and raw payload
                    packet_headers = packet.show(dump=True)  # Get detailed packet headers

                    # Update the decoding section of the GUI dynamically
                    window["-payloaddecoded-"].update(value=f"{packet_headers}\n")

                except IndexError:
                    sg.Popup("No corresponding packet found for the selected ML result!", auto_close=True)

            if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
                pkt_selected_index = window["-pktsall-"].get_indexes()[0]
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass

            if event == "-showtcpstreamsbtn-":      # load tcp streams btn
                load_tcp_streams(window)
            if event == "-tcpstreams-":
                streamindex = window["-tcpstreams-"].get_indexes()[0]
                show_tcpstream(window, streamindex)
            if event == "-http2streams-":
                http2streamindex = values[event][0]
                show_http2_stream(window, str(int(http2streamindex)))
            if event == "-showhttpstreamsbtn-":         # load http streams btn
                httpobjectindexes = []
                httpobjectactuals = []
                httpobjecttypes = []
                httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
                window["-httpobjects-"].update(values=httpobjectindexes)
            if event == "-httpobjects-":
                httpobjectindex = values[event][0]
                show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])


    if event == '-savepcap-':
        pcapname = "savedalert"
        create_pcap_file_safely(os.path.join(SAVED_DIR, f'{pcapname}.pcap'), pkt_list)

    if event in (None, 'Exit'):
        break

# Enhanced cleanup
if ENHANCEMENTS_AVAILABLE:
    # Stop performance monitoring
    if performance_monitor:
        performance_monitor.stop_monitoring()
        logging.info("Performance monitoring stopped")
    
    # Export final performance report
    if performance_monitor:
        try:
            report_file = performance_monitor.export_stats()
            logging.info(f"Final performance report saved to {report_file}")
        except Exception as e:
            logging.error(f"Failed to export performance report: {e}")
    
    logging.info("SCAPA shutdown complete")

window.close()
