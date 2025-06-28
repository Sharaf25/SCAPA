import scapy.all as scp
import codecs
import FreeSimpleGUI as sg
import os
import threading
import sys
import pyshark
import socket
import scapy.arch.windows as scpwinarch
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import time
from collections import defaultdict
import json
import logging
import re
import ipaddress
import subprocess
import pprint
import glob
import pickle
import numpy
import winsound
from plyer import notification
from sklearn.ensemble import RandomForestClassifier

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#rules ---->        instruction  protocol  sourceIP  sourcePort  direction  destinationIP  destinationPort  message


def alert_user(message):
    """Send desktop notification with sound"""
    # Play alert sound
    winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)

    # Use PySimpleGUI's non-blocking popup instead of tkinter
    sg.popup_non_blocking("Intrusion Detection Alert",
                          message,
                          auto_close=True,
                          auto_close_duration=5,  # Auto-close after 5 seconds
                          no_titlebar=False,
                          grab_anywhere=True,
                          keep_on_top=True,
                          icon=None)

def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    #print(rules_list)
    return rules_list

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


MLresult = []
pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
tcpstreams = []
SSLLOGFILEPATH = "C:\\Users\\Mostafa\\ssl1.log"
http2streams=[]
logdecodedtls = True
httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []
updatepktlist = False


#--------------------------------------------------GUI-------------------------------------

sg.theme('Topanga')

layout = [[sg.Button('STARTCAP', key="-startcap-"),
           sg.Button('STOPCAP', key='-stopcap-'), sg.Button('SAVE ALERT', key='-savepcap-'),
           sg.Button('REFRESH RULES', key='-refreshrules-'),
           sg.Button('LOAD TCP/HTTP2 STREAMS', key='-showtcpstreamsbtn-'),
           sg.Button('LOAD HTTP STREAMS', key='-showhttpstreamsbtn-'),
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
          [sg.Button('Exit')]]

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
        os.remove(f".\\temp\\httpstreamread.pcap")
    except:
        pass
    httppcapfile = f".\\temp\\httpstreamread.pcap"
    scp.wrpcap(httppcapfile, pkt_list)
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
    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()   #protocol number to protocol name
            # Get sport and dport from TCP/UDP layer instead of IP
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

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

with open ('model.pkl','rb') as file:
    model = pickle.load(file)
with open ('fmap.pkl','rb') as file:
    fmap = pickle.load(file)
with open ('pmap.pkl','rb') as file:
    pmap = pickle.load(file)


def pkt_process(pkt):
    global deviceiplist
    global window
    global updatepktlist
    global suspiciouspackets
    global pktsummarylist
    global pkt_list
    global MLresult

    if not updatepktlist:
        return

    pkt_summary = pkt.summary()
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)

    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
        suspacketactual.append(pkt)


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

    Pkt_Info_List = numpy.array([[duration, proto, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent,
                                  num_outbound_cmds, count, srv_count, serror_rate, rerror_rate, same_srv_rate,
                                  diff_srv_rate, round(srv_diff_host_rate,2)]])
    #print(Pkt_Info_List)
    if flag not in fmap.keys():
        Pkt_Info_List[0][2] = 0
    else:
        Pkt_Info_List[0][2] = fmap[Pkt_Info_List[0][2]]

    Pkt_Info_List[0][1] = pmap[Pkt_Info_List[0][1]]

    model_predict = model.predict(Pkt_Info_List)
    clean_prediction = str(model_predict).strip("[]'\"")          #to remove special characters from the output
    MLresult.append(f"{len(MLresult)} " + f"[{clean_prediction}]")        # add the packet number

    #MLresult.append(model_predict)

    return

ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]  #interfaces name
#print(ifaces)
# Fix the interfaces list creation
ifaces1 = [ifaces[0]]  # Start with the first interface
if len(ifaces) > 6:
    ifaces1.append(ifaces[6])  # Add the 7th interface if it exists
sniffthread = threading.Thread(target=scp.sniff, kwargs={"prn": pkt_process, "filter": "", "iface": ifaces[0:5]},
                               daemon=True)
sniffthread.start()

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
    global http2streams
    global logdecodedtls
    try:
        os.remove(f".\\temp\\tcpstreamread.pcap")
    except:
        pass
    scp.wrpcap(f".\\temp\\tcpstreamread.pcap", pkt_list)
    global tcpstreams
    tcpstreams = []
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap1 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter="tcp.seq==1 && tcp.ack==1 && tcp.len==0",
        keep_packets=True)
    number_of_streams = 0
    for pkt in cap1:
        if pkt.highest_layer.lower() == "tcp" or pkt.highest_layer.lower() == "tls":
            if int(pkt.tcp.stream) > number_of_streams:
                number_of_streams = int(pkt.tcp.stream) + 1
    for i in range(0, number_of_streams):
        tcpstreams.append(i)
    window["-tcpstreams-"].update(values=[])
    window["-tcpstreams-"].update(values=tcpstreams)

    # --- FIXED HTTP2 STREAM EXTRACTION ---
    if logdecodedtls:
        http2streams = []
        cap2 = pyshark.FileCapture(tcpstreamfilename, display_filter="http2", keep_packets=True)
        http2stream_info = []  # Collect HTTP2 stream information
        for pkt in cap2:
            if hasattr(pkt, 'http2') and hasattr(pkt.http2, 'streamid'):
                stream_id = pkt.http2.streamid
                http2stream_info.append(f"Stream ID: {stream_id}")  # Add stream ID to info list
                if stream_id not in http2streams:
                    http2streams.append(stream_id)
        window['-http2streams-'].update(values=http2streams)
        # Store the info for later display (fix: always ensure dict)
        if not hasattr(window, 'metadata') or not isinstance(window.metadata, dict):
            window.metadata = {}
        window.metadata['http2stream_info'] = http2stream_info
        pass

def show_http2_stream(window, streamno):         #Show the selected http2 stream in a new window
    global SSLLOGFILEPATH
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    # --- FIXED: use streamno, not http2streamindex ---
    cap3 = pyshark.FileCapture(
        tcpstreamfilename,
        display_filter = f'http2.streamid == {streamno}',
        override_prefs={'ssl.keylog_file': SSLLOGFILEPATH})
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        try:
            if hasattr(pkt, "TCP") and hasattr(pkt["TCP"], "payload"):
                payload = pkt["TCP"].payload
                http_payload += scp.raw(payload)
        except:
            pass
        # Optionally, collect HTTP2 header info here if needed
    if len(http_payload):
        http_headers = get_http_headers(http_payload)
        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)
            # Ensure bytes are converted to string for display
            dat += str(object_type) + "\n" + str(object_found) + "\n"
    show_http2_stream_openwin(dat)
    pass

def show_tcpstream(window, streamno):  #pyshark filter tcp steams and check if it's decodable by cross checking with ssl log file
    global SSLLOGFILEPATH
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    streamnumber = streamno
    cap = pyshark.FileCapture(
        tcpstreamfilename,
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

while True:

    #print(suspiciouspackets)

    event, values = window.read()
    if event == '-refreshrules-':
        process_rules(readrules())
    if event == "-startcap-":
        updatepktlist = True
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

                    # Decode packet details using Scapy's show(dump=True)  # Get detailed packet headers

                    # Update the decoding section of the GUI dynamically
                    window["-payloaddecoded-"].update(value=f"{packet_headers}\n")

                except IndexError:
                    sg.Popup("No corresponding packet found for the selected ML result!", auto_close=True)

            if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
                #pktselected = values['-pktsall-']
                pkt_selected_index = window["-pktsall-"].get_indexes()
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass

            if event == "-showtcpstreamsbtn-":      # load tcp streams btn
                load_tcp_streams(window)
            if event == "-tcpstreams-":
                streamindex = window["-tcpstreams-"].get_indexes()
                show_tcpstream(window, streamindex)
            if event == "-http2streams-":
                http2streamindex = values[event][0]
                show_http2_stream(window, int(http2streamindex))
            if event == "-showhttpstreamsbtn-":         # load http streams btn
                httpobjectindexes = []
                httpobjectactuals = []
                httpobjecttypes = []
                httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
                window["-httpobjects-"].update(values=httpobjectindexes)
            if event == "-httpobjects-":
                httpobjectindex = values[event][0]
                show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])


    if event == "-showhttpstreamsbtn-":
        httpobjectindexes = []
        httpobjectactuals = []
        httpobjecttypes = []
        httpobjectindexes, httpobjectactuals, httpobjecttypes = read_http()
        window["-httpobjects-"].update(values=httpobjectindexes)
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
    if event == "-httpobjects-":
        httpobjectindex = values[event][0]
        show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])

    if event == "-http2streams-":
        http2streamindex = values[event][0]
        print(http2streamindex)
        show_http2_stream(window, str(int(http2streamindex)))
    if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
        pkt_selected_index = window["-pktsall-"].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
        except:
            pass

    if event == '-savepcap-':
        pcapname = "savedalert"
        scp.wrpcap(f'.\\savedpcap\\{pcapname}.pcap', pkt_list)       #pkt_list works

    if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
        sus_selected = values['-pkts-']
        sus_selected_index = window['-pkts-'].get_indexes()[0]
        try:
            window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
        except:
            pass
        window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index])

    if event == "-showtcpstreamsbtn-":
        load_tcp_streams(window)

    if event == "-tcpstreams-":
        streamindex = window["-tcpstreams-"].get_indexes()
        show_tcpstream(window, streamindex)

    if event in (None, 'Exit'):
        break

window.close()
