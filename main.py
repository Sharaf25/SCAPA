import scapy.all as scp
import codecs
import PySimpleGUI as sg
import os
import threading
import sys
import pyshark
import socket
import scapy.arch.windows as scpwinarch
from scapy.all import sniff, IP, TCP, UDP, Raw
import time
from collections import defaultdict
import json
import logging
import re
import ipaddress
import subprocess
import yara
import pprint
import glob
import pickle
import numpy
from sklearn.ensemble import RandomForestClassifier

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#rules ---->        instruction  protocol  sourceIP  sourcePort  direction  destinationIP  destinationPort  message

def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list

alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsgs = []

# rule format --> "alert [srcip] [srcport] --> [dstip] [dstport] [msg]" [msg] may include spaces and is not within quotes

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

    print(alertprotocols)
    print(alertdestips)
    print(alertsrcips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsgs)

process_rules(readrules())

"""
deviceiplist = []
for route in scp.read_routes():
    if str(route[4]) not in deviceiplist:
        deviceiplist.append(str(route[4]))
        print(str(route[4]))
"""

MLresult = []
pktsummarylist = []
suspiciouspackets = []
suspacketactual = []
lastpacket = ""
sus_readablepayloads = []
all_readablepayloads = []
tcpstreams = []
SSLLOGFILEPATH = "C:\\Users\\Mostafa\\ssl1.log"
http2streams=[]
logdecodedtls = True
httpobjectindexes = []
httpobjectactuals = []
httpobjecttypes = []
#yaraflagged_filenames = []
#reqfilepathbase = "./temp/tcpflowdump/"
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
           sg.Text("Machine Learning", font=('Arial Bold', 14),justification="left", pad = ((35, 0), 0))
           ],
          [sg.Multiline(size=(100,20), key='-payloaddecoded-'),
           sg.Listbox(key='-http2streams-', size=(25, 20), values=http2streams, enable_events=True),
           sg.Listbox(key='-tcpstreams-', size=(25,20), values=tcpstreams, enable_events=True),
           sg.Listbox(key='-httpobjects-', size=(25, 20), values=httpobjectindexes, enable_events=True),
           sg.Listbox(key='-ML-', size=(33, 20), values=MLresult, enable_events=True)
           ],
          [sg.Button('Exit')]]

window = sg.Window('RTNIDS', layout, size=(1600,800), resizable=True)

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
            # else:
            #     logging.debug('Content Type did not matched with filters - %s' % headers[b'Content-Type'])
            #     if len(http_payload) > 10:
            #         logging.debug('Object first 50 bytes - %s' % str(http_payload[:50]))
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

def check_rules_warning(pkt):      #function to check if the packet should be flagged according to the rules
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsgs
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()   #protocol number to protocol name
            #print(proto)
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

                # print("chk \n", str(chksrcip) , str(chkdestip) , str(chkproto) , str(chkdestport) , str(chksrcport))
                # print("act \n", str(src) , str(dest) , str(proto) , str(dport) , str(sport))

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

                if flagpacket == True:
                    # print("Match")
                    if proto == "tcp":
                        try:
                            readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
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

    # for protocol in alertprotocols:
    #     if protocol.upper() in pkt:
    #         pass
    return False, ""


# Track connection and error statistics
connections = defaultdict(list)  # Store connection data per IP
error_stats = defaultdict(lambda: {'syn_errors': 0, 'rej_errors': 0})  # Track errors
same_service_stats = defaultdict(lambda: {'same_service': 0, 'diff_service': 0})  # Track same/diff service connections
time_window = 2  # Time window in seconds for rate calculations

# Initialize global variables for capturing features
start_time = None
protocol_type = ""
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
    global all_readablepayloads
    global pktsummarylist
    global pkt_list
    global MLresult

    pkt_summary = pkt.summary()
    #print("\n", src, " : ", dest, "\n")
    # if dest in deviceiplist:
    #     print(f"\n[*] INCOMING PACKET from \n")
    #     if updatepktlist:

    #     lastpacket = pkt_summary
    #     return pkt_summary
    pktsummarylist.append(f"{len(pktsummarylist)} " + pkt_summary)
    pkt_list.append(pkt)

    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(f"{len(suspiciouspackets)} {len(pktsummarylist) - 1}" + pkt_summary + f" MSG: {sus_msg}")
        suspacketactual.append(pkt)


    # if 'IP' in pkt:
    #     proto = proto_name_by_num(pkt['IP'].proto).lower()
    #     if proto == "tcp":
    #         try:
    #             readable_payload = bytes(pkt['TCP'].payload).decode('UTF8','replace')
    #             all_readablepayloads.append(readable_payload)
    #         except Exception as ex:
    #             all_readablepayloads.append("Error getting tcp payload!!")
    #             print(ex)
    #             pass
    #     elif proto == "udp":
    #         try:
    #             readable_payload = bytes(pkt['UDP'].payload).decode('UTF8','replace')
    #             all_readablepayloads.append(readable_payload)
    #         except Exception as ex:
    #             all_readablepayloads.append("Error getting udp payload!!")
    #             print(ex)
    #             pass
    #     else:
    #         all_readablepayloads.append("NOT TCP PACKET!!")
    #     if updatepktlist:
    #         window['-payloaddecodedall-'].update(value=all_readablepayloads[-1])
    #print(suspiciouspackets)
    #pkt.show()

    global duration, start_time, protocol_type, src_bytes, dst_bytes, flag, land, urgent, wrong_fragment, num_outbound_cmds, count, srv_count, serror_rate, rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate

    # Calculate duration (in seconds)
    if start_time is None:
        start_time = time.time()
    duration = time.time() - start_time

    # Extract protocol type (TCP, UDP)
    if pkt.haslayer(TCP):
        protocol_type = "tcp"
    elif pkt.haslayer(UDP):
        protocol_type = "udp"
    else:
        protocol_type = pkt[IP].proto  # for other IP protocols

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
        if flags == 0x02:  # SYN flag set
            if not pkt[TCP].ack:
                error_stats[src_ip]['syn_errors'] += 1

        if flags == 0x04:  # REJ (RST) flag set
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



    Pkt_Info_List = numpy.array([[duration, protocol_type, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent,
                                  num_outbound_cmds, count, srv_count, serror_rate, rerror_rate, same_srv_rate,
                                  diff_srv_rate, srv_diff_host_rate]])
    if flag not in fmap.keys():
        Pkt_Info_List[0][2] = 0
    else:
        Pkt_Info_List[0][2] = fmap[Pkt_Info_List[0][2]]

    Pkt_Info_List[0][1] = pmap[Pkt_Info_List[0][1]]

    model_predict = model.predict(Pkt_Info_List)

    print(model_predict)

    MLresult.append(model_predict)

    window["-ML-"].update(values=MLresult)

    return

ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]  #interfaces name
#print(ifaces)
ifaces1 = [ifaces[6]].append(ifaces[0])  # Ether and VMnet8
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
            print(pkt.tcp.stream)
            if int(pkt.tcp.stream) > number_of_streams:
                number_of_streams = int(pkt.tcp.stream) + 1
    for i in range(0, number_of_streams):
        tcpstreams.append(i)
    window["-tcpstreams-"].update(values=[])
    window["-tcpstreams-"].update(values=tcpstreams)

    if logdecodedtls == True:
        http2streams = []
        cap2 = pyshark.FileCapture(tcpstreamfilename, display_filter="http2.streamid",keep_packets=True)
        for pkt in cap2:
            field_names = pkt.http2._all_fields
            for field_name in field_names:
                http2_stream_id = {val for key, val in field_names.items() if key == 'http2.streamid'}
                http2_stream_id = "".join(http2_stream_id)
            if http2_stream_id not in http2streams:
                http2streams.append(http2_stream_id)
        window['-http2streams-'].update(values=http2streams)
        pass

global inc_pkt_list
def show_http2_stream(window, streamno):         #Show the selected hhp2 stream in a new window
    global SSLLOGFILEPATH
    tcpstreamfilename = ".\\temp\\tcpstreamread.pcap"
    cap3 = pyshark.FileCapture(tcpstreamfilename, display_filter = f'http2.streamid eq {str(http2streamindex)}', override_prefs={'ssl.keylog_file': SSLLOGFILEPATH})
    #print(cap3[0].http2.stream)
    dat = ""
    decode_hex = codecs.getdecoder("hex_codec")
    http_payload = bytes()
    for pkt in cap3:
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        try:
            payload = pkt["TCP"].payload
            http_payload += scp.raw(payload)
            #does literally nothing because we do not know the encoding format of the payload so scp.raw returns type error
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
                    #if field.split(".")[-1] != "headers":
                    http2headerdat += str(field.split(".")[-1]) + " : " + str(val) + " \n"
                    print(http2headerdat)
            dat += "\n" + http2headerdat
            # httpdat = "".join("".join({val for key,val in pkt.http2._all_fields.items() if key == 'http2.data.data'}).split(":"))
            # httpdatdecoded = decode_hex(httpdat)[0]
            # dat += httpdatdecoded
            # dat = pkt.pretty_print
            # payload = pkt.http2.payload
            # if hasattr(pkt,'http2'):
            #     if hasattr(pkt.http2,'json_object'):
            #         if hasattr(pkt.http2,'body_reassembled_data'):
            #             avp=json.loads(codecs.decode(pkt.http2.body_reassembled_data.raw_value,'hex'))
            # # encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            # # encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            # # dat += encryptedapplicationdata_hex_decoded
            #             dat += avp
            #print(encryptedapplicationdata_hex_decoded)
        # except Exception as ex:
        #     print(ex)

    if len(http_payload):
        http_headers = get_http_headers(http_payload)

        if http_headers is not None:
            object_found, object_type = extract_object(http_headers, http_payload)

            dat += object_type + "\n" + object_found + "\n"


    print(dat)
    formatteddat = dat
    # formatteddat = str(dat, "ascii", "replace")
    #show_tcp_stream_openwin(formatteddat)
    print(formatteddat)

    show_http2_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)
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
        # for x in pkt[pkt.highest_layer]._get_all_field_lines():
        #     print(x)
        try:
            payload = pkt.tcp.payload
            encryptedapplicationdata_hex = "".join(payload.split(":")[0:len(payload.split(":"))])
            encryptedapplicationdata_hex_decoded = decode_hex(encryptedapplicationdata_hex)[0]
            dat += encryptedapplicationdata_hex_decoded
            #print(encryptedapplicationdata_hex_decoded)
        except Exception as ex:
            print(ex)

    formatteddat = str(dat, "ascii", "replace")

    # dat1 = ""
    # try:
    #     if pkt.http > 0:
    #         dat1 += "Stream Index :" , str(pkt.tcp.stream) # to print stream index at the start

    #         dat1 += "\nHTTP LAYER :", str(pkt.http).replace('\\n', '').replace('\\r', '')

    # except:
    #     pass
    #show_tcp_stream_openwin(formatteddat)
    if formatteddat.strip() == "" or len(str(formatteddat.strip)) < 1:
        sg.PopupAutoClose("No data")
    else:
        show_tcp_stream_openwin(formatteddat)
    # os.remove(tcpstreamfilename)
    #print(formatteddat)

while True:

    print(suspiciouspackets)

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
            if event == "-stopcap-":
                updatepktlist = False
                break
            if event == '-refreshrules-':
                process_rules(readrules())
            if event == sg.TIMEOUT_EVENT:
                #window['-pkts-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                window['-pkts-'].update(suspiciouspackets, scroll_to_index=len(suspiciouspackets))
                window['-pktsall-'].update(pktsummarylist, scroll_to_index=len(pktsummarylist))
                window["-ML-"].update(MLresult, scroll_to_index=len(MLresult))
                #window['-payloaddecoded-'].update(value=sus_readablepayloads[len(suspiciouspackets)])
            if event in (None, 'Exit'):
                sys.exit()
                break
            if event == '-pkts-' and len(values['-pkts-']):     # if a list item is chosen
                sus_selected = values['-pkts-']
                #sus_selected_index = int(sus_selected.split()[0][0:2])
                sus_selected_index = values[event][0]
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(suspacketactual[sus_selected_index].tcp.stream))
                except:
                    pass
                window['-payloaddecoded-'].update(value=sus_readablepayloads[sus_selected_index ])
            if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
                #pktselected = values['-pktsall-']
                pkt_selected_index = window["-pktsall-"].get_indexes()
                try:
                    window["-tcpstreams-"].update(scroll_to_index=int(pkt_list[pkt_selected_index].tcp.stream))
                except:
                    pass

            if event == "-ML-":
                window.Element('-ML-').Update(values=[event, MLresult, 'new value 3'])
            #     #sus_selected_index = int(sus_selected.split()[0][0:2])
            #     pktselectedindex = window['-pktsall-'].get_indexes()[0]
            #     window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
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

    if event == "-httpobjects-":
        httpobjectindex = values[event][0]
        show_http2_stream_openwin(httpobjecttypes[httpobjectindex] + b"\n" + httpobjectactuals[httpobjectindex][:900])

    if event == "-http2streams-":
        http2streamindex = values[event][0]
        print(http2streamindex)
        show_http2_stream(window, str(int(http2streamindex)))
    if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
        #pktselected = values['-pktsall-']
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
        #sus_selected_index = int(sus_selected.split()[0][0:2])
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

        # if event == '-pktsall-' and len(values['-pktsall-']):     # if a list item is chosen
    #             pktselected = values['-pktsall-']
    #             #sus_selected_index = int(sus_selected.split()[0][0:2])
    #             pktselectedindex = window['-pktsall-'].get_indexes()[0]
    #             window['-payloaddecodedall-'].update(value=all_readablepayloads[pktselectedindex])
    if event in (None, 'Exit'):
        break


window.close()

################################################################################################################



