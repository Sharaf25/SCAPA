import pyshark
import os
import platform

# Cross-platform SSL key file path
if platform.system() == "Windows":
    key_path = os.path.expanduser("~/ssl_keys.log")
else:
    key_path = os.path.expanduser("~/ssl_keys.log")

pcap_file = 'tcpstreamread.pcap'


cap = pyshark.FileCapture(pcap_file,
                          display_filter="http2.streamid eq 5",
                          override_prefs={'ssl.keylog_file': key_path})

dat = ''
rawvallengthpassed = False
for field, val in cap[0].http2._all_fields.items():
    # if rawvallengthpassed == False:
    #     if field == 'http2.header.name.length':
    #         rawvallengthpassed = True
    # else:
    dat += str(field.split(".")[-1]) + " : " + str(val) + " \n\n"

print(dat)