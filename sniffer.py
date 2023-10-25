import logging
from datetime import datetime
import subprocess
import sys
 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
 
 
try:
    from scapy.all import *
 
except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()
    
 
print("\n! Make sure to run this program as ROOT !\n")

net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'enp0s8'): ")
 
try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout = None, stderr = None, shell = False)
 
except:
    print("\nFailed to configure interface as promiscuous.\n")
 
else:
    print("\nInterface %s was set to PROMISC mode.\n" % net_iface)
 
 
pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")
 
if int(pkt_to_sniff) != 0:
    print("\nThe program will capture %d packets.\n" % int(pkt_to_sniff))
    
elif int(pkt_to_sniff) == 0:
    print("\nThe program will capture packets until the timeout expires.\n")
 
 
time_to_sniff = input("* Enter the number of seconds to run the capture: ")
 
if int(time_to_sniff) != 0:
    print("\nThe program will capture packets for %d seconds.\n" % int(time_to_sniff))

proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ")
 
if (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    print("\nThe program will capture only %s packets.\n" % proto_sniff.upper())
    
elif (proto_sniff) == "0":
    print("\nThe program will capture all protocols.\n")
 
 
file_name = input("* Please give a name to the log file: ")
 
sniffer_log = open(file_name, "a")
 
 

def packet_log(packet):
    
    now = datetime.now()
    
    if proto_sniff == "0":
        
        print("Time: " + str(now) + " Protocol: ALL" + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)
        
    elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
        
        print("Time: " + str(now) + " Protocol: " + proto_sniff.upper() + " SMAC: " + packet[0].src + " DMAC: " + packet[0].dst, file = sniffer_log)
 
        
print("\n* Starting the capture...")
 
 
if proto_sniff == "0":
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
 
elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
    sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff), prn = packet_log)
    
else:
    print("\nCould not identify the protocol.\n")
    sys.exit()
 
 
print("\n* Please check the %s file to see the captured packets.\n" % file_name)
 
sniffer_log.close()
