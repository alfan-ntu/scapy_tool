#
# Subject: Scapy gadget constants
# Date: 2022/10/26
# Author: maoyi.fan@gmail.com
# Rev.: v. 0.1b
#
# History
#   v. 0.1b 2022/10/26: Multiplexing through VLAN tag
#   v. 0.1: firstly created
#
# ToDo's:
#   - display packets to be sent and packets received
#
from enum import Enum


#
# Enumeration class of scapy operations
#
class OpCode(Enum):
    PING = "ping"
    ARP = "arp"
    RARP = "rarp"
    ETHER = "ether_txrx"
    PORT_SCAN = "port_scan"
    HELP = "help"
    DUMMY = "dummy"


#
# Enumeration class of parameters to perform scapy operations
#
class ParamCode(Enum):
    SOURCE_PORT = "src_port"
    DESTINATION_PORT = "dest_port"
    SOURCE_IP = "src_ip"
    DESTINATION_IP = "dest_ip"
    SOURCE_MAC = "src_mac"
    DESTINATION_MAC = "dest_mac"
    VLAN_TAG = "vlan"               # Yes/No; True/False
    VLAN_VLANID = "vlan_vid"        # VLAN ID: 12-bits
    VLAN_PCP = "vlan_pcp"           # VLAN priority code: 0~7
    VLAN_DEI = "vlan_dei"           # VLAN Drop eligible indicator: 1 bit
    SCRIPT_FILE = "file"
    VERBOSE = "verbose"
    PROP_PROTO = "pproto"           # proprietary protocol
    DSID = "dsid"                   # Dest. SID
    SSID = "ssid"                   # Source SID
