#
# Subject: Scapy gadget constants
# Date: 2022/10/21
# Author: maoyi.fan@gmail.com
# Rev.: v. 0.1a
#
# History
#   v. 0.1: firstly created
#
# ToDo's:
#   1. add 802.1q VLAN tagged Ethernet frame example
#   2. display packets to be sent and packets received
#   3. add a script file support
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


#
# Enumeration class of parameters to perform scapy operations
#
class ParamCode(Enum):
    SOURCE_PORT = "src_port"
    DESTINATION_PORT = "dest_port"
    SOURCE_IP = "src_ip"
    DESTINATION_IP = "dest_ip"
    SOURCE_MAC = "src_ip"
    VLAN_TAG = "vlan"           # Yes/No; True/False
    VLAN_TPID = "vlan_tpid"     # VLAN Tag Protocol ID: 0x8100
    VLAN_TCI = "vlan_tci"       # VLAN Tag Control Information
    SCRIPT_FILE = "file"