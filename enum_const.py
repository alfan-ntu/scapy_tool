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


