#
# Subject: Scapy gadget class
# Date: 2022/10/17
# Author: maoyi.fan@gmail.com
# Rev.: v. 0.1a
#
# History
#   v. 0.1: project launched
#
# ToDo's:
#   1. add 802.1q VLAN tagged Ethernet frame example
#   2. display packets to be sent and packets received
#   3. add a script file support 
#
import getopt
import sys
from enum import Enum


#
# Enumeration class of scapy operations
#
class OpCode(Enum):
    PING = "ping"
    ARP = "arp"
    RARP = "rarp"
    ETHER = "ether_frame_txrx"


class ScapyInst:
    def __init__(self, argv):
        self.op_code = ""
        self.src_ip = ""
        self.dest_ip = ""
        self.src_mac = ""
        self.dest_mac = ""
        self.ether_type = ""
        self.cmd_parser(argv)

    def cmd_parser(self, argv):
        try:
            opts, args = getopt.getopt(argv, "h",
                                       ["ping", "arp", "ether_frame_txrx",
                                        "src_ip=", "dest_ip=", "src_mac=", "dest_mac=", "help"])
        except getopt.GetoptError:
            self.cmd_syntax()
            sys.exit()
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                self.cmd_syntax()
                sys.exit()
            elif opt in ("--src_ip"):
                print("Source IP: {0}".format(arg))
                self.set_source_ip(arg)
            elif opt in ("--dest_ip"):
                print("Destination IP: {0}".format(arg))
                self.set_dest_ip(arg)
            elif opt in ("--src_mac"):
                print("Source MAC: {0}".format(arg))
                self.set_source_mac(arg)
            elif opt in ("--"+OpCode.PING.value):
                print("Ping action...")
                self.op_code="ping"
            elif opt in ("--"+OpCode.ARP.value):
                print("ARP action...")
                self.op_code="arp"
            elif opt in ("--"+OpCode.ETHER.value):
                print("Sending Ethernet Frame")
                self.op_code=OpCode.ETHER.value
            else:
                print("Command name:", opt)

    def set_source_ip(self, sip):
        self.src_ip = sip

    def set_dest_ip(self, dip):
        self.dest_ip = dip

    def set_source_mac(self, smac):
        self.src_mac = smac

    def set_dest_mac(self, dmac):
        self.dest_mac = dmac

    def get_source_ip(self):
        return self.src_ip

    def get_dest_ip(self):
        return self.dest_ip

    def cmd_syntax(self):
        print("Syntax: \n\tscapy_test.py --op_code --src_ip=<source IP> --dest_ip=<destination IP> "
              "--src_mac=<source MAC> --dest_mac=<destination MAC> --ether_type=<type> -h")
        print("\top_code: \n"
              "\t\tping: sending a ICMP ping packet\n"
              "\t\tarp: sending an ARP packet\n"
              "\t\trarp: sending an RARP packet\n"
              "\t\tether_frame_txrx: sending a layer 2 packet of specified Ether Type")