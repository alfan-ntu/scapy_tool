#
# Subject: Scapy gadget class
# Date: 2022/10/17
# Author: maoyi.fan@aegiscloud.com.tw
# Rev.: v. 0.1
#
# ToDo's:
#   1. add 802.1q VLAN tagged Ethernet frame example
#
import getopt
import sys
from enum import Enum


class OpCode(Enum):
    PING = "ping"
    ARP = "arp"
    RARP = "rarp"


class ScapyInst:
    def __init__(self, argv):
        self.op_code = ""
        self.src_ip = ""
        self.dest_ip = ""
        self.src_mac = ""
        self.dest_mac = ""
        self.cmd_parser(argv)

    def cmd_parser(self, argv):
        try:
            opts, args = getopt.getopt(argv, "h",
                                       ["ping", "arp",
                                        "src_ip=", "dest_ip=", "src_mac=", "dest_mac=", "help"])
        except getopt.GetoptError:
            print("Syntax: \n\tscapy_test.py --src_ip=<source IP> --dest_ip=<destination IP> "
                  "--src_mac=<source MAC> --dest_mac=<destination MAC> -h")
            sys.exit()
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print("Syntax: \n\tscapy_test.py --src_ip=<source IP> --dest_ip=<destination IP> "
                      "--src_mac=<source MAC> --dest_mac=<destination MAC> -h")
                sys.exit()
            elif opt in ("--src_ip"):
                print("Source IP: {0}".format(arg))
                self.set_source_ip(arg)
            elif opt in ("--dest_ip"):
                print("Destination IP: {0}".format(arg))
                self.set_dest_ip(arg)
            elif opt in ("--ping"):
                print("Ping action...")
                self.op_code="ping"
            elif opt in ("--arp"):
                print("ARP action...")
                self.op_code="arp"
            else:
                print("Command name:", opt)

    def set_source_ip(self, sip):
        self.src_ip = sip

    def set_dest_ip(self, dip):
        self.dest_ip = dip

    def set_src_mac(self, smac):
        self.src_mac = smac

    def set_dest_mac(self, dmac):
        self.dest_mac = dmac

    def get_source_ip(self):
        return self.src_ip

    def get_dest_ip(self):
        return self.dest_ip
