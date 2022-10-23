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
import os.path
from enum_const import *


def is_an_opcode(oc):
    voc = False
    if oc[0] == "op":
        for op in OpCode:
            if oc[1] == op.value:
                voc = True
    return voc


#
# Parse command arguments or an external script file to collect network parameters
# for cooking a Scapy operation in ScapyInst.recipe
#
class ScapyInst:
    def __init__(self, argv):
        self.init_scapy_inst()
        self.cmd_parser(argv)

    def init_scapy_inst(self):
        self.op_code = ""
        self.src_ip = ""
        self.dest_ip = ""
        self.src_mac = ""
        self.dest_mac = ""
        self.ether_type = ""
        self.vlan = False
        self.vlan_tpid = ""
        self.vlan_tci = ""
        self.path_to_file = ""
        self.recipe = []

    def dump_scapy_inst(self):
        print("Op Code: ", self.op_code)
        print("Source IP: ", self.src_ip)
        print("Destination IP: ", self.dest_ip)
        print("Source MAC: ", self.src_mac)
        print("Destination MAC: ", self.dest_mac)
        if self.vlan:
            print("VLAN ID: ", self.vlan_tpid)
            print("VLAN TCI: ", self.vlan_tci)

    def cmd_parser(self, argv):
        try:
            opts, args = getopt.getopt(argv, "hf:",
                                       ["ping", "arp", "ether_txrx",
                                        "src_ip=", "dest_ip=", "src_mac=", "dest_mac=",
                                        "file=", "help"])
        except getopt.GetoptError:
            self.cmd_syntax()
            sys.exit()
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                self.cmd_syntax()
                sys.exit()
            elif opt in ("-f", "--file"):
                self.path_to_file = arg
                if not self.script_parser():
                    print("Invalid external script file: {0}".format(arg))
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

    # command syntax output
    def cmd_syntax(self):
        print("Syntax: \n\tscapy_test.py --op_code --src_ip=<source IP> --dest_ip=<destination IP> "
              "--src_mac=<source MAC> --dest_mac=<destination MAC> --ether_type=<type> -h")
        print("\top_code: \n"
              "\t\tping: sending a ICMP ping packet\n"
              "\t\tarp: sending an ARP packet\n"
              "\t\trarp: sending an RARP packet\n"
              "\t\tether_txrx: sending a layer 2 packet of specified Ether Type")

    def script_parser(self):
        valid_script = True if os.path.exists(self.path_to_file) else False
        # ToDo's : add file token parser
        with open(self.path_to_file, 'r') as fp:
            while True:
                line = fp.readline()
                if not line or line == '\n':
                    break
                elif line[0] == '#':
                    pass
                else:
                    token = line[:-1].split("=", 1)
                    token[0] = token[0].strip()
                    token[1] = token[1].strip()
                    self.recipe.append(token)
        fp.close()
        # traverse recipe for composing scapy command
        for token in self.recipe:
            if is_an_opcode(token):
                self.op_code = token[1]
            if token[0] == "source_ip":
                self.src_ip = token[1]
            elif token[0] == "dest_ip":
                self.dest_ip = token[1]
            elif token[0] == "source_mac":
                self.src_mac = token[1]
            elif token[0] == "dest_mac":
                self.dest_mac = token[1]
            elif token[0] == "vlan":
                if token[1].upper() == "YES" or token[1].upper() == "TRUE":
                    self.vlan = True
            elif token[0] == "vlan_tpid":
                self.vlan_tpid = token[1]
            elif token[0] == "vlan_tci":
                self.vlan_tci = token[1]
            else:
                pass
        return valid_script
