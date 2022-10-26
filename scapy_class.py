#
# Subject: Scapy gadget class
# Date: 2022/10/26
# Author: maoyi.fan@gmail.com
# Rev.: v. 0.1b
#
# History
#   v. 0.1b 2022/10/26: Multiplexing through VLAN tag
#   v. 0.1: project launched
#
# ToDo's:
#   - display packets to be sent and packets received
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
# supporting function: command syntax output
#
def cmd_syntax():
    print("Syntax: \n\tscapy_test.py --op_code --src_ip=<source IP> --dest_ip=<destination IP> "
          "--src_mac=<source MAC> --dest_mac=<destination MAC> --ether_type=<type> -h")
    print("\top_code: \n"
          "\t\tping: sending a ICMP ping packet\n"
          "\t\tarp: sending an ARP packet\n"
          "\t\trarp: sending an RARP packet\n"
          "\t\tether_txrx: sending a layer 2 packet of specified Ether Type\n"
          "\t\tscan_port: scanning all listening ports on the target IP\n")


#
# supporting function: compose long option arguments based on Enum classes OpCode and ParamCode
#
def compose_longopts():
    longopts = []
    for opcode in OpCode:
        longopts.append(opcode.value)
    for prm_code in ParamCode:
        longopts.append(prm_code.value+'=')
    return longopts


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
        self.start_port = 0         # port value #1 for TCP class protocol
        self.end_port   = 0         # port value #2 for TCP class protocol
        self.src_ip = ""
        self.dest_ip = ""
        self.src_mac = ""
        self.dest_mac = ""
        self.ether_type = ""
        self.vlan = False           # Default to not VLAN tagged
        self.vlan_vid = ""
        self.vlan_pcp = ""
        self.vlan_dei = ""
        self.path_to_file = ""
        self.recipe = []
        self.verbose = False        # default not to dump scapy instance
        self.pproto = False         # Default not to support proprietary protocol
        self.dsid = ""
        self.ssid = ""

    def dump_scapy_inst(self):
        if self.verbose:
            print(">>> Dumping Scapy Operation Instance")
            print("\tOp Code: ", self.op_code)
            print("\tSource/Start Port: ", self.start_port)
            print("\tDest/End Port: ", self.end_port)
            print("\tSource IP: ", self.src_ip)
            print("\tDestination IP: ", self.dest_ip)
            print("\tSource MAC: ", self.src_mac)
            print("\tDestination MAC: ", self.dest_mac)
            if self.vlan:
                print("\tVLAN ID: ", self.vlan_vid)
                print("\tVLAN PCP: ", self.vlan_pcp)
                print("\tVLAN DEI: ", self.vlan_dei)
            if self.pproto:
                print("\tDSID: ", self.dsid)
                print("\tSSID: ", self.ssid)
            print(">>> End of Scapy Instance Dumping\n")

    def cmd_parser(self, argv):
        try:
            longopts = compose_longopts()
            opts, args = getopt.getopt(argv, "hf:v:", longopts)
        except getopt.GetoptError:
            cmd_syntax()
            sys.exit()
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                cmd_syntax()
                sys.exit()
            elif opt in ("-f", "--file"):
                self.path_to_file = arg
                if not self.script_parser():
                    print("Invalid external script file: {0}".format(arg))
            elif opt in ("-v", "--verbose"):
                if arg.upper() == "YES" or arg.upper() == "TRUE":
                    self.verbose = True
            elif opt in ParamCode.SOURCE_PORT.value:
                print("Srouce/start port: {0}".format(arg))
                self.set_source_port(arg)
            elif opt in ('--'+ParamCode.DESTINATION_PORT.value):
                print("Dest/end port: {0}".format(arg))
                self.set_dest_port(arg)
            elif opt in ('--'+ParamCode.SOURCE_IP.value):
                print("Source IP: {0}".format(arg))
                self.set_source_ip(arg)
            elif opt in ('--'+ParamCode.DESTINATION_IP.value):
                print("Destination IP: {0}".format(arg))
                self.set_dest_ip(arg)
            elif opt in ('--'+ParamCode.SOURCE_MAC.value):
                print("Source MAC: {0}".format(arg))
                self.set_source_mac(arg)
            elif opt in ('--'+OpCode.PING.value):
                print("Ping action...")
                self.op_code=OpCode.PING.value
            elif opt in ('--'+OpCode.ARP.value):
                print("ARP action...")
                self.op_code=OpCode.ARP.value
            elif opt in ('--'+OpCode.ETHER.value):
                print("Sending Ethernet Frame action...")
                self.op_code=OpCode.ETHER.value
            elif opt in ('--'+OpCode.PORT_SCAN.value):
                print("Port Scan action...")
                self.op_code=OpCode.PORT_SCAN.value
            else:
                print("Command name:", opt)

    def set_source_port(self, sport):
        self.start_port = sport

    def set_dest_port(self, dport):
        self.end_port = dport

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

    def script_parser(self):
        valid_script = True if os.path.exists(self.path_to_file) else False
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
            else:
                if token[0] == ParamCode.SOURCE_PORT.value:
                    self.start_port = token[1]
                elif token[0] == ParamCode.DESTINATION_PORT.value:
                    self.end_port = token[1]
                elif token[0] == ParamCode.SOURCE_IP.value:
                    self.src_ip = token[1]
                elif token[0] == ParamCode.DESTINATION_IP.value:
                    self.dest_ip = token[1]
                elif token[0] == ParamCode.SOURCE_MAC.value:
                    self.src_mac = token[1]
                elif token[0] == ParamCode.DESTINATION_MAC.value:
                    self.dest_mac = token[1]
                elif token[0] == ParamCode.VLAN_TAG.value:
                    if token[1].upper() == "YES" or token[1].upper() == "TRUE":
                        self.vlan = True
                elif token[0] == ParamCode.VLAN_VLANID.value:
                    self.vlan_vid = token[1]
                elif token[0] == ParamCode.VLAN_PCP.value:
                    self.vlan_pcp = token[1]
                elif token[0] == ParamCode.VLAN_DEI.value:
                    self.vlan_dei = token[1]
                elif token[0] == ParamCode.VERBOSE.value:
                    if token[1].upper() == "YES" or token[1].upper() == "TRUE":
                        self.verbose = True
                elif token[0] == ParamCode.PROP_PROTO.value:
                    if token[1].upper() == "YES" or token[1].upper() == "TRUE":
                        self.pproto = True
                elif token[0] == ParamCode.DSID.value:
                    self.dsid = token[1]
                elif token[0] == ParamCode.SSID.value:
                    self.ssid = token[1]
                else:
                    pass
        return valid_script
