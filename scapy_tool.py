#
# Subject: A simple gadget set demonstrating the use of scapy
# Date: 2022/10/18
# Author: maoyi.fan@gmail.com
# Rev.: v. 0.1a
#
# History:
#    v. 0.1: project launched
#
# ToDo's:
#   1. add 802.1q VLAN tagged Ethernet frame example
#   2. display packets to be sent and packets received
#
import scapy.all as scapy
import sys
from scapy_class import ScapyInst
from enum_const import *


def main(argv):
    scapy_inst = ScapyInst(argv)
    if scapy_inst.op_code:
        scapy_inst.dump_scapy_inst()
        print("Scapy operation is ", scapy_inst.op_code)
        if scapy_inst.op_code == OpCode.PING.value:
            scapy_ping(scapy_inst)
        elif scapy_inst.op_code == OpCode.ARP.value:
            scapy_arp(scapy_inst)
            print("{0} is at {1} ".format(scapy_inst.dest_ip, scapy_inst.dest_mac))
        # elif scapy_inst.op_code == OpCode.RARP.value:
        #     scapy_rarp(scapy_inst)
        elif scapy_inst.op_code == OpCode.ETHER.value:
            scapy_ether_txrx(scapy_inst, True)
        elif scapy_inst.op_code == OpCode.PORT_SCAN.value:
            scapy_port_scan(scapy_inst, False)
    else:
        print("Missing scapy operation!")


#
# Initiates a port scan to a range of ports on the target machine
#
def scapy_port_scan(scapy_inst, show_tx=False):
    print("Target IP: {0}; Start port: {1}; End port: {2} ".format(
        scapy_inst.dest_ip, scapy_inst.start_port, scapy_inst.end_port))
    dest_ip = scapy_inst.dest_ip
    for pt in range(int(scapy_inst.start_port), int(scapy_inst.end_port)+1):
        pkt = scapy.IP(dst=dest_ip)/scapy.TCP(dport=pt, flags='S')
        response = scapy.sr1(pkt, timeout=0.5, verbose=0)
        if response is not None and scapy.TCP in response and response[scapy.TCP].flags == 0x12:
            print(f'\nPort {str(pt)} is open!')
            scapy.sr(scapy.IP(dst=dest_ip)/scapy.TCP(dport=response.sport, flags='R'), timeout=0.5, verbose=0)
        else:
            print('.', end='')
    print("Port scan completes!")

#
#
#
def scapy_ether_txrx(scapy_inst, show_tx=False):
    print("Running ethernet frame txrx...")
    tcp_pkt = scapy.TCP(sport=135, dport=135)
    ip_pkt = scapy.IP(src=scapy_inst.src_ip, dst=scapy_inst.dest_ip)
    xeth = scapy.Ether(src=scapy_inst.src_mac)/ip_pkt/tcp_pkt
    if show_tx:
        xeth.show()
    scapy.sendp(xeth, count=5)


#
# PING handler using Scapy
#
def scapy_ping(scapy_inst):
    print("Ping ", scapy_inst.dest_ip)
    p = scapy.IP(dst=scapy_inst.dest_ip)/scapy.ICMP()/"Hello Admin"
    p_rx = scapy.sr1(p)
    p_rx.show()     # obj.show() is a great function to show the content
                    # of the network object


#
# ARP handler using Scapy
#
def scapy_arp(scapy_inst):
    print("ARP ", scapy_inst.dest_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = scapy.ARP(pdst=scapy_inst.dest_ip)
    xeth = broadcast/arp_request
    ans = scapy.srp(xeth, timeout=1, verbose=False)[0]
    scapy_inst.dest_mac = ans[0][1].hwsrc


#
#
#
def scapy_rarp(scapy_inst):
    print("RARP ", scapy_inst.dest_mac)


if __name__ == "__main__":
    main(sys.argv[1:])
