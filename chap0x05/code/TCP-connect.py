#! /usr/bin/python

from scapy.all import *

dst_ip = "172.16.111.121"
dst_port=8888

ret = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="S"),timeout=10)
if ret is None:
    print("Filtered")
elif ret.haslayer(TCP):
    if ret[1].flags == 0x12:
        print("Open")
    elif ret[1].flags == 0x14:
        print("Closed")