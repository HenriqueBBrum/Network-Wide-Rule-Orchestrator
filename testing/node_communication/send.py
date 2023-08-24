#!/usr/bin/env python3

# Sends packets according to the workload .txt files in the experiment_traffic_generator folder
# Each line in a .txt file indicates the destination host, the bandwidth, the duration and the wait time to send the flow
from scapy.all import *
import time
import argparse
import os, sys
import json
import threading


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    udp_port = 50000
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=get_if_hwaddr('eth0')) / \
                IP(dst="10.0.2.2")/UDP(sport=udp_port,dport=udp_port)/Raw(RandString(size=100))

    sendpfast(pkt, pps=1, loop=15)
    sendpfast(pkt, pps=1, loop=15)



if __name__ == '__main__':
    main()
