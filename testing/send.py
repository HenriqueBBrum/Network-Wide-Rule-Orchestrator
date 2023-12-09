#!/usr/bin/env python3

# Sends packets according to the workload .txt files in the experiment_traffic_generator folder
# Each line in a .txt file indicates the destination host, the bandwidth, the duration and the wait time to send the flow

import time
import argparse
import os, sys
import json
import threading
from scapy.all import *

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    udp_port = 50000
    pkt = Ether(dst='ff:ff:ff:ff:ff:ff')/IP(dst="192.168.10.5")
    sendpfast(pkt, pps=2, loop=10, iface="eth0")





if __name__ == '__main__':
    main()
