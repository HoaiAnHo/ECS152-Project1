#!/usr/bin/env python3

import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

# Opening a PCAP file
def observer():
    # with open('project1_part2.pcap', 'rb') as f:
    with open('peertube.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            print(ts)
    return pcap

# count number of devices connected to hotspot
def device_count(pcap):
    device_num = 0
    device_list = []
    print("Number of devices: ", device_num, "\n")
    return device_list

# count number of packets sent by each device
# count number of packets received by each device
def packet_count(pcap):
    sent = 0
    receive = 0

# find any endpoints where more than one device sends out a network packet to it
# print out the IP addresses of these endpoints
def endpoint_check():
    ips = []
    for i in ips:
        print(i)

# count number of each application layer protocol used by each device
def cat_count():
    print("Protocol")

# find the total time elapsed in the PCAP file (in minutes)
def time_check():
    print("time")

# check if the devices send packets concurrently or sequentially
# List the sets of devices with concurrent traffic.
def traffic_check():
    print("traffic")

# figure out at approximately what point of time the devices were disconnected from hotspot
def disconnect_check():
    print("disconnect")

if __name__ == '__main__':
    pcap = observer()
    # device_count(pcap)