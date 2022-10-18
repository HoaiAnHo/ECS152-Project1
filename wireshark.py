#!/usr/bin/env python3

import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

# THIS PROGRAM ASSUMES YOU'RE LOOKING AT JUST ONE SITE

# Opening a PCAP file
def observer(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap_object = dpkt.pcap.Reader(f)
        cat_counter(pcap_object)
    return pcap_object

# Count how many UDP and TCP packets there are in the file
# Count how many HTTPS vs HTTP packets were sent?
# Count, then calculate percentage of packets observed for HTTPS,HTTP,DNS,FTP,SSH,DHCP,TELNET,SMTP,POP3,NTP
# (Look at port numbers)
def cat_counter(pcap_object):
    udp_num = 0
    tcp_num = 0
    # http_num = 0
    # https_num = 0
    # dns_num = 0
    # ftp_num = 0
    # ssh_num = 0
    # dhcp_num = 0
    # telnet_num = 0
    # smtp_num = 0
    # pop3_num = 0
    # ntp_num = 0
    total = 0

    for ts, buf in pcap_object:
        total += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        # tcp = ip.data
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp_num += 1
        if ip.p == dpkt.ip.IP_PROTO_UDP:
            udp_num += 1
        # if tcp.dport == 80 and len(tcp.data) > 0:
        #     http_num += 1

    print("UDP packets: ", udp_num, " --- TCP packets: ", tcp_num)
    print("Total packets: ", total)
    # print("HTTP packets: ", http_num, " ---- HTTPs packets: ",  https_num, "\n")
    # print("HTTP packets: ", http_num)
    # print("Package percentages: \n")
    # print("HTTP: ", http_num/total, " --- HTTPS: ", https_num/total, " --- DNS: ", dns_num/total)


# Count number of unique destination IP addresses
# (might also check load time of site)

# Calculate top 5 destination IP addresses, and try identifying who owns them
# (Use DevTools and HAR files generated to determine hostnames of some IP addresses)

# Check if different IP addresses are mapped to the same hostname

if __name__ == '__main__':
    pcap_file = input("Enter PCAP filename: ")
    pcap = observer(pcap_file)