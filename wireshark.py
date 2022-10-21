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


# Converts Mac address in hexadecimal into a string
# Is normally included in dpkt but for some reason was not being detected by my system.
def mac_to_string(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


# Converts inet object (Ip address) to string also normally included in DPKT but not being detected
def ip_to_string(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# prints unique elements of list and number of calls to item
def unique(list_in):
    unique_out = {}
    for x in list_in:
        if x in unique_out:
            unique_out[x] += 1
        if x not in unique_out:
            unique_out[x] = 1
    sort_values = sorted(unique_out.values())  # Sort the values
    sorted_out = {}
    for i in sort_values:
        for k in unique_out.keys():
            if unique_out[k] == i:
                sorted_out[k] = unique_out[k]
    for x in sorted_out:
        print("Address: ", x, "\t # of packets: ", sorted_out[x])
    print("Total # of Unique items is: \t", len(unique_out))


# Count how many UDP and TCP packets there are in the file
# Count how many HTTPS vs HTTP packets were sent?
# Count, then calculate percentage of packets observed for HTTPS,HTTP,DNS,FTP,SSH,DHCP,TELNET,SMTP,POP3,NTP
# (Look at port numbers)
def cat_counter(pcap_object):
    udp_num = 0
    tcp_num = 0
    http_num = 0
    https_num = 0
    dns_num = 0
    ftp_num = 0
    ssh_num = 0
    dhcp_num = 0
    telnet_num = 0
    smtp_num = 0
    pop3_num = 0
    ntp_num = 0
    total = 0
    mac_in = []
    mac_out = []
    ip_in = []
    ip_out = []
    for ts, buf in pcap_object:
        total += 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        mac_in.append(mac_to_string(eth.src))
        mac_out.append(mac_to_string(eth.dst))
        ip_in.append(ip_to_string(ip.src))
        ip_out.append(ip_to_string(ip.dst))
        # Handling TCP packets
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp_num += 1
            tcp = ip.data
            port_num = tcp.dport
            if port_num == 80 and len(tcp.data) != 0:
                http_num += 1
            elif port_num == 22 and len(tcp.data) != 0:
                ssh_num += 1
            elif port_num == 25 and len(tcp.data) != 0:
                smtp_num += 1
            elif port_num == 443 and len(tcp.data) != 0:
                https_num += 1
            elif port_num == 23 and len(tcp.data) != 0:
                telnet_num += 1
            elif (port_num == 20 or port_num == 21) and len(tcp.data) != 0:
                ftp_num += 1
            elif port_num == 53 and len(tcp.data) != 0:
                dns_num += 1
        # Handling UDP packets
        if ip.p == dpkt.ip.IP_PROTO_UDP:

            udp_num += 1
            udp = ip.data
            port_num = udp.dport
            if (port_num == 67 or port_num == 68) and len(udp.data) != 0:
                dhcp_num += 1
            elif port_num == 53 and len(udp.data) != 0:
                dns_num += 1
            elif port_num == 110 and len(udp.data) != 0:
                pop3_num += 1
            elif port_num == 123 and len(udp.data) != 0:
                ntp_num += 1
    print("IP Addresses: ")
    print("Unique IP addresses Destinations: ")
    unique(ip_out)
    print("Unique IP Addresses Sources: ")
    unique(ip_in)
    print("MAC Addresses: ")
    print("Mac addresses Destinations: ", len(mac_out))
    unique(mac_out)
    print("Mac Addresses Sources: ", len(mac_in))
    unique(mac_in)
    print("UDP packets: ", udp_num, " --- TCP packets: ", tcp_num)
    print("\nTotal packets: ", total)
    print("\nHTTP packets: ", http_num, "\nHTTPs packets: ",  https_num)
    print("\nTelnet packets: ", telnet_num)
    print("\nSMTP packets: ", smtp_num)
    print("\nSSH packets: ", ssh_num)
    print("\nPOP3 packets: ", pop3_num)
    print("\nNTP packets: ", ntp_num)
    print("\nFTP packets: ", ftp_num)
    print("\nDNS packets: ", dns_num)
    print("\nDHCP packets: ", dhcp_num)
    print("\nPacket percentages:")
    print("\nUDP: ", (udp_num / total) * 100, "\nTCP: ", (tcp_num / total) * 100)
    print("\nHTTP: ", (http_num/total) * 100, "\nHTTPS: ", (https_num/total) * 100,
          " \nDNS: ", (dns_num/total) * 100)
    print("\nTelnet: ", (telnet_num / total) * 100, "\nFTP: ", (ftp_num / total) * 100,
          " \nDHCP: ", (dhcp_num / total) * 100)
    print("\nSSH: ", (ssh_num / total) * 100, "\nSMTP: ", (smtp_num / total) * 100,
          " \nPOP3: ", (pop3_num / total) * 100)
    print("\nNTP: ", (ntp_num / total) * 100)
# Count number of unique destination IP addresses
# (might also check load time of site)

# Calculate top 5 destination IP addresses, and try identifying who owns them
# (Use DevTools and HAR files generated to determine hostnames of some IP addresses)

# Check if different IP addresses are mapped to the same hostname

if __name__ == '__main__':
    pcap_file = input("Enter PCAP filename: ")
    pcap = observer(pcap_file)