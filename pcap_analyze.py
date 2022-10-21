#!/usr/bin/env python3

import dpkt
import datetime
import socket
from dpkt.compat import compat_ord

# prints unique elements of list
def unique(list_in):
    unique_out = []
    for x in list_in:
        if x not in unique_out:
            unique_out.append(x)
    for x in unique_out:
        print(x)

def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# count number of devices connected to hotspot
def device_count():
    device_list = []
    ip_list = []
    dest_list = []
    times = []
    concurs = []
    disconnects = []
    with open('project1_part2.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            times.append(ts)
            eth = dpkt.ethernet.Ethernet(buf)
            if mac_addr(eth.src) not in device_list:
                device_list.append(mac_addr(eth.src))
            if mac_addr(eth.dst) not in device_list:
                device_list.append(mac_addr(eth.dst))
            # Make sure the Ethernet data contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                disconnects.append(ts)
                continue
            # Now unpack the data within the Ethernet frame (the IP packet)
            # Pulling out src, dst, length, fragment info, TTL, and Protocol
            ip = eth.data
            if inet_to_str(ip.src) not in ip_list:
                ip_list.append(inet_to_str(ip.src))
            if inet_to_str(ip.dst) not in dest_list:
                dest_list.append(inet_to_str(ip.dst))
    print("Time to capture file: ", str(datetime.datetime.utcfromtimestamp(times[0])),
          str(datetime.datetime.utcfromtimestamp(times[-1])))
    print("Time when devices disconnect: ", str(datetime.datetime.utcfromtimestamp(disconnects[0])))
    print("MAC addresses: ", len(device_list))
    print("IP addresses: ", len(ip_list), " ", len(dest_list))
    # check = concur_check(times)
    # print("Concurs is REAL??? --------", len(check))
    packet_count(device_list)

def concur_check(times):
    concurs = []
    for i in times:
        if times.count(i) > 1:
            if i not in concurs:
                concurs.append(i)
    return concurs


# count number of packets sent by each device
# count number of packets received by each device
def packet_count(mac_list):
    send_list = []
    receive_list = []
    for i in mac_list:
        send_list.append(0)
        receive_list.append(0)
    with open('project1_part2.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            sender = mac_list.index(mac_addr(eth.src))
            receiver = mac_list.index(mac_addr(eth.dst))
            send_list[sender] += 1
            receive_list[receiver] += 1
        print("List of devices that sent and received packets: ----------------")
        b = 0
        for a in mac_list:
            print(a, "--------", send_list[b], receive_list[b])
            b += 1

# find any endpoints where more than one device sends out a network packet to it
# print out the IP addresses of these endpoints
def endpoint_check():
    ips = []
    for i in ips:
        print(i)

def cat_counter():
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
    ip_in = []
    ip_out = []
    with open('project1_part2.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            total += 1
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue
            ip = eth.data

            ip_in.append(inet_to_str(ip.src))
            ip_out.append(inet_to_str(ip.dst))
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
        print("UDP packets: ", udp_num, " --- TCP packets: ", tcp_num)
        print("Total packets: ", total)
        print("HTTP packets: ", http_num, "\nHTTPs packets: ", https_num)
        print("Telnet packets: ", telnet_num)
        print("SMTP packets: ", smtp_num)
        print("SSH packets: ", ssh_num)
        print("POP3 packets: ", pop3_num)
        print("NTP packets: ", ntp_num)
        print("FTP packets: ", ftp_num)
        print("DNS packets: ", dns_num)
        print("DHCP packets: ", dhcp_num)

# check if the devices send packets concurrently or sequentially
# List the sets of devices with concurrent traffic.
def traffic_check():
    print("traffic")

# figure out at approximately what point of time the devices were disconnected from hotspot
def disconnect_check():
    print("disconnect")

if __name__ == '__main__':
    device_count()
    cat_counter()