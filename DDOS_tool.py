# Python-based tool to detect DDoS attacks from PCAP file
"""
Project Contributors:
* Abhishek Ningala
* Ashish Yadav
"""

# Step 1: Imported modules
import argparse
import os
import sys
from scapy.layers.inet import IP
from scapy.utils import RawPcapReader
import geoip2.database
from scapy.all import *
from prettytable import PrettyTable
from collections import Counter
import plotly
import dpkt
import socket
import traceback
from ipaddress import ip_address
import json
from tabulate import tabulate
from pprint import pprint


# Step 2: Opening the pcap file
def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    # Step 3: Counting the total number of packets
    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1

    print('{} contains {} packets'.format(file_name, count))


# Step 4: Defined a new class to detect and count IP addresses and hits
def IPDetector():
    # Step 5: Read the PCAP using rdpcap
    packets = rdpcap("file.pcap")

    # Step 6: Reading and Appending IPs in a packet in Scapy
    srcIP = []
    for pkt in packets:
        if IP in pkt:
            try:
                srcIP.append(pkt[IP].src)
            except:
                pass

    # Step 7: Counting the total hits from IP addresses of interest
    cnt = Counter()
    for ip in srcIP:
        cnt[ip] += 1

    # Step 8: Printing a Table of total hits using PrettyTable
    table = PrettyTable(["IP", "Count"])
    for ip, count in cnt.most_common():
        table.add_row([ip, count])
    print(table)

    # Step 9: Adding Lists to prepare a plot
    xData = []
    yData = []

    for ip, count in cnt.most_common():
        xData.append(ip)
        yData.append(count)

    # Step 10: Printing a graph plot of total IP addresses count in a html link
    plotly.offline.plot({
        "data": [plotly.graph_objs.Bar(x=xData, y=yData)]})


# Step 11: Defined a class to locate all the IP addresses of interest and hardcoded here, can be given from argument
# line using argparse but out of the scope for present task

def Geolocator():
    reader = geoip2.database.Reader("./GeoLite2-City_20200407/GeoLite2-City.mmdb")
    ip_list = ["12.183.1.55", "46.161.20.66", "69.50.209.186", "8.8.8.8", "8.8.4.4", "207.46.197.32"]

    # Step 12: Printing geolocation indicators of IP addresses using GeoLite2 database

    for ip in ip_list:
        print("IP Address Location:")
        response = reader.city(ip)
        print(response.country.iso_code)
        print(response.country.name)
        print(response.postal.code)
        print(response.subdivisions.most_specific.name)
        print(response.city.name)
        print(response.location.latitude)
        print(response.location.longitude)


# Step 11: Defined a class SynfloodAttackandPortScan to locate all the IP addresses involved in SYN attack or port
# scan if any present

class SynfloodAttackandPortScan:

    # __init__ is a special Python method that is automatically called when memory is allocated for a new object. The
    # sole purpose of __init__ is to initialize the values of instance members for the new object.
    def __init__(self, filename):
        self.filename = filename
        self.suspicious_ip = dict()
        self.attackers = list()
        self.port_list = dict()

    def check_if_port_scan(self, ip):
        ports = self.port_list[ip]
        return len(ports) > 5

    # Parsing is a common programming task that splits the given sequence of characters or values (text) into smaller
    # parts based on some rules.
    def parse(self):

        # Opening pcap file
        with open(self.filename, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)  # Parse file
            print("Parsing....")
            for ts, buf in pcap:
                try:
                    # Extracting TCP data if present else fail silently
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    tcp = ip.data

                    # Checking if SYN ACK is set. SYN flag (Synchronisation flag) is a flag in TCP segment used to
                    # initiate a connection between two hosts. ACK_flag indicates that the Acknowledgment field is
                    # significant. All packets after the initial SYN packet sent by the client should have this flag
                    # set.
                    syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
                    ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0

                    # Finding port number and src, dest IPs
                    port = tcp.dport
                    src_ip_addr_str = socket.inet_ntoa(ip.src)

                    # Finding if Packet is a TCP-SYN
                    if (syn_flag == True and ack_flag == False):

                        self.suspicious_ip[ip.src] = self.suspicious_ip.get(ip.src, [0, 0, []])
                        self.suspicious_ip[ip.src][0] += 1
                        self.suspicious_ip[ip.src][2].append(port)
                    else:
                        self.suspicious_ip[ip.src] = self.suspicious_ip.get(ip.src, [0, 0, []])
                        self.suspicious_ip[ip.src][1] += 1
                        self.suspicious_ip[ip.src][2].append(port)

                except:
                    pass

            return self.__table(self.__detect_attackers(), ["IP Adress", "Port"])

    # Counting total suspicious IP based on the pcap file
    def get_count(self):
        ip_count = list()
        for ip, count in self.suspicious_ip.items():
            if (count[0] > 3 * count[1]):
                ip_count.append([socket.inet_ntoa(ip), count[0]])
        return self.__table(ip_count, ["IP Adress", "Count"])

    def get_ips(self):
        return self.__table(self.attackers, ["IP Adress", "Port"])

    def __detect_attackers(self):

        for ip, count in self.suspicious_ip.items():
            if (count[0] > 3 * count[1]):
                for port in count[2]:
                    self.port_list[socket.inet_ntoa(ip)] = self.port_list.get(socket.inet_ntoa(ip), [])
                    self.port_list[socket.inet_ntoa(ip)].append(port)
                    self.attackers.append([socket.inet_ntoa(ip), int(port)])

        return self.attackers

    def to_json(self):
        with open('suspicious_ip.json', 'w') as f:
            json.dumps(f, self.suspicious_ip, indent=4)

    def get_port_lists(self):
        return self.port_list

    def __table(self, info, headers):
        return tabulate(info, headers=headers, tablefmt="fancy_grid")


# Giving command to parse through pcap file
def PortScan(filename):
    s = SynfloodAttackandPortScan(filename)
    s.parse()
    # Printing Suspicious IP Addresses with their SYN Packet Counts or looking for scan attack
    print("Suspicious IP Addresses with their SYN Packet Counts:")
    print(s.get_count())

    if (input("Do you wish to see the ports attacked/scanned? (y/n) : ") == 'y'):
        print(s.get_ips())


# Step 12: Using Argparse and parser to take arguments and exit with outputs

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    # Step 13: Calling every function intended for the project at the end to give output in line

    process_pcap(file_name)
    IPDetector()
    Geolocator()
    PortScan(file_name)
