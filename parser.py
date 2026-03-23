# Extracts data

from scapy.all import IP, TCP, UDP, DNS, DNSQR

def parse_packet(pkt):
    data = {
        "src": None,
        "dst": None,
        "protocol": None,
        "dport": None,
        "flags": None,
        "dns_query": None
    }