# Captures packets

from scapy.all import sniff
from parser import parse_packet
from detect import (
    detect_malicious_ip,
    detect_port_scan,
    detect_syn_flood,
    detect_suspic_dns,
)

from config import INTERFACE

def handle_packet(pkt):
    data = parse_packet(pkt)
    src = data["src"]
    dst = data["dst"]
    proto = data["protocol"]
    dport = data["dport"]
    flags = data["flags"]
    dns_query = data["dns_query"]

    if not src or not dst:
        return
    detect_malicious_ip(src, dst)
    if proto == "TCP" and dport:
        detect_port_scan(src, dst, dport)
        detect_syn_flood(src, flags)
    if dns_query:
        detect_suspicious_dns(src, dns_query)

