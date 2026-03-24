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

    if IP in pkt:
        data["src"] = pkt[IP].src
        data["dst"] = pkt[IP].dst
    if TCP in pkt:
        data["protocol"] = "TCP"
        data["dport"] = pkt[TCP].dport
        data["flags"] = pkt[TCP].flags
    elif UDP in pkt:
        data["protocol"] = "UDP"
        data["dport"] = pkt[UDP].dport
    if DNS in pkt and pkt[DNS].qd is not None:
        q = pkt[DNS].qd
        if isinstance(q, DNSQR):
            data["dns_query"] = q.qname.decode(errors="ignore").rstrip(".")
    return data