# Port scan, SYN flood, DNS detection

from datetime import datetime
from collections import defaultdict
from alert import format_alert
from logger import log_alert
from config import (
    PORT_SCAN_PORT_THRESHOLD, PORT_SCAN_TIME_WINDOW,
    SYN_FLOOD_SYN_THRESHOLD, SYN_FLOOD_TIME_WINDOW,
    SYN_FLOOD_MIN_SYN_ACK_RATIO,
    MAX_DOMAIN_LENGTH, MAX_SUBDOMAINS, SUSPICIOUS_TLDS,
    BLACKLIST_FILE
)

# Access blacklist
with open(BLACKLIST_FILE) as f:
    BLACKLIST = {line.strip() for line in f if line.strip()}

port_scan_data = defaultdict(lambda: {"ports": set(), "first_seen": datetime.now()})
syn_data = defaultdict(lambda: {"syn_times": [], "completed": 0})

def detect_malicious_ip(src, dst):
    if src in BLACKLIST:
        log_alert(format_alert("ALERT", f"Traffic from malicious IP {src} to {dst}"))
    if dst in BLACKLIST:
        log_alert(format_alert("ALERT", f"Traffic to malicious IP {dst} from {src}"))

def detect_port_scan(src, dst, dport):
    key = (src, dst)
    entry = port_scan_data[key]
    now = datetime.now()
    if (now - entry["first_seen"]).total_seconds() > PORT_SCAN_TIME_WINDOW:
        entry["ports"] = set()
        entry["first_seen"] = now
    entry["ports"].add(dport)
    if len(entry["ports"]) >= PORT_SCAN_PORT_THRESHOLD:
        log_alert(format_alert("ALERT", f"Possible port scan from {src} to {dst}"))
        entry["ports"] = set()
        entry["first_seen"] = now

def detect_syn_flood(src, flags):
    now = datetime.now()
    entry = syn_data[src]
    entry["syn_times"] = [
        t for t in entry["syn_times"]
        if (now - t).total_seconds() <= SYN_FLOOD_TIME_WINDOW
    ]
    syn_flag = flags & 0x02
    ack_flag = flags & 0x10

    if syn_flag and not ack_flag:
        entry["syn_times"].append(now)
    if ack_flag:
        entry["completed"] += 1
    syn_count = len(entry["syn_times"])
    completed = entry["completed"]
    if syn_count >= SYN_FLOOD_SYN_THRESHOLD:
        ratio = completed / syn_count if syn_count else 0
        if ratio < SYN_FLOOD_MIN_SYN_ACK_RATIO:
            log_alert(format_alert("ALERT", f"Possible SYN flood from {src}"))
            entry["syn_times"] = []
            entry["completed"] = 0