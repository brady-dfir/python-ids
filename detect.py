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
