# Formats alerts
# Ex. Output: [ALERT] Possible port scan from 192.168.10.1

def format_alert(alert_type: str, details: str):
    return f"{alert_type}] {details}"