# VIPER

## Overview
VIPER is a lightweight Intrusion Detection System (IDS) built with python using Scapy. VIPER can detect the following events: port scans, SYN floods, suspicous DNS queries, and known malicious IPs. Alerts are printed to the console and saved to a log file in the following format:

2026-03-14 09:21:03 [ALERT] Possible port scan from 192.168.1.55

# Structure
main.py - Runs IDS
sniffer.py - Captures packets
parser.py - Extracts data
detect.py - Port scan, SYN flood, DNS detection
alert.py - Formats alerts
logger.py - Saves alerts to a file
config.py - Settings and configurations
blacklist.txt - Malicious IP list
__init__.py - Public interface

## Key Features

### Port Scan Detection
Tracks destination ports contacted by a source within a timeframe. Alert will trigger when the number exceeds the set threshold.

### SYN Flood Detection
Counts SYN packets per source and compares them to validated handshakes. Alert will trigger when SYN volume is high and handshake validation ratio is low.

### Suspicious DNS Query Detection
Flags DNS queries with excessive domain lenght, too many subdomains, suspicious TLDs (.xyz, .top, .click)

### Malicious IP Detection
Loads IPs from blacklist.txt and flags and alerts traffic that involves them. IPs can be added to blacklist.txt

### Modular and Configurable
Add new detectors by creating functions in detect.py and calling them from sniffer.py. All settings exist in config.py. Thresholds can be configured depending on the environment.

## Installation
pip install scapy

python main.py (use sudo if using linux)

