import json
import os
from pyshark import LiveCapture
from protocol_filter import is_protocol_allowed
from logger import log_event, log_anomaly, log_attack
from time import time
from traffic_analysis import analyze_traffic, detect_anomalies
import ssl
from sklearn.ensemble import IsolationForest
import numpy as np

# Load configuration
CONFIG_FILE = "config.json"

def load_config():
    """Loads the firewall configuration from a JSON file."""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"{CONFIG_FILE} does not exist.")
    with open(CONFIG_FILE, "r") as config_file:
        return json.load(config_file)

config = load_config()

BLACKLIST = config.get("blacklist", [])
WHITELIST = config.get("whitelist", [])
ALLOWED_PROTOCOLS = config.get("allowed_protocols", ["HTTP", "DNS", "FTP", "HTTPS", "SMTP", "SSH", "POP3", "IMAP"])
ALERT_THRESHOLD = config.get("alert_threshold", 200)

# SSL Configuration
ssl_cert = config.get("ssl_cert")
ssl_key = config.get("ssl_key")

# Setup SSL context
def create_ssl_context():
    """Creates and returns an SSL context using the provided cert and key."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
    return context

blocked_counts = {"blacklist_hits": 0, "unusual_protocols": 0}
violation_counts = {}
recent_logs = set()
offender_time_window = 60  # Track offenders within 60 seconds
offender_timestamps = {}

traffic_data = {
    "total_packets": 0,
    "allowed_packets": 0,
    "blocked_packets": 0,
    "traffic_volume": 0,  # Track traffic volume (in bytes)
    "protocols": {}
}

def is_blacklisted(ip: str) -> bool:
    """Check if the IP is in the blacklist."""
    return ip in BLACKLIST

def is_whitelisted(ip: str) -> bool:
    """Check if the IP is in the whitelist."""
    return ip in WHITELIST

def log_event_with_details(event: str, details: str):
    """Logs events with details and controls log repetition."""
    global recent_logs, offender_timestamps
    current_time = time()
    if details not in recent_logs or current_time - offender_timestamps.get(details, 0) > offender_time_window:
        log_event(event, details)
        print(f"{event}: {details}")
        recent_logs.add(details)
        offender_timestamps[details] = current_time

    if len(recent_logs) > 1000:
        recent_logs.clear()

def inspect_packet(packet):
    """Processes packets and applies firewall rules."""
    try:
        # Skip non-IP packets gracefully
        if not hasattr(packet, "ip"):
            log_event("Info", "Packet does not contain an IP layer (e.g., ARP or MAC layer).")
            return  # Skip non-IP packets

        src_ip = packet.ip.src

        # Whitelist check - if the source IP is in the whitelist, allow the packet
        if is_whitelisted(src_ip):
            log_event_with_details("Allowed", f"Whitelisted IP: {src_ip}")
            return

        # Blacklist check
        if is_blacklisted(src_ip):
            blocked_counts["blacklist_hits"] += 1
            log_event_with_details("Blocked", f"Packet from blacklisted IP {src_ip}")
            return

        # Analyze traffic patterns and detect anomalies
        analyze_traffic(packet)

        # Signature-based attack detection (e.g., SYN flood, XSS, etc.)
        if not is_protocol_allowed(packet):
            log_attack(packet, "Potential attack detected")

        # Allow the packet if no issues
        log_event_with_details("Allowed", f"Packet from {src_ip}")

        # Traffic anomaly detection (based on traffic volume, patterns)
        detect_anomalies()

        # Check for alert thresholds for blocked packets
        for key, count in blocked_counts.items():
            if count >= ALERT_THRESHOLD:
                log_event_with_details("Alert", f"{key} threshold reached: {count}")
                blocked_counts[key] = 0

    except AttributeError as e:
        log_event("Error", f"Malformed packet: {e}")

def start_packet_sniffer():
    """Starts the packet sniffer."""
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        capture = LiveCapture(interface="Ethernet")
        for packet in capture.sniff_continuously():
            inspect_packet(packet)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.")
    except Exception as e:
        log_event("Error", f"Packet sniffer error: {e}")

if __name__ == "__main__":
    start_packet_sniffer()
