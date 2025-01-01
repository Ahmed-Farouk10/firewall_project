import json
import os
from pyshark import LiveCapture
from protocol_filter import is_protocol_allowed
from logger import log_event
from time import time

CONFIG_FILE = "config.json"

def load_config():
    """Loads the firewall configuration from a JSON file."""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"{CONFIG_FILE} does not exist.")
    with open(CONFIG_FILE, "r") as config_file:
        return json.load(config_file)

config = load_config()
print("Config file loaded successfully:", config)

BLACKLIST = config.get("blacklist", [])
WHITELIST = config.get("whitelist", [])
ALLOWED_PROTOCOLS = config.get("allowed_protocols", ["HTTP", "DNS", "FTP"])
ALERT_THRESHOLD = config.get("alert_threshold", 200)

blocked_counts = {"blacklist_hits": 0, "unusual_protocols": 0}
violation_counts = {}
recent_logs = set()
offender_time_window = 60  # Track offenders within 60 seconds
offender_timestamps = {}

def is_blacklisted(ip: str) -> bool:
    return ip in BLACKLIST

def is_whitelisted(ip: str) -> bool:
    return ip in WHITELIST

def log_event_with_details(event: str, details: str):
    """Suppresses repeated logs for persistent offenders."""
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
        if not hasattr(packet, "ip"):
            log_event("Error", "Packet does not contain an IP layer.")
            return

        src_ip = packet.ip.src

        if is_whitelisted(src_ip):
            log_event_with_details("Allowed", f"Whitelisted IP: {src_ip}")
            return

        if is_blacklisted(src_ip):
            blocked_counts["blacklist_hits"] += 1
            log_event_with_details("Blocked", f"Packet from blacklisted IP {src_ip}")
            return

        if not is_protocol_allowed(packet):
            violation_counts[src_ip] = violation_counts.get(src_ip, 0) + 1
            if violation_counts[src_ip] >= 10:
                log_event_with_details("Blocked", f"Persistent offender: {src_ip}")
                violation_counts[src_ip] = 0
            blocked_counts["unusual_protocols"] += 1
            return

        log_event_with_details("Allowed", f"Packet from {src_ip}")

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
