import json
from pyshark import LiveCapture
from protocol_filter import is_protocol_allowed
from logger import log_event
import os

# Load configuration
config_path = "config.json"

if not os.path.exists(config_path):
    raise FileNotFoundError(f"{config_path} does not exist. Please create it with valid JSON.")

with open(config_path, "r") as config_file:
    try:
        config = json.load(config_file)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {config_path}: {e}")

print("Config file loaded successfully:", config)

# Get blacklist and other configurations
blacklist = config.get("blacklist", [])

def is_blacklisted(ip: str) -> bool:
    """Checks if an IP address is in the blacklist."""
    return ip in blacklist

def inspect_packet(packet):
    """Analyzes a packet using Deep Packet Inspection."""
    try:
        src_ip = packet.ip.src
        if is_blacklisted(src_ip):
            log_event("Blocked", f"Packet from blacklisted IP {src_ip}")
            print(f"Blocked: Packet from blacklisted IP {src_ip}")
            return

        # Check protocol filtering
        if not is_protocol_allowed(packet):
            log_event("Blocked", f"Disallowed protocol in packet from {src_ip}")
            print(f"Blocked: Disallowed protocol in packet from {src_ip}")
            return

        log_event("Allowed", f"Packet from {src_ip}")
        print(f"Allowed: Packet from {src_ip}")
    except AttributeError:
        log_event("Error", "Malformed packet encountered.")
        print("Error: Malformed packet encountered.")

def start_packet_sniffer():
    """Starts live packet capture."""
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        capture = LiveCapture(interface="Ethernet")  # Replace "Ethernet" with your network interface
        for packet in capture.sniff_continuously():
            inspect_packet(packet)
    except Exception as e:
        print(f"Error occurred while sniffing packets: {e}")
        log_event("Error", f"Packet sniffer error: {e}")

if __name__ == "__main__":
    start_packet_sniffer()
