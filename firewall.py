import json
import os
from pyshark import LiveCapture
from protocol_filter import is_protocol_allowed
from logger import log_event

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

# Load configurations
blacklist = config.get("blacklist", [])
whitelist = config.get("whitelist", [])
port_rules = config.get("port_rules", {})
allowed_protocols = config.get("allowed_protocols", ["HTTP", "HTTPS", "DNS"])
alert_thresholds = config.get("alert_thresholds", {"blacklist_hits": 50, "high_traffic": 1000, "unusual_protocols": 20})
log_verbosity = config.get("log_verbosity", "detailed")

blocked_counts = {
    "blacklist_hits": 0,
    "high_traffic": 0,
    "unusual_protocols": 0
}

def is_blacklisted(ip: str) -> bool:
    return ip in blacklist

def is_whitelisted(ip: str) -> bool:
    return ip in whitelist

def is_port_allowed(port: int) -> bool:
    rule = port_rules.get(str(port), "allow")
    return rule == "allow"

def log_event_with_verbosity(event, details):
    if log_verbosity == "minimal" and event in ["Allowed", "Alert"]:
        return
    log_event(event, details)

def inspect_packet(packet):
    try:
        src_ip = packet.ip.src
        if is_whitelisted(src_ip):
            log_event_with_verbosity("Allowed", f"Packet from whitelisted IP {src_ip}")
            print(f"Allowed: Packet from whitelisted IP {src_ip}")
            return
        if is_blacklisted(src_ip):
            blocked_counts["blacklist_hits"] += 1
            log_event("Blocked", f"Packet from blacklisted IP {src_ip}")
            print(f"Blocked: Packet from blacklisted IP {src_ip}")
            return
        if not is_protocol_allowed(packet):
            blocked_counts["unusual_protocols"] += 1
            log_event("Blocked", f"Disallowed protocol in packet from {src_ip}")
            print(f"Blocked: Disallowed protocol in packet from {src_ip}")
            return
        if "TCP" in packet or "UDP" in packet:
            try:
                port = int(packet[packet.transport_layer].dstport)
                if not is_port_allowed(port):
                    log_event("Blocked", f"Disallowed port {port} in packet from {src_ip}")
                    print(f"Blocked: Disallowed port {port} in packet from {src_ip}")
                    return
            except AttributeError:
                log_event("Error", "Failed to extract port information")
        log_event_with_verbosity("Allowed", f"Packet from {src_ip}")
        print(f"Allowed: Packet from {src_ip}")
        for key, count in blocked_counts.items():
            threshold = alert_thresholds.get(key, 1000)
            if count >= threshold:
                log_event("Alert", f"{key} threshold reached: {count}")
                print(f"Alert: {key} threshold reached: {count}")
                blocked_counts[key] = 0
    except AttributeError as e:
        log_event("Error", f"Malformed or incomplete packet: {e}")
        print(f"Error: Malformed or incomplete packet encountered: {e}")

def start_packet_sniffer():
    print("Starting packet sniffer... Press Ctrl+C to stop.")
    try:
        capture = LiveCapture(interface="Ethernet")
        for packet in capture.sniff_continuously():
            inspect_packet(packet)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.")
    except Exception as e:
        print(f"Error occurred while sniffing packets: {e}")
        log_event("Error", f"Packet sniffer error: {e}")

if __name__ == "__main__":
    start_packet_sniffer()
