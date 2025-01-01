import json
import os
from traffic_analysis import analyze_traffic, detect_anomalies
from daemon import start_daemon
from logger import log_event
from protocol_filter import is_protocol_allowed
from stateful import track_connection
from cli import view_blacklist
from pyshark import LiveCapture

# Load configuration
CONFIG_FILE = "config.json"
with open(CONFIG_FILE, "r") as f:
    config = json.load(f)

# Test Cases
def test_logger():
    print("Testing Logger...")
    try:
        log_event("TestEvent", "This is a test log.")
        print("Logger: PASSED")
    except Exception as e:
        print(f"Logger: FAILED - {e}")

def test_blacklist():
    print("Testing Blacklist Functionality...")
    blacklisted_ip = config.get("blacklist", [])[0]
    if blacklisted_ip:
        assert blacklisted_ip in config["blacklist"]
        print("Blacklist Check: PASSED")
    else:
        print("Blacklist Check: FAILED - No blacklisted IPs found.")

def test_protocol_filtering():
    print("Testing Protocol Filtering...")
    class MockPacket:
        highest_layer = "HTTP"  # Simulating the correct attribute
    allowed = is_protocol_allowed(MockPacket())
    if allowed:
        print("Protocol Filtering: PASSED")
    else:
        print("Protocol Filtering: FAILED")

def test_anomaly_detection():
    print("Testing Traffic Analysis...")
    try:
        for i in range(110):  # Simulate packets
            mock_packet = type("MockPacket", (), {"length": 500, "ip": type("IP", (), {"ttl": 64})})
            analyze_traffic(mock_packet)
        detect_anomalies()
        print("Anomaly Detection: PASSED")
    except Exception as e:
        print(f"Anomaly Detection: FAILED - {e}")

def test_stateful_tracking():
    print("Testing Stateful Tracking...")
    try:
        mock_packet = type("MockPacket", (), {
            "ip": type("IP", (), {"src": "192.168.1.1", "dst": "192.168.1.2"}),
            "tcp": type("TCP", (), {"flags": "SYN"})
        })
        track_connection(mock_packet)
        print("Stateful Tracking: PASSED")
    except Exception as e:
        print(f"Stateful Tracking: FAILED - {e}")

def test_live_capture():
    print("Testing Live Capture...")
    try:
        # Using the specified Ethernet interface
        capture = LiveCapture(interface="\\Device\\NPF_{783316AD-29E2-4CE2-A53D-FC1D8CC89E1F}")
        capture.sniff(timeout=10)
        print(f"Packets Captured: {len(capture)}")
        print("Live Capture: PASSED")
    except Exception as e:
        print(f"Live Capture: FAILED - {e}")


def test_view_blacklist():
    print("Testing CLI Blacklist Viewer...")
    try:
        view_blacklist()
        print("CLI Blacklist Viewer: PASSED")
    except Exception as e:
        print(f"CLI Blacklist Viewer: FAILED - {e}")

# Run Tests
if __name__ == "__main__":
    test_logger()
    test_blacklist()
    test_protocol_filtering()
    test_anomaly_detection()
    test_stateful_tracking()
    test_live_capture()
    test_view_blacklist()
