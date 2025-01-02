from collections import defaultdict

# Store connections by (src_ip, dst_ip)
connections = defaultdict(dict)

def track_connection(packet):
    """Tracks TCP/UDP connections to differentiate legitimate traffic."""
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        connection_key = (src_ip, dst_ip)

        # Track the TCP flags and connection state
        if hasattr(packet, "tcp"):
            if packet.tcp.flags == "SYN":
                connections[connection_key]["state"] = "SYN_SENT"
            elif packet.tcp.flags == "SYN,ACK":
                connections[connection_key]["state"] = "ESTABLISHED"
            elif packet.tcp.flags == "FIN":
                connections[connection_key]["state"] = "CLOSED"
                
        # Handle UDP or other protocols (e.g., ICMP)
        elif hasattr(packet, "udp"):
            # Example for UDP (can add logic if needed)
            connections[connection_key]["state"] = "UDP_TRAFFIC"
        
        # Optional: Add timeout handling for stale connections

    except AttributeError:
        pass  # Ignore non-TCP/UDP packets
