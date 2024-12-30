from collections import defaultdict

connections = defaultdict(dict)

def track_connection(packet):
    """Tracks TCP/UDP connections to differentiate legitimate traffic."""
    try:
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        connection_key = (src_ip, dst_ip)

        if packet.tcp.flags == "SYN":
            connections[connection_key]["state"] = "SYN_SENT"
        elif packet.tcp.flags == "SYN,ACK":
            connections[connection_key]["state"] = "ESTABLISHED"
        elif packet.tcp.flags == "FIN":
            connections[connection_key]["state"] = "CLOSED"

    except AttributeError:
        pass  # Ignore non-TCP/UDP packets
