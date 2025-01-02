import re
from logger import log_event

def is_protocol_allowed(packet):
    """Filters packets based on allowed protocols and checks for malicious patterns."""
    allowed_protocols = ["HTTP", "DNS", "FTP", "HTTPS", "SMTP", "ICMP", "SSH", "TCP", "UDP"]

    try:
        packet_protocol = packet.highest_layer

        # Check if the packet's protocol is in the allowed protocols list
        if packet_protocol in allowed_protocols:
            # Check for potential malicious signatures based on the protocol
            if packet_protocol == "HTTP":
                # Example: Detect possible XSS attacks in HTTP packets
                if hasattr(packet, "http"):
                    # Searching for common XSS attack patterns in the HTTP content
                    if re.search(r"<script.*?>", packet.http.get_raw_packet().decode("utf-8", errors="ignore"), re.IGNORECASE):
                        log_event("Blocked", f"XSS attack detected in HTTP packet from {packet.ip.src}")
                        return False  # Block packet if XSS pattern is found

            elif packet_protocol == "TCP":
                # Example: Detect SYN flood or suspicious TCP sequence number manipulation
                if hasattr(packet, "tcp"):
                    # SYN flood detection: Look for SYN packets without completion of the handshake
                    if packet.tcp.flags == "S" and (packet.tcp.seq == "0" or packet.tcp.ack == "0"):
                        log_event("Blocked", f"SYN flood or suspicious SYN packet from {packet.ip.src}")
                        return False  # Block packet if SYN flood or suspicious TCP flag detected

            elif packet_protocol == "ICMP":
                # ICMP can be used for flooding attacks; detecting high frequency of Echo Request (ping)
                if hasattr(packet, "icmp"):
                    if packet.icmp.type == "8":  # Echo Request type
                        log_event("Blocked", f"Possible ICMP flood detected from {packet.ip.src}")
                        return False  # Block packet if it's part of an ICMP flood attack

            elif packet_protocol == "DNS":
                # Detect DNS amplification attack by inspecting query size and other patterns
                if hasattr(packet, "dns"):
                    if len(packet.dns.qd) > 512:  # Oversized DNS query (sign of DNS amplification)
                        log_event("Blocked", f"DNS amplification attempt detected from {packet.ip.src}")
                        return False  # Block packet if DNS amplification detected

            elif packet_protocol == "UDP":
                # Detect potential DDoS amplification via UDP packets
                if hasattr(packet, "udp"):
                    if packet.udp.length > 512:  # Oversized UDP packets
                        log_event("Blocked", f"Potential DDoS amplification attack detected from {packet.ip.src}")
                        return False  # Block packet if oversized UDP packet detected

            # Additional protocol checks can be added here for new patterns or attacks

            return True  # Return True if the packet is in the allowed protocol list and no signatures found

        else:
            # Log the disallowed protocol for further analysis
            log_event("Disallowed Protocol", f"Packet with protocol {packet_protocol} is not allowed.")
            return False

    except AttributeError as e:
        # If the packet does not have a highest_layer attribute, log it as an error
        log_event("Error", f"Malformed packet: {e}")
        return False
