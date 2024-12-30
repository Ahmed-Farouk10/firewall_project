def is_protocol_allowed(packet):
    """Filters packets based on protocol."""
    allowed_protocols = ["HTTP", "DNS", "FTP"]
    try:
        return packet.highest_layer in allowed_protocols
    except AttributeError:
        return False
