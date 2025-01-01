def is_protocol_allowed(packet):
    """Filters packets based on allowed protocols."""
    allowed_protocols = ["HTTP", "DNS", "FTP", "HTTPS", "SMTP"]
    try:
        return packet.highest_layer in allowed_protocols
    except AttributeError:
        return False
