import logging

# Set up logging configuration with a more detailed format
logging.basicConfig(
    filename="firewall_logs.txt", 
    level=logging.DEBUG,  # Log all levels, including DEBUG, INFO, WARNING, ERROR, CRITICAL
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_event(event, details, level="INFO"):
    """
    Logs events with a specified level (INFO, WARNING, ERROR, DEBUG, CRITICAL) to the firewall log file.
    
    Parameters:
    event (str): The event type, such as "Allowed", "Blocked", "Alert", etc.
    details (str): Detailed information about the event.
    level (str): The severity level of the log (e.g., INFO, WARNING, ERROR, DEBUG, CRITICAL). Default is INFO.
    """
    
    # Ensure the level is valid
    valid_levels = {"INFO", "WARNING", "ERROR", "DEBUG", "CRITICAL"}
    if level not in valid_levels:
        level = "INFO"  # Default to INFO if the level is invalid
    
    # Log the event with the appropriate severity level
    if level == "INFO":
        logging.info(f"{event}: {details}")
    elif level == "WARNING":
        logging.warning(f"{event}: {details}")
    elif level == "ERROR":
        logging.error(f"{event}: {details}")
    elif level == "DEBUG":
        logging.debug(f"{event}: {details}")
    elif level == "CRITICAL":
        logging.critical(f"{event}: {details}")
    
    # Additionally, print the event to the console for real-time monitoring
    print(f"{event}: {details}")

def log_anomaly(packet, details):
    """Logs an anomaly detected in the traffic."""
    # Adding packet details (IP address, traffic pattern, etc.)
    log_event("Anomaly Detected", f"Packet from {packet.ip.src} - {details}", level="WARNING")

def log_attack(packet, details):
    """Logs an attack attempt or suspicious activity."""
    # Attack-specific logging with packet info and threat details
    log_event("Attack Detected", f"Packet from {packet.ip.src} - {details}", level="ERROR")

def log_ssl_event(details, level="INFO"):
    """Logs SSL-related events, such as certificate validation or handshake issues."""
    # Use this for logging SSL certificate validation, handshake issues, or certificate errors
    log_event("SSL Event", details, level)

def log_certificate_issue(certificate_details, level="ERROR"):
    """Logs issues related to SSL certificates such as expired certificates or validation failures."""
    log_event("SSL Certificate Issue", certificate_details, level)

def log_ssl_handshake(packet, details):
    """Logs SSL handshake events, e.g., successful handshake or errors during the SSL/TLS handshake."""
    log_event("SSL Handshake Event", f"Packet from {packet.ip.src} - {details}", level="INFO")

