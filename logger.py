import logging

logging.basicConfig(filename="firewall_logs.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

def log_event(event, details):
    """Logs events to the firewall log file."""
    logging.info(f"{event}: {details}")
