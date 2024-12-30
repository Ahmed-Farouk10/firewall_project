import os

def start_daemon():
    """Starts the firewall as a daemon."""
    os.system("python firewall.py &")
