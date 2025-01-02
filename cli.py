import json
import re
import sys
import argparse
import os
from logger import log_event

CONFIG_FILE = "config.json"

def load_config():
    """Helper function to load config file."""
    try:
        with open(CONFIG_FILE, "r") as config_file:
            return json.load(config_file)
    except FileNotFoundError:
        print(f"Error: {CONFIG_FILE} not found.")
        return {}
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from config file.")
        return {}

def save_config(config):
    """Helper function to save config to the file."""
    with open(CONFIG_FILE, "r+") as config_file:
        config_file.seek(0)
        json.dump(config, config_file, indent=4)
        config_file.truncate()

def is_valid_ip(ip):
    """Validates an IP address format."""
    pattern = r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." \
              r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." \
              r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\." \
              r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

def view_blacklist():
    """Displays the current blacklist."""
    config = load_config()
    if "blacklist" in config:
        print("Current Blacklist:", config["blacklist"])
    else:
        print("No blacklist found.")

def add_allowed_protocol(protocol):
    """Adds a protocol to the allowed list."""
    config = load_config()
    if "allowed_protocols" not in config:
        config["allowed_protocols"] = []
    
    if protocol not in config["allowed_protocols"]:
        config["allowed_protocols"].append(protocol)
        save_config(config)
        print(f"{protocol} added to allowed protocols.")
    else:
        print(f"{protocol} is already in the allowed protocols.")

def remove_allowed_protocol(protocol):
    """Removes a protocol from the allowed list."""
    config = load_config()
    if "allowed_protocols" in config and protocol in config["allowed_protocols"]:
        config["allowed_protocols"].remove(protocol)
        save_config(config)
        print(f"{protocol} removed from allowed protocols.")
    else:
        print(f"{protocol} not found in allowed protocols.")

def add_blacklist_ip(ip):
    """Adds an IP to the blacklist."""
    if not is_valid_ip(ip):
        print("Invalid IP address format.")
        return
    
    config = load_config()
    if "blacklist" not in config:
        config["blacklist"] = []
    
    if ip not in config["blacklist"]:
        config["blacklist"].append(ip)
        save_config(config)
        print(f"{ip} added to blacklist.")
    else:
        print(f"{ip} is already in the blacklist.")

def remove_blacklist_ip(ip):
    """Removes an IP from the blacklist."""
    config = load_config()
    if "blacklist" in config and ip in config["blacklist"]:
        config["blacklist"].remove(ip)
        save_config(config)
        print(f"{ip} removed from blacklist.")
    else:
        print(f"{ip} not found in the blacklist.")

def view_whitelist():
    """Displays the current whitelist."""
    config = load_config()
    if "whitelist" in config:
        print("Current Whitelist:", config["whitelist"])
    else:
        print("No whitelist found.")

def add_whitelist_ip(ip):
    """Adds an IP to the whitelist."""
    if not is_valid_ip(ip):
        print("Invalid IP address format.")
        return
    
    config = load_config()
    if "whitelist" not in config:
        config["whitelist"] = []
    
    if ip not in config["whitelist"]:
        config["whitelist"].append(ip)
        save_config(config)
        print(f"{ip} added to whitelist.")
    else:
        print(f"{ip} is already in the whitelist.")

def remove_whitelist_ip(ip):
    """Removes an IP from the whitelist."""
    config = load_config()
    if "whitelist" in config and ip in config["whitelist"]:
        config["whitelist"].remove(ip)
        save_config(config)
        print(f"{ip} removed from whitelist.")
    else:
        print(f"{ip} not found in the whitelist.")

def display_logs():
    """Displays firewall logs for real-time monitoring."""
    try:
        with open("firewall_logs.txt", "r") as log_file:
            logs = log_file.readlines()
            for line in logs[-10:]:  # Display last 10 logs
                print(line.strip())
    except FileNotFoundError:
        print("Error: Log file not found.")

def print_help():
    """Displays help information about CLI commands."""
    help_text = """
    Available commands:
    - add_blacklist_ip <IP>         : Adds an IP to the blacklist.
    - remove_blacklist_ip <IP>      : Removes an IP from the blacklist.
    - add_whitelist_ip <IP>         : Adds an IP to the whitelist.
    - remove_whitelist_ip <IP>      : Removes an IP from the whitelist.
    - add_allowed_protocol <protocol> : Adds a protocol to the allowed list.
    - remove_allowed_protocol <protocol> : Removes a protocol from the allowed list.
    - view_blacklist                : Displays the current blacklist.
    - view_whitelist                : Displays the current whitelist.
    - display_logs                  : Displays the last 10 firewall logs.
    - --help                        : Displays this help message.
    """
    print(help_text)

def main():
    parser = argparse.ArgumentParser(description="Firewall Configuration CLI")
    parser.add_argument("command", help="Command to execute", choices=["add_blacklist_ip", "remove_blacklist_ip", "add_whitelist_ip", "remove_whitelist_ip", 
                                                                    "add_allowed_protocol", "remove_allowed_protocol", "view_blacklist", "view_whitelist", 
                                                                    "display_logs", "--help"])
    parser.add_argument("value", help="Value for the command", nargs="?", default=None)

    args = parser.parse_args()

    if args.command == "add_blacklist_ip":
        add_blacklist_ip(args.value)
    elif args.command == "remove_blacklist_ip":
        remove_blacklist_ip(args.value)
    elif args.command == "add_whitelist_ip":
        add_whitelist_ip(args.value)
    elif args.command == "remove_whitelist_ip":
        remove_whitelist_ip(args.value)
    elif args.command == "add_allowed_protocol":
        add_allowed_protocol(args.value)
    elif args.command == "remove_allowed_protocol":
        remove_allowed_protocol(args.value)
    elif args.command == "view_blacklist":
        view_blacklist()
    elif args.command == "view_whitelist":
        view_whitelist()
    elif args.command == "display_logs":
        display_logs()
    elif args.command == "--help":
        print_help()

if __name__ == "__main__":
    main()
