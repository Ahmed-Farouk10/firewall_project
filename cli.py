import json

def view_blacklist():
    """Displays the current blacklist."""
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
    print("Current Blacklist:", config["blacklist"])

def add_allowed_protocol(protocol):
    """Adds a protocol to the allowed list."""
    with open("config.json", "r+") as config_file:
        config = json.load(config_file)
        if protocol not in config["allowed_protocols"]:
            config["allowed_protocols"].append(protocol)
            config_file.seek(0)
            json.dump(config, config_file, indent=4)
            config_file.truncate()
        print(f"{protocol} added to allowed protocols.")

def add_blacklist_ip(ip):
    """Adds an IP to the blacklist."""
    with open("config.json", "r+") as config_file:
        config = json.load(config_file)
        if ip not in config["blacklist"]:
            config["blacklist"].append(ip)
            config_file.seek(0)
            json.dump(config, config_file, indent=4)
            config_file.truncate()
        print(f"{ip} added to blacklist.")
