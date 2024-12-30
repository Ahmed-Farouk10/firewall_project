import json

def view_blacklist():
    """Displays the current blacklist."""
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
    print("Current Blacklist:", config["blacklist"])
