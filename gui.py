import tkinter as tk
from tkinter import messagebox, simpledialog
import json
import threading
import asyncio
from pyshark import LiveCapture
import logging

CONFIG_FILE = "config.json"

# Load and save configuration
def load_config():
    try:
        with open(CONFIG_FILE, "r") as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        config = {
            "blacklist": [],
            "whitelist": [],
            "log_file": "firewall_logs.txt",
            "alert_threshold": 50,
            "allowed_protocols": ["HTTP", "DNS", "FTP"],
            "ssl_cert": "path/to/certificate.crt"
        }
    if "whitelist" not in config:
        config["whitelist"] = []
    return config

def save_config(config):
    with open(CONFIG_FILE, "w") as config_file:
        json.dump(config, config_file, indent=4)

# Logging setup
config = load_config()
BLACKLIST = config["blacklist"]
WHITELIST = config["whitelist"]

logging.basicConfig(
    filename=config["log_file"],
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Firewall Management")

        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=20, pady=20)

        # Listboxes for displaying blacklist and whitelist
        self.blacklist_label = tk.Label(self.frame, text="Blacklist", font=("Arial", 14))
        self.blacklist_label.grid(row=0, column=0, padx=5, pady=5)

        self.blacklist_box = tk.Listbox(self.frame, height=10, width=40)
        self.blacklist_box.grid(row=1, column=0, padx=5, pady=5)

        self.whitelist_label = tk.Label(self.frame, text="Whitelist", font=("Arial", 14))
        self.whitelist_label.grid(row=0, column=1, padx=5, pady=5)

        self.whitelist_box = tk.Listbox(self.frame, height=10, width=40)
        self.whitelist_box.grid(row=1, column=1, padx=5, pady=5)

        # Packet details display
        self.packet_details_label = tk.Label(self.frame, text="Packet Details", font=("Arial", 14))
        self.packet_details_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.packet_details_box = tk.Text(self.frame, height=10, width=80)
        self.packet_details_box.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        # Buttons to add/remove IPs
        self.add_to_blacklist_btn = tk.Button(self.frame, text="Add to Blacklist", command=self.add_to_blacklist)
        self.add_to_blacklist_btn.grid(row=4, column=0, padx=5, pady=5)

        self.remove_from_blacklist_btn = tk.Button(self.frame, text="Remove from Blacklist", command=self.remove_from_blacklist)
        self.remove_from_blacklist_btn.grid(row=5, column=0, padx=5, pady=5)

        self.add_to_whitelist_btn = tk.Button(self.frame, text="Add to Whitelist", command=self.add_to_whitelist)
        self.add_to_whitelist_btn.grid(row=4, column=1, padx=5, pady=5)

        self.remove_from_whitelist_btn = tk.Button(self.frame, text="Remove from Whitelist", command=self.remove_from_whitelist)
        self.remove_from_whitelist_btn.grid(row=5, column=1, padx=5, pady=5)

        # Start and Stop Packet Sniffer
        self.start_sniffer_btn = tk.Button(self.frame, text="Start Sniffer", command=self.start_sniffer)
        self.start_sniffer_btn.grid(row=6, column=0, padx=5, pady=5)

        self.stop_sniffer_btn = tk.Button(self.frame, text="Stop Sniffer", command=self.stop_sniffer)
        self.stop_sniffer_btn.grid(row=6, column=1, padx=5, pady=5)

        # Update the listboxes with current data
        self.update_blacklist()
        self.update_whitelist()

    def update_blacklist(self):
        """Updates the blacklist listbox."""
        self.blacklist_box.delete(0, tk.END)
        for ip in BLACKLIST:
            self.blacklist_box.insert(tk.END, ip)

    def update_whitelist(self):
        """Updates the whitelist listbox."""
        self.whitelist_box.delete(0, tk.END)
        for ip in WHITELIST:
            self.whitelist_box.insert(tk.END, ip)

    def add_to_blacklist(self):
        """Adds an IP to the blacklist."""
        ip = self.prompt_ip()
        if ip:
            if ip not in BLACKLIST:
                BLACKLIST.append(ip)
                save_config(config)
                self.update_blacklist()
            else:
                messagebox.showwarning("Warning", f"IP {ip} is already in the blacklist.")

    def remove_from_blacklist(self):
        """Removes an IP from the blacklist."""
        ip = self.get_selected_ip(self.blacklist_box)
        if ip and ip in BLACKLIST:
            BLACKLIST.remove(ip)
            save_config(config)
            self.update_blacklist()

    def add_to_whitelist(self):
        """Adds an IP to the whitelist."""
        ip = self.prompt_ip()
        if ip:
            if ip not in WHITELIST:
                WHITELIST.append(ip)
                save_config(config)
                self.update_whitelist()
            else:
                messagebox.showwarning("Warning", f"IP {ip} is already in the whitelist.")

    def remove_from_whitelist(self):
        """Removes an IP from the whitelist."""
        ip = self.get_selected_ip(self.whitelist_box)
        if ip and ip in WHITELIST:
            WHITELIST.remove(ip)
            save_config(config)
            self.update_whitelist()

    def prompt_ip(self):
        """Prompts the user to enter an IP address."""
        ip = simpledialog.askstring("Input", "Enter IP Address:")
        return ip if ip else None

    def get_selected_ip(self, listbox):
        """Gets the selected IP from a listbox."""
        try:
            return listbox.get(listbox.curselection())
        except tk.TclError:
            messagebox.showwarning("Warning", "Please select an IP to remove.")
            return None

    def start_sniffer(self):
        """Starts packet sniffer in a separate thread."""
        self.sniffer_thread = threading.Thread(target=self.sniff_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

    def stop_sniffer(self):
        """Stops the packet sniffer."""
        print("Packet Sniffer Stopped.")

    def sniff_packets(self):
        """Simulates packet sniffing."""
        loop = asyncio.new_event_loop()  # Create a new event loop for the sniffer thread
        asyncio.set_event_loop(loop)  # Set this loop for the current thread
        capture = LiveCapture(interface="Ethernet")

        print("Packet Sniffer started...")
        try:
            for packet in capture.sniff_continuously():
                if hasattr(packet, "ip"):
                    self.inspect_packet(packet)
        except KeyboardInterrupt:
            print("Sniffer stopped.")
        finally:
            loop.close()  # Close the event loop once done

    def inspect_packet(self, packet):
        """Inspects and logs packets."""
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        protocol = packet.transport_layer

        # Update the packet details text box
        packet_details = f"Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}"
        self.packet_details_box.insert(tk.END, packet_details + "\n")
        self.packet_details_box.yview(tk.END)

        # Log the packet action (Allowed/Blocked)
        if src_ip in BLACKLIST:
            print(f"Blocked: Packet from blacklisted IP {src_ip}")
            self.log_packet_action("Blocked", src_ip, dst_ip, protocol)
        elif src_ip in WHITELIST:
            print(f"Allowed: Packet from whitelisted IP {src_ip}")
            self.log_packet_action("Allowed", src_ip, dst_ip, protocol)
        else:
            print(f"Allowed: Packet from {src_ip}")
            self.log_packet_action("Allowed", src_ip, dst_ip, protocol)

    def log_packet_action(self, action, src_ip, dst_ip, protocol):
        """Logs the action taken on a packet (allowed/blocked)."""
        log_message = f"{action}: Source IP {src_ip}, Destination IP {dst_ip}, Protocol {protocol}"
        logging.info(log_message)

# Running the GUI
if __name__ == "__main__":
    root = tk.Tk()
    gui = FirewallGUI(root)
    root.mainloop()
