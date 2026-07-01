import time
import json
import subprocess

LOG_FILE = "honeypot.log"
# Malicious keywords we want to block
THREAT_KEYWORDS = ["root", "admin", "nmap", "cat /etc/passwd"]

def block_ip(ip_address):
    print(f"[!] QUARANTINE: Blocking IP {ip_address}")
    # This is the command that will eventually talk to the firewall
    # command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    # subprocess.run(command)

def process_log_entry(line):
    try:
        data = json.loads(line)
        payload = data.get("payload", "").lower()
        
        # Check if payload contains any threat keyword
        if any(keyword in payload for keyword in THREAT_KEYWORDS):
            print(f"[!] Threat detected from {data['source_ip']} with payload: {payload}")
            block_ip(data['source_ip'])
            
    except json.JSONDecodeError:
        pass

def start_watcher():
    print("[*] Quarantine Engine starting...")
    with open(LOG_FILE, "r") as f:
        # Go to the end of the file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            process_log_entry(line)

if __name__ == "__main__":
    start_watcher()
