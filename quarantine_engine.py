import time
import json
import subprocess
import logging
from datetime import datetime

# Setup Forensic Logging
logging.basicConfig(
    filename='quarantine.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

LOG_FILE = "honeypot.log"
THREAT_KEYWORDS = ["root", "admin", "nmap", "cat /etc/passwd"]
WHITELIST = ["127.0.0.1", "10.223.142.11", "192.168.56.101", "172.17.0.1", "172.18.0.1"] 

def log_incident(ip, payload):
    message = f"BLOCKING IP: {ip} | TRIGGER: {payload}"
    logging.info(message)
    print(f"[!] Logged: {message}")

def block_ip(ip_address, payload):
    if ip_address in WHITELIST:
        return
    
    # Check for existing rule
    result = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"], 
                            capture_output=True)
    
    if result.returncode != 0:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        log_incident(ip_address, payload) # Log only on new blocks

def start_watcher():
    print("[*] Quarantine Engine (Forensic Mode) active...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                data = json.loads(line.strip())
                payload = data.get("payload", "").lower()
                if any(k in payload for k in THREAT_KEYWORDS):
                    block_ip(data['source_ip'], payload)
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    start_watcher()
