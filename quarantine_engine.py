import time
import json
import subprocess
import os

LOG_FILE = "honeypot.log"
THREAT_KEYWORDS = ["root", "admin", "nmap", "cat /etc/passwd"]
WHITELIST = ["127.0.0.1", "10.223.142.11", "192.168.56.101", "172.17.0.1", "172.18.0.1"] 

def is_already_blocked(ip):
    result = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], 
                            capture_output=True, text=True)
    return result.returncode == 0

def block_ip(ip_address):
    if ip_address in WHITELIST:
        return
    if not is_already_blocked(ip_address):
        print(f"[!!!] QUARANTINE: Blocking {ip_address}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])

def start_watcher():
    print("[*] Quarantine Engine (Polling Mode) active...")
    # Open file in a way that doesn't cache old data
    with open(LOG_FILE, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            try:
                data = json.loads(line.strip())
                payload = data.get("payload", "").lower()
                if any(k in payload for k in THREAT_KEYWORDS):
                    print(f"[!] Threat detected from {data['source_ip']}")
                    block_ip(data['source_ip'])
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    start_watcher()
