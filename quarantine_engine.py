import time
import json
import subprocess
import logging
from datetime import datetime
# Import your centralized configs
from config import WHITELIST, THREAT_KEYWORDS, LOG_FILE, QUARANTINE_LOG
# Import the new Intelligence module
from intelligence import BehaviorTracker

# Setup Forensic Logging
logging.basicConfig(
    filename='quarantine.log',
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s'
)

# Initialize the Brain
tracker = BehaviorTracker()

def log_incident(ip, payload, score):
    message = f"BLOCKING IP: {ip} | TRIGGER: {payload} | FINAL SCORE: {score}"
    logging.info(message)
    print(f"[!] Logged: {message}")

def block_ip(ip_address, payload, score):
    if ip_address in WHITELIST:
        return
    
    # Check for existing rule
    result = subprocess.run(["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"], 
                            capture_output=True)
    
    if result.returncode != 0:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"])
        log_incident(ip_address, payload, score) 

def start_watcher():
    print("[*] Quarantine Engine (Intelligence Mode) active...")
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            try:
                data = json.loads(line.strip())
                source_ip = data.get('source_ip')
                payload = data.get("payload", "").lower()
                
                # Get the threat score from the Brain
                score = tracker.analyze_payload(source_ip, payload)
                print(f"[*] IP: {source_ip} | Threat Score: {score} | Payload: {payload}")
                
                # Dynamic Thresholding: Block if score is 15 or higher
                if score >= 15:
                    block_ip(source_ip, payload, score)
                    
            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    start_watcher()
