# quarantine_engine.py
import time
import json
import subprocess
import logging
from datetime import datetime
from config import WHITELIST, THREAT_KEYWORDS, LOG_FILE, QUARANTINE_LOG
from intelligence import BehaviorTracker

logging.basicConfig(
    filename='quarantine.log',
    level=logging.INFO,
    format='%(message)s' 
)

tracker = BehaviorTracker()

def log_incident(ip, payload, score, reason="THRESHOLD_EXCEEDED"):
    alert = {
        "timestamp": datetime.now().isoformat(),
        "ip": ip,
        "action": "BLOCK",
        "reason": reason,
        "final_score": score,
        "payload_snippet": payload[:20]
    }
    logging.info(json.dumps(alert))
    print(f"[!] Alert Generated: {json.dumps(alert)}")

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
    print("[*] Quarantine Engine (Testing Mode) active...")
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
                
                score = tracker.analyze_payload(source_ip, payload)
                confidence = tracker.get_confidence_level(score)
                
                print(f"[*] IP: {source_ip} | Score: {score} | Level: {confidence}")
                
                # UPDATED FOR TESTING: Block if score is 0 or higher
                if score >= 15:
                    block_ip(source_ip, payload, score)
                    
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"[!] Error processing log: {e}")

if __name__ == "__main__":
    start_watcher()
