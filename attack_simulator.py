import socket
import time
import random
import json

# Target setup
TARGET_IP = "127.0.0.1"
TARGET_PORT = 2222
LOG_FILE = "honeypot.log"
PAYLOADS = ["admin", "root", "nmap", "ping", "get_data"]

def log_attack(attacker_ip, payload):
    """Write the attack to the honeypot log file for the engine to process."""
    entry = {"source_ip": attacker_ip, "payload": payload}
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[Log] Written to {LOG_FILE}: {attacker_ip} -> {payload}")

def send_attack(attacker_ip, payload):
    try:
        # Simulate a connection attempt (keeping your original logic)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1) # Short timeout so it doesn't hang
            s.connect((TARGET_IP, TARGET_PORT))
            s.sendall(payload.encode())
        print(f"[Network] Attack from {attacker_ip} reached target.")
    except Exception:
        # We catch exceptions because the target might not be listening 
        # (which is expected for a honeypot)
        print(f"[Network] Connection refused for {attacker_ip} (expected).")

if __name__ == "__main__":
    print("[*] Attack Simulator starting...")
    # Simulate 20 attacks in a burst
    for i in range(20):
        ip = f"192.168.1.{random.randint(1, 250)}"
        payload = random.choice(PAYLOADS)
        
        # 1. Log it so the engine sees it
        log_attack(ip, payload)
        # 2. Try the network connection
        send_attack(ip, payload)
        
        time.sleep(0.2) # Faster burst interval for stress testing
