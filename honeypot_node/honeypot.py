import socket
import logging
import json
from datetime import datetime, timezone

# Configuration
BIND_IP = "0.0.0.0"
BIND_PORT = 2222
SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"

# Setup Logging
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(message)s' # We store the JSON string directly
)

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)
    print(f"[*] Honeypot listening on {BIND_IP}:{BIND_PORT}...")

    while True:
        client, addr = server.accept()
        
        # Capture raw data
        payload = ""
        try:
            client.settimeout(5.0)
            client.send(SSH_BANNER)
            data = client.recv(1024)
            payload = data.decode(errors='ignore').strip()
        except Exception:
            payload = "NO_PAYLOAD"
        
        # Construct JSON log using timezone-aware UTC
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": addr[0],
            "source_port": addr[1],
            "target_port": BIND_PORT,
            "payload": payload
        }
        
        # Log as a JSON string
        logging.info(json.dumps(log_entry))
        print(f"[+] Logged event: {log_entry}")
        
        client.close()

if __name__ == "__main__":
    start_honeypot()
