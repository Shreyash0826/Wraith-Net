# honeypot.py
import socket
import logging
import json
import threading
import signal
import sys
import os
import pwd
from datetime import datetime, timezone

# Configuration
BIND_IP = "0.0.0.0"
BIND_PORT = 2222
SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"

logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(message)s')

def drop_privileges():
    """Drops root privileges to the 'wraith_sandbox' user."""
    if os.getuid() == 0:
        pwnam = pwd.getpwnam('wraith_sandbox')
        os.setgroups([])
        os.setgid(pwnam.pw_gid)
        os.setuid(pwnam.pw_uid)
        print("[*] Privileges dropped. Running as user: wraith_sandbox")

def signal_handler(sig, frame):
    print("\n[*] Shutting down honeypot cleanly...")
    sys.exit(0)

def handle_client(client_socket, addr):
    payload = ""
    try:
        client_socket.settimeout(5.0)
        client_socket.send(SSH_BANNER)
        data = client_socket.recv(1024)
        payload = data.decode(errors='ignore').strip()
    except Exception:
        payload = "NO_PAYLOAD"
    
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": addr[0],
        "source_port": addr[1],
        "target_port": BIND_PORT,
        "payload": payload
    }
    
    logging.info(json.dumps(log_entry))
    client_socket.close()

def start_honeypot():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # 1. Bind to port (Still root)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(10)
    
    # 2. Drop privileges immediately after binding
    drop_privileges()
    
    print(f"[*] Honeypot active on {BIND_IP}:{BIND_PORT}. Press Ctrl+C to stop.")

    while True:
        client, addr = server.accept()
        client_thread = threading.Thread(target=handle_client, args=(client, addr))
        client_thread.start()

if __name__ == "__main__":
    start_honeypot()
