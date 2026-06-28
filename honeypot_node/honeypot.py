import socket
import logging
import json
import threading
from datetime import datetime, timezone

# Configuration
BIND_IP = "0.0.0.0"
BIND_PORT = 2222
SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"

logging.basicConfig(filename='honeypot.log', level=logging.INFO, format='%(message)s')

def handle_client(client_socket, addr):
    """Function to handle individual client connections in a thread."""
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
    print(f"[+] Thread handled event from {addr[0]}: {log_entry['payload']}")
    client_socket.close()

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(10) # Higher backlog for concurrent attempts
    print(f"[*] Honeypot listening on {BIND_IP}:{BIND_PORT}...")

    while True:
        client, addr = server.accept()
        print(f"[!] New connection from {addr[0]}:{addr[1]}")
        
        # Start a new thread for this connection
        client_thread = threading.Thread(target=handle_client, args=(client, addr))
        client_thread.start()

if __name__ == "__main__":
    start_honeypot()
