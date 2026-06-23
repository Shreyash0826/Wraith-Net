import socket
import logging

# Configuration
BIND_IP = "0.0.0.0"
BIND_PORT = 2222
SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"

# Setup Logging
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)
    print(f"[*] Honeypot listening on {BIND_IP}:{BIND_PORT}...")

    while True:
        client, addr = server.accept()
        log_msg = f"Connection received from {addr[0]}:{addr[1]}"
        
        # Print to console and log to file
        print(f"[!] {log_msg}")
        logging.info(log_msg)

        client.send(SSH_BANNER)
        client.close()

if __name__ == "__main__":
    start_honeypot()
