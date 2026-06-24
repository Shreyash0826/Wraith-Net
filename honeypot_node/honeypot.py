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

        # 1. Send the bait
        client.send(SSH_BANNER)
        
        # 2. Capture the payload (The "Exploit" attempt)
        try:
            # Set a small timeout so the script doesn't hang forever
            client.settimeout(5.0)
            data = client.recv(1024) 
            if data:
                payload_msg = f"Payload from {addr[0]}: {data.decode(errors='ignore').strip()}"
                print(f"[+] {payload_msg}")
                logging.info(payload_msg)
        except socket.timeout:
            print(f"[-] Connection from {addr[0]} timed out waiting for payload.")
        except Exception as e:
            print(f"[-] Error receiving data: {e}")
        
        # 3. Close the connection
        client.close()

if __name__ == "__main__":
    start_honeypot()
