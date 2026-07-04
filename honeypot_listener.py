import socket
import json
import time
from datetime import datetime

def run_listener():
    HOST, PORT = "127.0.0.1", 2222
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[*] Honeypot listening on {PORT}...")
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(1024).decode().strip()
                # Write to log file in the format the Engine expects
                log_entry = {
                    "timestamp": str(datetime.now()),
                    "source_ip": addr[0],
                    "payload": data
                }
                with open("honeypot.log", "a") as f:
                    f.write(json.dumps(log_entry) + "\n")

if __name__ == "__main__":
    run_listener()
