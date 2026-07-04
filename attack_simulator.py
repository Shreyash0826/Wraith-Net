import socket
import time
import random

# Target setup
TARGET_IP = "127.0.0.1"
TARGET_PORT = 2222
PAYLOADS = ["admin", "root", "nmap", "ping", "get_data"]

def send_attack(attacker_ip, payload):
    try:
        # Simulate a connection attempt
        # In a real environment, we'd spoof the source IP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((TARGET_IP, TARGET_PORT))
            s.sendall(payload.encode())
        print(f"[Simulated] Attack from {attacker_ip}: {payload}")
    except Exception as e:
        print(f"[-] Could not connect: {e}")

if __name__ == "__main__":
    print("[*] Attack Simulator starting...")
    for i in range(10):
        ip = f"192.168.1.{random.randint(1, 250)}"
        payload = random.choice(PAYLOADS)
        send_attack(ip, payload)
        time.sleep(0.5) # Burst interval
