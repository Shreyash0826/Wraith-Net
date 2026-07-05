# config.py - Central Configuration

# Network Settings
HOST = "127.0.0.1"
PORT = 2222

# Security Policies
WHITELIST = ["10.223.142.11", "192.168.56.101", "172.17.0.1", "172.17.0.1", "127.0.0.1"]
THREAT_KEYWORDS = ["admin", "root", "nmap", "ping", "get_data", "sqlmap"]

# File Paths
LOG_FILE = "honeypot.log"
QUARANTINE_LOG = "quarantine.log"
