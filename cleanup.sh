#!/bin/bash
# Reset firewall and logs for a clean slate
sudo iptables -F
echo "" > honeypot.log
echo "" > quarantine.log
echo "[*] Environment reset successful."
