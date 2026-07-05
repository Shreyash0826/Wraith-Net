# Wraith-Net: Security Honeypot & Quarantine Engine

## Overview
Wraith-Net is a modular security framework designed to capture, log, and automatically quarantine malicious network traffic using Linux kernel-level filtering (iptables).

## Project Structure
- `honeypot_listener.py`: Captures incoming raw TCP traffic.
- `quarantine_engine.py`: Scans logs for threats and automates firewall blocking.
- `attack_simulator.py`: Stress-testing tool to verify detection latency.

## Getting Started
1. Run `honeypot_listener.py` to start the honeypot.
2. Run `sudo quarantine_engine.py` to activate real-time protection.
3. Run `attack_simulator.py` to test the system integrity.
