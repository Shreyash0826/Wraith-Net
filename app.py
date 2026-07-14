# app.py
from flask import Flask, render_template, jsonify, request
import json
import os
import subprocess

app = Flask(__name__)
LOG_FILE = 'quarantine.log'

@app.route('/')
def index():
    return render_template('index.html')

# --- FORENSIC & ALERT ENDPOINTS ---

@app.route('/api/alerts')
def get_alerts():
    alerts = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()[-20:]
            for line in lines:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    return jsonify(alerts[::-1]) # Return newest first

@app.route('/api/forensic_logs')
def get_forensic_logs():
    """Returns the last 20 logs for the Forensic Feed."""
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()[-20:]
            for line in lines:
                if line.strip():
                    logs.append(json.loads(line))
    return jsonify(logs[::-1])

# --- CONTROL & HEALTH ENDPOINTS ---

@app.route('/api/clear_all', methods=['POST'])
def clear_all():
    """Emergency: Flushes all INPUT rules."""
    subprocess.run(["sudo", "iptables", "-F", "INPUT"])
    return jsonify({"status": "success", "message": "Firewall cleared"})

@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    return jsonify({"status": "success", "message": f"{ip} unblocked"})

@app.route('/api/whitelist/<ip>', methods=['POST'])
def whitelist_ip(ip):
    with open('whitelist.txt', 'a') as f:
        f.write(f"{ip}\n")
    return jsonify({"status": "success", "message": f"{ip} whitelisted"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
