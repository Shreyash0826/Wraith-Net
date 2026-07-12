# app.py
from flask import Flask, render_template, jsonify
import json
import os
import subprocess

app = Flask(__name__)
LOG_FILE = 'quarantine.log'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    alerts = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            # Read last 20 logs
            lines = f.readlines()[-20:]
            for line in lines:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    return jsonify(alerts[::-1]) # Return newest first

# --- NEW API ENDPOINTS FOR INTERACTIVE RESPONSE ---

@app.route('/api/unblock/<ip>', methods=['POST'])
def unblock_ip(ip):
    # Remove from iptables
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    return jsonify({"status": "success", "message": f"{ip} unblocked"})

@app.route('/api/whitelist/<ip>', methods=['POST'])
def whitelist_ip(ip):
    # Append to a whitelist file
    with open('whitelist.txt', 'a') as f:
        f.write(f"{ip}\n")
    return jsonify({"status": "success", "message": f"{ip} whitelisted"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
