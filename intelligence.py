# intelligence.py
import time
from config import THREAT_KEYWORDS

class BehaviorTracker:
    def __init__(self):
        # Format: {ip: {'score': 0, 'last_seen': timestamp}}
        self.tracker = {}
        self.DECAY_TIME = 300  # 5 minutes to decay
        self.VELOCITY_THRESHOLD = 2.0 # Seconds between requests

    def analyze_payload(self, source_ip, payload):
        current_time = time.time()
        
        # Initialize or fetch existing data
        if source_ip not in self.tracker:
            self.tracker[source_ip] = {'score': 0, 'last_seen': current_time}
        
        data = self.tracker[source_ip]
        
        # 1. Apply Decay (if time has passed)
        if current_time - data['last_seen'] > self.DECAY_TIME:
            data['score'] = max(0, data['score'] - 5)
            
        # 2. Calculate Velocity (Rapid fire detection)
        time_delta = current_time - data['last_seen']
        score_increment = 5
        if time_delta < self.VELOCITY_THRESHOLD:
            score_increment += 5 # Extra penalty for rapid attacks
            
        # 3. Apply Scoring
        payload = payload.lower()
        if any(word in payload for word in THREAT_KEYWORDS):
            data['score'] += score_increment
        if "nmap" in payload or "root" in payload:
            data['score'] += 10
            
        data['last_seen'] = current_time
        return data['score']
