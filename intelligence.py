# intelligence.py
import time
from config import THREAT_KEYWORDS

class BehaviorTracker:
    def __init__(self):
        # Format: {ip: {'score': 0, 'last_seen': timestamp}}
        self.tracker = {}
        self.DECAY_TIME = 30  # Reduced to 30s for testing (increase to 300+ later)
        self.DECAY_AMOUNT = 5
        self.VELOCITY_THRESHOLD = 2.0 

    def analyze_payload(self, source_ip, payload):
        current_time = time.time()
        
        # Initialize or fetch existing data
        if source_ip not in self.tracker:
            self.tracker[source_ip] = {'score': 0, 'last_seen': current_time}
        
        data = self.tracker[source_ip]
        
        # 1. Apply Decay
        # If the gap between now and last seen exceeds DECAY_TIME, decay the score
        time_since_last = current_time - data['last_seen']
        if time_since_last > self.DECAY_TIME:
            # Decay based on how many "decay intervals" have passed
            intervals = int(time_since_last // self.DECAY_TIME)
            data['score'] = max(0, data['score'] - (intervals * self.DECAY_AMOUNT))
            
        # 2. Calculate Velocity (Rapid fire detection)
        score_increment = 5
        if time_since_last < self.VELOCITY_THRESHOLD:
            score_increment += 5 
            
        # 3. Apply Scoring
        payload = payload.lower()
        if any(word in payload for word in THREAT_KEYWORDS):
            data['score'] += score_increment
        if "nmap" in payload or "root" in payload:
            data['score'] += 10
            
        # Update timestamp
        data['last_seen'] = current_time
        return data['score']

    def get_confidence_level(self, score):
        if score >= 20: return "CRITICAL"
        elif score >= 15: return "HIGH"
        elif score >= 10: return "MEDIUM"
        else: return "LOW"
