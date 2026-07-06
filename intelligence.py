# intelligence.py
from config import THREAT_KEYWORDS

class BehaviorTracker:
    def __init__(self):
        # Stores IP as key, score as value
        self.tracker = {}

    def analyze_payload(self, source_ip, payload):
        score = 0
        payload = payload.lower()
        
        # Scoring logic
        if any(word in payload for word in THREAT_KEYWORDS):
            score += 5
        if "nmap" in payload:
            score += 10
        if "root" in payload:
            score += 10
            
        # Update session score
        self.tracker[source_ip] = self.tracker.get(source_ip, 0) + score
        return self.tracker[source_ip]
