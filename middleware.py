from flask import request
import re
import time
from rules import RULES
from database import log_attack, get_client_ip
from anomaly_detection import AnomalyDetector

SAFE_PATHS = ['/login', '/', '/logout', '/favicon.ico', '/monitor', '/api/logs']

anomaly_detector = AnomalyDetector()

# Train with normal traffic (do this once on startup)
# You can load from a file or database
normal_samples = [
    {'ip': '127.0.0.1', 'path': '/login', 'payload': 'username=test&password=test', 'timestamp': time.time()},
    {'ip': '127.0.0.1', 'path': '/dashboard', 'payload': '', 'timestamp': time.time()},
    # ... more normal samples
]
anomaly_detector.train_baseline(normal_samples)

def waf_middleware(app):
    @app.before_request
    def inspect_request():
        # Skip monitoring for safe paths (GET only, no query params)
        if request.path in SAFE_PATHS and request.method == 'GET' and not request.args:
            return
        
        # Skip static files
        if request.path.startswith('/static'):
            return
            
        try:
            get_data = request.args.to_dict(flat=True)
            post_data = request.form.to_dict(flat=True)
        except Exception:
            get_data, post_data = {}, {}

        data = str(get_data) + str(post_data)
        data += str(request.headers.get('User-Agent', '')) + str(request.path)

        # ===========================
        # PATTERN MATCHING DETECTION
        # ===========================
        for attack_type, patterns in RULES.items():
            for pattern in patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    ip = get_client_ip(request)
                    user_agent = request.headers.get('User-Agent', 'Unknown')
                    log_attack(ip, attack_type, data[:500], request.path, user_agent)
                    print(f"[WAF BLOCKED] {attack_type} from {ip} (pattern: {pattern})")
                    return "⚠️ Request blocked: suspicious activity detected.", 403
        
        # ===========================
        # ANOMALY DETECTION
        # ===========================
        if anomaly_detector.is_trained:
            request_data = {
                'ip': get_client_ip(request),
                'path': request.path,
                'payload': data,
                'timestamp': time.time()
            }
            
            is_anomalous, score, details = anomaly_detector.is_anomalous(request_data, threshold=60)
            
            if is_anomalous:
                ip = get_client_ip(request)
                user_agent = request.headers.get('User-Agent', 'Unknown')
                details_str = ', '.join([f"{k}: {v}" for k, v in details.items()])
                payload = f"Anomaly Score: {score} | {details_str}"
                log_attack(ip, 'Anomalous Behavior', payload[:500], request.path, user_agent)
                print(f"[WAF BLOCKED] Anomalous behavior from {ip} (score: {score})")
                print(f"  Details: {details}")
                return "⚠️ Request blocked: suspicious activity detected.", 403
        
        # Otherwise allow request to proceed
    