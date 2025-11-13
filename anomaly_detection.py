# anomaly_detection.py
"""
Anomaly Detection Module for Web Application Firewall
Implements statistical anomaly detection to identify unusual request patterns
"""

import time
from collections import defaultdict
import statistics

class AnomalyDetector:
    """
    Simple anomaly detection system that learns normal traffic patterns
    and flags suspicious behavior based on statistical thresholds
    """
    
    def __init__(self):
        # Store request patterns per IP
        self.request_history = defaultdict(list)
        self.baseline = {
            'avg_request_size': 100,  # Reasonable default
            'std_request_size': 50,
            'avg_requests_per_minute': 10,
            'std_requests_per_minute': 5,
            'common_paths': {'/login', '/dashboard', '/logout', '/monitor', '/'},
            'avg_special_chars': 5,
            'std_special_chars': 3
        }
        self.is_trained = True  # Start as trained with defaults
    
    def train_baseline(self, normal_traffic_samples):
        """
        Train the baseline using normal traffic patterns
        normal_traffic_samples: list of dict with keys: 'ip', 'path', 'payload', 'timestamp'
        """
        if not normal_traffic_samples or len(normal_traffic_samples) < 5:
            print("[Anomaly Detector] Using default baseline (insufficient training data)")
            return
        
        request_sizes = []
        special_char_counts = []
        paths = []
        ip_timestamps = defaultdict(list)
        
        for sample in normal_traffic_samples:
            # Collect metrics
            payload = sample.get('payload', '')
            request_sizes.append(len(payload))
            
            # Count special characters
            special_chars = sum(1 for c in payload if not c.isalnum() and not c.isspace())
            special_char_counts.append(special_chars)
            
            # Track paths
            paths.append(sample.get('path', ''))
            
            # Track request timing per IP
            ip = sample.get('ip', '')
            timestamp = sample.get('timestamp', time.time())
            ip_timestamps[ip].append(timestamp)
        
        # Calculate baseline statistics
        if request_sizes:
            self.baseline['avg_request_size'] = statistics.mean(request_sizes)
            self.baseline['std_request_size'] = max(statistics.stdev(request_sizes) if len(request_sizes) > 1 else 50, 50)
        
        if special_char_counts:
            self.baseline['avg_special_chars'] = statistics.mean(special_char_counts)
            self.baseline['std_special_chars'] = max(statistics.stdev(special_char_counts) if len(special_char_counts) > 1 else 3, 3)
        
        # Common paths
        from collections import Counter
        path_counts = Counter(paths)
        self.baseline['common_paths'] = {path for path, count in path_counts.items()}
        
        # Calculate average requests per minute per IP
        requests_per_minute = []
        for ip, timestamps in ip_timestamps.items():
            if len(timestamps) > 1:
                duration = max(timestamps) - min(timestamps)
                if duration > 0:
                    rpm = (len(timestamps) / duration) * 60
                    requests_per_minute.append(rpm)
        
        if requests_per_minute:
            self.baseline['avg_requests_per_minute'] = statistics.mean(requests_per_minute)
            self.baseline['std_requests_per_minute'] = max(statistics.stdev(requests_per_minute) if len(requests_per_minute) > 1 else 5, 5)
        
        self.is_trained = True
        print("[Anomaly Detector] Baseline trained successfully")
        print(f"  - Avg request size: {self.baseline['avg_request_size']:.2f} bytes")
        print(f"  - Avg special chars: {self.baseline['avg_special_chars']:.2f}")
        print(f"  - Common paths: {len(self.baseline['common_paths'])}")
    
    def calculate_anomaly_score(self, request_data):
        """
        Calculate anomaly score for a request
        Returns: (score, details) where score is 0-100 (higher = more suspicious)
        """
        if not self.is_trained:
            return 0, {"warning": "Detector not trained"}
        
        score = 0
        details = {}
        
        payload = request_data.get('payload', '')
        ip = request_data.get('ip', '')
        path = request_data.get('path', '')
        timestamp = request_data.get('timestamp', time.time())
        
        # 1. Check request size anomaly (MORE LENIENT)
        request_size = len(payload)
        if self.baseline.get('std_request_size', 0) > 0:
            z_score = abs((request_size - self.baseline['avg_request_size']) / self.baseline['std_request_size'])
            if z_score > 5:  # Changed from 3 to 5 (more lenient)
                score += 20  # Reduced from 25
                details['size_anomaly'] = f"Very unusual request size (z-score: {z_score:.2f})"
        
        # 2. Check special character density (MORE LENIENT)
        special_chars = sum(1 for c in payload if not c.isalnum() and not c.isspace())
        if self.baseline.get('std_special_chars', 0) > 0:
            z_score = abs((special_chars - self.baseline['avg_special_chars']) / self.baseline['std_special_chars'])
            if z_score > 4:  # Changed from 2.5 to 4 (more lenient)
                score += 15  # Reduced from 20
                details['special_chars_anomaly'] = f"Very unusual special character count (z-score: {z_score:.2f})"
        
        # 3. REMOVED uncommon path check (too aggressive for normal browsing)
        
        # 4. Check request rate per IP (MORE LENIENT)
        self.request_history[ip].append(timestamp)
        
        # Keep only requests from last minute
        cutoff_time = timestamp - 60
        self.request_history[ip] = [t for t in self.request_history[ip] if t > cutoff_time]
        
        requests_per_minute = len(self.request_history[ip])
        
        # Only flag if VERY high request rate
        if requests_per_minute > 50:  # More than 50 requests per minute
            score += 40
            details['high_request_rate'] = f"Excessive request rate: {requests_per_minute} req/min"
        
        # 5. Check for suspicious patterns (only add small score)
        sql_keywords = ['SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'EXEC']
        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
        
        payload_upper = payload.upper()
        if any(keyword in payload_upper for keyword in sql_keywords):
            score += 15
            details['sql_keywords'] = "Contains SQL-like keywords"
        
        if any(pattern.lower() in payload.lower() for pattern in xss_patterns):
            score += 15
            details['xss_patterns'] = "Contains XSS-like patterns"
        
        return min(score, 100), details
    
    def is_anomalous(self, request_data, threshold=70):  # Increased threshold from 60 to 70
        """
        Check if request is anomalous based on threshold
        threshold: score above which request is considered anomalous (default 70)
        """
        score, details = self.calculate_anomaly_score(request_data)
        return score >= threshold, score, details


# Initialize global detector instance
anomaly_detector = AnomalyDetector()

# Don't train on import - use sensible defaults instead
print("[Anomaly Detector] Initialized with default baseline")