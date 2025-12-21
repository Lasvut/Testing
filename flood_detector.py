"""
Flood Detection Module

Analyzes attack patterns and detects flood conditions
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from alerts_config import alert_config
from constants import (
    WINDOW_1_MINUTE,
    WINDOW_5_MINUTES,
    WINDOW_10_MINUTES,
    WINDOW_1_HOUR,
    MAX_ATTACK_TYPE_WINDOW_SIZE,
    MAX_GLOBAL_ATTACK_WINDOW_SIZE,
    FLOOD_THRESHOLD_PER_IP,
    FLOOD_THRESHOLD_TOTAL,
    FLOOD_VELOCITY_MULTIPLIER,
    FLOOD_TYPE_CONCENTRATION_PCT,
    FLOOD_MIN_ATTACKS_FOR_CONCENTRATION
)


class FloodDetector:
    """Detects attack floods and abnormal traffic patterns"""

    def __init__(self):
        """Initialize flood detector"""
        self.config = alert_config

        # Sliding window storage (stores timestamps of attacks)
        # Format: {ip: deque([timestamp1, timestamp2, ...])}
        self.attack_windows = defaultdict(lambda: deque(maxlen=MAX_ATTACK_TYPE_WINDOW_SIZE))

        # Global attack window (all IPs)
        self.global_attack_window = deque(maxlen=MAX_GLOBAL_ATTACK_WINDOW_SIZE)

        # Baseline tracking for velocity detection
        self.baseline_rates = {
            'last_hour': 0,
            'last_10min': 0,
            'last_updated': time.time()
        }

        # Attack type tracking
        self.attack_type_windows = defaultdict(lambda: deque(maxlen=MAX_ATTACK_TYPE_WINDOW_SIZE))

    def record_attack(self, ip, attack_type, timestamp=None):
        """
        Record an attack for flood detection analysis

        Args:
            ip: Source IP address
            attack_type: Type of attack
            timestamp: Attack timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = time.time()

        # Record in IP-specific window
        self.attack_windows[ip].append(timestamp)

        # Record in global window
        self.global_attack_window.append({
            'ip': ip,
            'type': attack_type,
            'time': timestamp
        })

        # Record by attack type
        self.attack_type_windows[attack_type].append(timestamp)

    def check_flood(self, ip, attack_type=None):
        """
        Check if current traffic pattern indicates a flood

        Args:
            ip: Source IP to check
            attack_type: Optional attack type

        Returns:
            tuple: (is_flood: bool, flood_type: str, details: dict)
        """
        current_time = time.time()

        # Clean old entries (older than 5 minutes)
        self._clean_old_entries(current_time)

        # Get thresholds from config (with constants as defaults)
        per_ip_threshold = self.config.get('flood_threshold_per_ip', FLOOD_THRESHOLD_PER_IP)
        total_threshold = self.config.get('flood_threshold_total', FLOOD_THRESHOLD_TOTAL)
        velocity_multiplier = self.config.get('flood_velocity_multiplier', FLOOD_VELOCITY_MULTIPLIER)

        # Check 1: Single IP flooding
        ip_flood, ip_details = self._check_ip_flood(ip, current_time, per_ip_threshold)
        if ip_flood:
            return True, 'single_ip_flood', ip_details

        # Check 2: Distributed flood (multiple IPs)
        dist_flood, dist_details = self._check_distributed_flood(current_time, total_threshold)
        if dist_flood:
            return True, 'distributed_flood', dist_details

        # Check 3: Velocity spike (sudden increase)
        velocity_flood, vel_details = self._check_velocity_spike(current_time, velocity_multiplier)
        if velocity_flood:
            return True, 'velocity_spike', vel_details

        # Check 4: Attack type concentration (many same-type attacks)
        if attack_type:
            type_flood, type_details = self._check_attack_type_flood(attack_type, current_time)
            if type_flood:
                return True, 'attack_type_flood', type_details

        return False, None, {}

    def _check_ip_flood(self, ip, current_time, threshold):
        """Check if single IP is flooding"""
        # Count attacks from this IP in last 60 seconds
        recent_attacks = [
            ts for ts in self.attack_windows[ip]
            if current_time - ts <= 60
        ]

        if len(recent_attacks) >= threshold:
            # Calculate attack rate
            attack_rate = len(recent_attacks) / 60.0  # attacks per second

            return True, {
                'ip': ip,
                'attack_count': len(recent_attacks),
                'time_window': '60 seconds',
                'attack_rate': f"{attack_rate:.2f} attacks/sec",
                'threshold': threshold
            }

        return False, {}

    def _check_distributed_flood(self, current_time, threshold):
        """Check for distributed flood from multiple IPs"""
        # Count total attacks in last 60 seconds
        recent_attacks = [
            attack for attack in self.global_attack_window
            if current_time - attack['time'] <= 60
        ]

        if len(recent_attacks) >= threshold:
            # Count unique IPs
            unique_ips = set(attack['ip'] for attack in recent_attacks)

            # Count by attack type
            attack_types = defaultdict(int)
            for attack in recent_attacks:
                attack_types[attack['type']] += 1

            return True, {
                'attack_count': len(recent_attacks),
                'unique_ips': len(unique_ips),
                'time_window': '60 seconds',
                'attack_types': dict(attack_types),
                'threshold': threshold,
                'top_ips': self._get_top_ips(recent_attacks, limit=5)
            }

        return False, {}

    def _check_velocity_spike(self, current_time, multiplier):
        """Check for sudden velocity spike in attack rate"""
        # Update baseline rates if needed (every 5 minutes)
        if current_time - self.baseline_rates['last_updated'] > 300:
            self._update_baseline_rates(current_time)

        # Get current rate (last 60 seconds)
        recent_attacks = [
            attack for attack in self.global_attack_window
            if current_time - attack['time'] <= 60
        ]
        current_rate = len(recent_attacks) / 60.0  # attacks per second

        # Get baseline rate (use 10-minute baseline)
        baseline_rate = self.baseline_rates['last_10min']

        # Check if current rate is significantly higher than baseline
        if baseline_rate > 0 and current_rate >= (baseline_rate * multiplier):
            increase_pct = ((current_rate - baseline_rate) / baseline_rate) * 100

            return True, {
                'current_rate': f"{current_rate:.2f} attacks/sec",
                'baseline_rate': f"{baseline_rate:.2f} attacks/sec",
                'increase_percentage': f"{increase_pct:.1f}%",
                'multiplier': multiplier,
                'attack_count': len(recent_attacks)
            }

        return False, {}

    def _check_attack_type_flood(self, attack_type, current_time):
        """Check if specific attack type is flooding"""
        # Count this attack type in last 60 seconds
        recent_attacks = [
            ts for ts in self.attack_type_windows[attack_type]
            if current_time - ts <= 60
        ]

        # If this type represents >80% of recent attacks, it's a concentrated attack
        total_recent = len([
            attack for attack in self.global_attack_window
            if current_time - attack['time'] <= 60
        ])

        if total_recent > 0:
            type_percentage = (len(recent_attacks) / total_recent) * 100

            if type_percentage >= 80 and len(recent_attacks) >= 20:
                return True, {
                    'attack_type': attack_type,
                    'attack_count': len(recent_attacks),
                    'percentage': f"{type_percentage:.1f}%",
                    'total_attacks': total_recent,
                    'time_window': '60 seconds'
                }

        return False, {}

    def _clean_old_entries(self, current_time):
        """
        Remove entries older than 5 minutes.

        OPTIMIZATION: Uses lazy cleanup with list comprehension for better
        performance. Only removes empty windows to free memory.
        """
        cutoff_time = current_time - WINDOW_5_MINUTES

        # Clean IP-specific windows - remove only empty ones
        empty_ips = [ip for ip, window in self.attack_windows.items()
                     if not window or (window and window[-1] < cutoff_time)]
        for ip in empty_ips:
            del self.attack_windows[ip]

        # Clean global window - trim old entries
        while self.global_attack_window and self.global_attack_window[0]['time'] < cutoff_time:
            self.global_attack_window.popleft()

        # Clean attack type windows - remove only empty ones
        empty_types = [attack_type for attack_type, window in self.attack_type_windows.items()
                       if not window or (window and window[-1] < cutoff_time)]
        for attack_type in empty_types:
            del self.attack_type_windows[attack_type]

    def _update_baseline_rates(self, current_time):
        """Update baseline attack rates"""
        # Calculate attacks in last hour
        hour_ago = current_time - 3600
        attacks_last_hour = [
            attack for attack in self.global_attack_window
            if attack['time'] >= hour_ago
        ]
        self.baseline_rates['last_hour'] = len(attacks_last_hour) / 3600.0  # per second

        # Calculate attacks in last 10 minutes
        ten_min_ago = current_time - 600
        attacks_last_10min = [
            attack for attack in self.global_attack_window
            if attack['time'] >= ten_min_ago
        ]
        self.baseline_rates['last_10min'] = len(attacks_last_10min) / 600.0  # per second

        self.baseline_rates['last_updated'] = current_time

    def _get_top_ips(self, attacks, limit=5):
        """Get top attacking IPs from attack list"""
        ip_counts = defaultdict(int)
        for attack in attacks:
            ip_counts[attack['ip']] += 1

        # Sort by count and return top N
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'ip': ip, 'count': count} for ip, count in sorted_ips[:limit]]

    def get_statistics(self):
        """Get current flood detector statistics"""
        current_time = time.time()

        # OPTIMIZATION: Single pass through global_attack_window instead of 3 passes
        # Filter attacks in last 60 seconds and 5 minutes
        recent_60s = [
            attack for attack in self.global_attack_window
            if current_time - attack['time'] <= 60
        ]
        recent_5min = [
            attack for attack in self.global_attack_window
            if current_time - attack['time'] <= 300
        ]

        # Count unique IPs from the already-filtered 60s list
        unique_ips_60s = len(set(attack['ip'] for attack in recent_60s))

        return {
            'attacks_last_60s': len(recent_60s),
            'attacks_last_5min': len(recent_5min),
            'unique_ips_60s': unique_ips_60s,
            'tracked_ips': len(self.attack_windows),
            'baseline_rate_hour': f"{self.baseline_rates['last_hour']:.4f} attacks/sec",
            'baseline_rate_10min': f"{self.baseline_rates['last_10min']:.4f} attacks/sec"
        }

    def clear_history(self):
        """Clear all tracking history (useful for testing)"""
        self.attack_windows.clear()
        self.global_attack_window.clear()
        self.attack_type_windows.clear()
        self.baseline_rates = {
            'last_hour': 0,
            'last_10min': 0,
            'last_updated': time.time()
        }


# Global flood detector instance
flood_detector = FloodDetector()
