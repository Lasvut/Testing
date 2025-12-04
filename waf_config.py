"""
WAF Configuration Module

Manages WAF global settings including master toggle, detection layers, and modes
"""

import json
import os
from datetime import datetime


class WAFConfig:
    """Centralized WAF configuration management"""

    DEFAULT_CONFIG = {
        # Master Toggle
        "waf_enabled": True,
        "last_toggled_by": None,
        "last_toggled_at": None,

        # Detection Layers
        "pattern_detection_enabled": True,
        "anomaly_detection_enabled": True,

        # Detection Mode
        "detection_mode": "blocking",  # blocking, monitoring, learning

        # Rate Limiting
        "rate_limiting_enabled": True,
        "rate_limit_per_ip": 100,  # requests per minute
        "rate_limit_global": 1000,  # requests per minute globally
        "rate_limit_burst": 20,  # burst allowance

        # Path-specific rate limits
        "path_rate_limits": {
            "/login": 5,  # 5 requests/minute
            "/api/*": 100,  # 100 requests/minute
        },

        # Response configuration
        "block_response_message": "⚠️ Request blocked: suspicious activity detected.",
        "rate_limit_response_message": "⚠️ Rate limit exceeded. Please slow down.",

        # Logging
        "log_all_requests": False,  # Log everything (performance impact)
        "log_blocked_only": True,   # Log only blocked requests

        # Performance
        "skip_static_files": True,  # Skip WAF for .css, .js, .jpg, etc.

        # Status
        "total_requests_processed": 0,
        "total_attacks_blocked": 0,
        "waf_start_time": None
    }

    def __init__(self, config_file='waf_config.json'):
        """Initialize WAF configuration"""
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults to ensure all keys exist
                return {**self.DEFAULT_CONFIG, **config}
            except Exception as e:
                print(f"[WAF Config] Error loading config: {e}, using defaults")
                return self.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            config = self.DEFAULT_CONFIG.copy()
            config['waf_start_time'] = datetime.utcnow().isoformat()
            self.save_config(config)
            return config

    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config

        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"[WAF Config] Error saving config: {e}")
            return False

    def get(self, key, default=None):
        """Get configuration value"""
        return self.config.get(key, default)

    def set(self, key, value):
        """Set configuration value"""
        self.config[key] = value
        return self.save_config()

    def update(self, updates):
        """Update multiple configuration values"""
        self.config.update(updates)
        return self.save_config()

    def is_waf_enabled(self):
        """Check if WAF is globally enabled"""
        return self.config.get('waf_enabled', True)

    def is_pattern_detection_enabled(self):
        """Check if pattern-based detection is enabled"""
        return self.config.get('pattern_detection_enabled', True)

    def is_anomaly_detection_enabled(self):
        """Check if anomaly detection is enabled"""
        return self.config.get('anomaly_detection_enabled', True)

    def is_rate_limiting_enabled(self):
        """Check if rate limiting is enabled"""
        return self.config.get('rate_limiting_enabled', True)

    def get_detection_mode(self):
        """Get current detection mode"""
        return self.config.get('detection_mode', 'blocking')

    def toggle_waf(self, enabled, username=None):
        """
        Toggle WAF on/off

        Args:
            enabled: True to enable, False to disable
            username: User who toggled the WAF

        Returns:
            bool: Success status
        """
        self.config['waf_enabled'] = enabled
        self.config['last_toggled_by'] = username
        self.config['last_toggled_at'] = datetime.utcnow().isoformat()

        # Log the toggle action
        status = "enabled" if enabled else "disabled"
        print(f"[WAF Config] WAF {status} by {username} at {self.config['last_toggled_at']}")

        return self.save_config()

    def get_rate_limit(self, path=None):
        """
        Get rate limit for specific path or default

        Args:
            path: Request path (optional)

        Returns:
            int: Rate limit (requests per minute)
        """
        if not path:
            return self.config.get('rate_limit_per_ip', 100)

        # Check path-specific limits
        path_limits = self.config.get('path_rate_limits', {})

        # Exact match
        if path in path_limits:
            return path_limits[path]

        # Wildcard match
        for pattern, limit in path_limits.items():
            if '*' in pattern:
                prefix = pattern.replace('*', '')
                if path.startswith(prefix):
                    return limit

        # Default
        return self.config.get('rate_limit_per_ip', 100)

    def increment_stats(self, requests=0, attacks=0):
        """
        Increment WAF statistics

        Args:
            requests: Number of requests to add
            attacks: Number of attacks blocked to add
        """
        self.config['total_requests_processed'] = self.config.get('total_requests_processed', 0) + requests
        self.config['total_attacks_blocked'] = self.config.get('total_attacks_blocked', 0) + attacks
        self.save_config()

    def get_statistics(self):
        """Get WAF statistics"""
        return {
            'waf_enabled': self.config.get('waf_enabled', True),
            'detection_mode': self.config.get('detection_mode', 'blocking'),
            'total_requests': self.config.get('total_requests_processed', 0),
            'total_attacks_blocked': self.config.get('total_attacks_blocked', 0),
            'pattern_detection': self.config.get('pattern_detection_enabled', True),
            'anomaly_detection': self.config.get('anomaly_detection_enabled', True),
            'rate_limiting': self.config.get('rate_limiting_enabled', True),
            'uptime_since': self.config.get('waf_start_time'),
            'last_toggled_by': self.config.get('last_toggled_by'),
            'last_toggled_at': self.config.get('last_toggled_at')
        }

    def to_dict(self):
        """Export configuration as dictionary"""
        return self.config.copy()

    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self.config = self.DEFAULT_CONFIG.copy()
        self.config['waf_start_time'] = datetime.utcnow().isoformat()
        return self.save_config()


# Global WAF configuration instance
waf_config = WAFConfig()
