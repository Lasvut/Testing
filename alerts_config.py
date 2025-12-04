"""
Alert Configuration Module

Manages alert settings for email and Discord notifications
"""

import json
import os

class AlertConfig:
    """Centralized alert configuration management"""

    # Default configuration
    DEFAULT_CONFIG = {
        # Email settings
        "email_enabled": False,
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "smtp_username": "",
        "smtp_password": "",
        "email_recipients": [],  # List of email addresses
        "email_from": "",

        # Discord settings
        "discord_enabled": False,
        "discord_webhook_url": "",

        # Flood detection thresholds
        "flood_threshold_per_ip": 10,  # Attacks per minute from single IP
        "flood_threshold_total": 50,   # Total attacks per minute
        "flood_velocity_multiplier": 3.0,  # 300% increase = flood

        # Alert rate limiting (seconds)
        "alert_cooldown_flood": 300,      # 5 minutes
        "alert_cooldown_critical": 120,   # 2 minutes
        "alert_cooldown_config": 60,      # 1 minute
        "alert_cooldown_system": 300,     # 5 minutes

        # Alert types enabled
        "alert_types": {
            "flood": True,
            "critical_attack": True,
            "config_change": True,
            "system_health": True
        },

        # Severity levels for different attack types
        "severity_mapping": {
            "SQL Injection": "CRITICAL",
            "Command Injection": "CRITICAL",
            "XSS": "WARNING",
            "Directory Traversal": "WARNING",
            "File Inclusion": "CRITICAL",
            "Anomalous Behavior": "WARNING"
        }
    }

    def __init__(self, config_file='alert_config.json'):
        """Initialize alert configuration"""
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
                print(f"[Alert Config] Error loading config: {e}, using defaults")
                return self.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()

    def save_config(self, config=None):
        """Save configuration to file"""
        if config is None:
            config = self.config

        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"[Alert Config] Error saving config: {e}")
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

    def is_email_enabled(self):
        """Check if email alerts are enabled"""
        return (self.config.get('email_enabled', False) and
                self.config.get('smtp_username') and
                self.config.get('smtp_password') and
                len(self.config.get('email_recipients', [])) > 0)

    def is_discord_enabled(self):
        """Check if Discord alerts are enabled"""
        return (self.config.get('discord_enabled', False) and
                self.config.get('discord_webhook_url'))

    def is_alert_type_enabled(self, alert_type):
        """Check if specific alert type is enabled"""
        alert_types = self.config.get('alert_types', {})
        return alert_types.get(alert_type, False)

    def get_severity(self, attack_type):
        """Get severity level for attack type"""
        severity_mapping = self.config.get('severity_mapping', {})
        return severity_mapping.get(attack_type, 'WARNING')

    def get_cooldown(self, alert_category):
        """Get cooldown period for alert category"""
        key = f'alert_cooldown_{alert_category}'
        return self.config.get(key, 300)  # Default 5 minutes

    def to_dict(self):
        """Export configuration as dictionary (without sensitive data for API)"""
        safe_config = self.config.copy()
        # Remove sensitive fields
        safe_config['smtp_password'] = '***' if safe_config.get('smtp_password') else ''
        return safe_config

    def validate_email_config(self):
        """Validate email configuration"""
        required_fields = ['smtp_server', 'smtp_port', 'smtp_username',
                          'smtp_password', 'email_recipients', 'email_from']

        for field in required_fields:
            value = self.config.get(field)
            if not value:
                return False, f"Missing required field: {field}"

            if field == 'email_recipients' and len(value) == 0:
                return False, "At least one email recipient required"

        return True, "Email configuration valid"

    def validate_discord_config(self):
        """Validate Discord configuration"""
        webhook_url = self.config.get('discord_webhook_url', '')

        if not webhook_url:
            return False, "Discord webhook URL is required"

        if not webhook_url.startswith('https://discord.com/api/webhooks/'):
            return False, "Invalid Discord webhook URL format"

        return True, "Discord configuration valid"


# Global configuration instance
alert_config = AlertConfig()
