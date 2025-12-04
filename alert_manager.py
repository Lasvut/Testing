"""
Alert Manager Module

Coordinates all alert functionality - flood detection, email, Discord
"""

import time
from datetime import datetime
from collections import defaultdict
from alerts_config import alert_config
from email_sender import email_sender
from discord_sender import discord_sender
from flood_detector import flood_detector


class AlertManager:
    """Manages all alert operations"""

    def __init__(self):
        """Initialize alert manager"""
        self.config = alert_config
        self.email_sender = email_sender
        self.discord_sender = discord_sender
        self.flood_detector = flood_detector

        # Track last alert time for rate limiting
        # Format: {alert_category: last_alert_timestamp}
        self.last_alert_times = {}

        # Track ongoing flood conditions
        self.ongoing_floods = {}  # {flood_key: start_time}

    def process_attack(self, ip, attack_type, payload, path='', user_agent=''):
        """
        Process an attack and check if alerts should be sent

        Args:
            ip: Source IP address
            attack_type: Type of attack
            payload: Attack payload
            path: Request path
            user_agent: User agent string

        Returns:
            bool: True if alert was sent
        """
        # Record attack for flood detection
        self.flood_detector.record_attack(ip, attack_type)

        # Check for flood conditions
        is_flood, flood_type, flood_details = self.flood_detector.check_flood(ip, attack_type)

        if is_flood:
            # Send flood alert (with rate limiting)
            return self._send_flood_alert(ip, attack_type, flood_type, flood_details)

        # Check if this is a critical attack type
        severity = self.config.get_severity(attack_type)
        if severity == 'CRITICAL' and self.config.is_alert_type_enabled('critical_attack'):
            return self._send_critical_attack_alert(ip, attack_type, payload, path)

        return False

    def _send_flood_alert(self, ip, attack_type, flood_type, details):
        """Send flood alert with rate limiting"""
        if not self.config.is_alert_type_enabled('flood'):
            return False

        # Check rate limiting
        flood_key = f"flood_{ip}_{flood_type}"
        if not self._should_send_alert('flood', flood_key):
            # Update ongoing flood tracking
            if flood_key not in self.ongoing_floods:
                self.ongoing_floods[flood_key] = time.time()
            return False

        # Build alert message
        flood_type_names = {
            'single_ip_flood': 'Single IP Attack Flood',
            'distributed_flood': 'Distributed Attack Flood',
            'velocity_spike': 'Sudden Attack Velocity Spike',
            'attack_type_flood': 'Concentrated Attack Type Flood'
        }

        message = f"**{flood_type_names.get(flood_type, 'Attack Flood')}** detected on your WAF system."

        if flood_type == 'single_ip_flood':
            message += f"\n\nA single IP address ({ip}) is flooding your system with attacks."
        elif flood_type == 'distributed_flood':
            message += f"\n\nMultiple IP addresses are coordinating an attack flood."
        elif flood_type == 'velocity_spike':
            message += f"\n\nAttack rate has suddenly spiked significantly above baseline levels."
        elif flood_type == 'attack_type_flood':
            message += f"\n\nConcentrated {attack_type} attacks detected."

        # Add ongoing flood info if applicable
        if flood_key in self.ongoing_floods:
            duration = int(time.time() - self.ongoing_floods[flood_key])
            details['flood_duration'] = f"{duration} seconds"
            message += f"\n\n**Note:** This flood has been ongoing for {duration} seconds."
        else:
            self.ongoing_floods[flood_key] = time.time()

        # Send alerts
        success = self._dispatch_alert('flood', 'CRITICAL', message, details)

        # Update last alert time
        if success:
            self.last_alert_times[flood_key] = time.time()

        return success

    def _send_critical_attack_alert(self, ip, attack_type, payload, path):
        """Send critical attack alert"""
        # Check rate limiting (per IP + attack type)
        alert_key = f"critical_{ip}_{attack_type}"
        if not self._should_send_alert('critical', alert_key):
            return False

        # Build message
        message = f"**Critical {attack_type} attack** detected from IP address {ip}."
        message += "\n\nImmediate investigation recommended."

        details = {
            'ip': ip,
            'attack_type': attack_type,
            'payload': payload[:500],  # Limit payload length
            'path': path
        }

        # Send alerts
        success = self._dispatch_alert('critical_attack', 'CRITICAL', message, details)

        # Update last alert time
        if success:
            self.last_alert_times[alert_key] = time.time()

        return success

    def send_config_change_alert(self, user, action, details):
        """
        Send configuration change alert

        Args:
            user: Username who made the change
            action: Action performed (e.g., "WAF Rule Modified")
            details: Details about the change

        Returns:
            bool: True if alert sent successfully
        """
        if not self.config.is_alert_type_enabled('config_change'):
            return False

        # Check rate limiting
        alert_key = f"config_{action}"
        if not self._should_send_alert('config', alert_key):
            return False

        # Build message
        message = f"**Configuration Change Alert**\n\n"
        message += f"User **{user}** performed action: **{action}**"

        alert_details = {
            'user': user,
            'action': action,
            'change_details': details,
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        }

        # Send alerts
        success = self._dispatch_alert('config_change', 'WARNING', message, alert_details)

        # Update last alert time
        if success:
            self.last_alert_times[alert_key] = time.time()

        return success

    def send_system_health_alert(self, component, error, severity='WARNING'):
        """
        Send system health alert

        Args:
            component: System component with issue (e.g., "ML Model", "Database")
            error: Error description
            severity: Severity level

        Returns:
            bool: True if alert sent successfully
        """
        if not self.config.is_alert_type_enabled('system_health'):
            return False

        # Check rate limiting
        alert_key = f"system_{component}"
        if not self._should_send_alert('system', alert_key):
            return False

        # Build message
        message = f"**System Health Alert**\n\n"
        message += f"Component **{component}** is experiencing issues."

        alert_details = {
            'component': component,
            'error': str(error),
            'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        }

        # Send alerts
        success = self._dispatch_alert('system_health', severity, message, alert_details)

        # Update last alert time
        if success:
            self.last_alert_times[alert_key] = time.time()

        return success

    def _dispatch_alert(self, alert_type, severity, message, details):
        """
        Dispatch alert to all enabled channels

        Args:
            alert_type: Type of alert
            severity: Severity level
            message: Alert message
            details: Additional details

        Returns:
            bool: True if at least one alert was sent
        """
        sent_count = 0

        # Send email alert
        if self.config.is_email_enabled():
            success, error = self.email_sender.send_alert(alert_type, severity, message, details)
            if success:
                sent_count += 1
            elif error:
                print(f"[Alert Manager] Email failed: {error}")

        # Send Discord alert
        if self.config.is_discord_enabled():
            success, error = self.discord_sender.send_alert(alert_type, severity, message, details)
            if success:
                sent_count += 1
            elif error:
                print(f"[Alert Manager] Discord failed: {error}")

        if sent_count > 0:
            print(f"[Alert Manager] Sent {alert_type} alert via {sent_count} channel(s)")
            # Log to database (will be implemented when we update database schema)
            self._log_alert_to_db(alert_type, severity, message, details, 'sent')
            return True
        else:
            print(f"[Alert Manager] Failed to send {alert_type} alert")
            self._log_alert_to_db(alert_type, severity, message, details, 'failed')
            return False

    def _should_send_alert(self, category, alert_key):
        """
        Check if alert should be sent based on rate limiting

        Args:
            category: Alert category (flood, critical, config, system)
            alert_key: Unique key for this specific alert

        Returns:
            bool: True if alert should be sent
        """
        cooldown = self.config.get_cooldown(category)
        last_time = self.last_alert_times.get(alert_key, 0)
        current_time = time.time()

        if current_time - last_time >= cooldown:
            return True

        # Alert is still in cooldown period
        remaining = int(cooldown - (current_time - last_time))
        print(f"[Alert Manager] Alert '{alert_key}' in cooldown ({remaining}s remaining)")
        return False

    def _log_alert_to_db(self, alert_type, severity, message, details, status):
        """
        Log alert to database

        Args:
            alert_type: Type of alert
            severity: Severity level
            message: Alert message
            details: Additional details
            status: Alert status (sent, failed, rate_limited)
        """
        try:
            from database import get_connection
            import json

            conn = get_connection()
            cursor = conn.cursor()

            # Get recipients
            recipients = []
            if self.config.is_email_enabled():
                recipients.extend(self.config.get('email_recipients', []))
            if self.config.is_discord_enabled():
                recipients.append('Discord Webhook')

            cursor.execute("""
                INSERT INTO alert_history (timestamp, alert_type, severity, message, recipients, status, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                alert_type,
                severity,
                message,
                ', '.join(recipients),
                status,
                json.dumps(details) if details else '{}'
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"[Alert Manager] Failed to log alert to database: {e}")

    def cleanup_ongoing_floods(self):
        """Clean up old ongoing flood entries"""
        current_time = time.time()
        # Remove floods older than 10 minutes
        self.ongoing_floods = {
            key: start_time
            for key, start_time in self.ongoing_floods.items()
            if current_time - start_time < 600
        }

    def get_statistics(self):
        """Get alert manager statistics"""
        return {
            'flood_detector': self.flood_detector.get_statistics(),
            'ongoing_floods': len(self.ongoing_floods),
            'email_enabled': self.config.is_email_enabled(),
            'discord_enabled': self.config.is_discord_enabled(),
            'active_cooldowns': len(self.last_alert_times)
        }

    def test_alerts(self):
        """
        Test all enabled alert channels

        Returns:
            dict: Test results for each channel
        """
        results = {}

        # Test email
        if self.config.is_email_enabled():
            success, error = self.email_sender.test_connection()
            results['email'] = {
                'enabled': True,
                'success': success,
                'message': error if not success else 'Connection successful'
            }
        else:
            results['email'] = {
                'enabled': False,
                'success': False,
                'message': 'Email alerts not enabled or not configured'
            }

        # Test Discord
        if self.config.is_discord_enabled():
            success, error = self.discord_sender.test_connection()
            results['discord'] = {
                'enabled': True,
                'success': success,
                'message': error if not success else 'Test message sent successfully'
            }
        else:
            results['discord'] = {
                'enabled': False,
                'success': False,
                'message': 'Discord alerts not enabled or not configured'
            }

        return results


# Global alert manager instance
alert_manager = AlertManager()
