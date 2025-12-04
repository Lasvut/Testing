"""
Discord Webhook Alert Sender Module

Handles sending alerts to Discord via webhooks
"""

import requests
import json
from datetime import datetime
from alerts_config import alert_config


class DiscordSender:
    """Handles Discord webhook alert delivery"""

    def __init__(self):
        """Initialize Discord sender"""
        self.config = alert_config

    def send_alert(self, alert_type, severity, message, details=None):
        """
        Send Discord webhook alert

        Args:
            alert_type: Type of alert (flood, critical_attack, config_change, etc.)
            severity: Severity level (INFO, WARNING, CRITICAL)
            message: Alert message/summary
            details: Dictionary with additional details

        Returns:
            tuple: (success: bool, error_message: str or None)
        """
        if not self.config.is_discord_enabled():
            return False, "Discord alerts not enabled or not configured"

        try:
            webhook_url = self.config.get('discord_webhook_url')

            # Build Discord embed
            embed = self._build_embed(alert_type, severity, message, details)

            # Send webhook
            payload = {
                "username": "WAF Alert System",
                "avatar_url": "https://cdn-icons-png.flaticon.com/512/2913/2913133.png",
                "embeds": [embed]
            }

            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 204:
                print(f"[Discord Alert] Sent {alert_type} alert successfully")
                return True, None
            else:
                error = f"Discord webhook returned status {response.status_code}"
                print(f"[Discord Alert] Error: {error}")
                return False, error

        except requests.exceptions.Timeout:
            error = "Discord webhook request timed out"
            print(f"[Discord Alert] Error: {error}")
            return False, error

        except requests.exceptions.RequestException as e:
            error = f"Discord webhook request failed: {str(e)}"
            print(f"[Discord Alert] Error: {error}")
            return False, error

        except Exception as e:
            error = f"Failed to send Discord alert: {str(e)}"
            print(f"[Discord Alert] Error: {error}")
            return False, error

    def _build_embed(self, alert_type, severity, message, details):
        """Build Discord embed object"""
        # Color mapping for severity levels
        color_map = {
            'CRITICAL': 15158332,  # Red
            'WARNING': 16776960,   # Yellow
            'INFO': 3447003        # Blue
        }
        color = color_map.get(severity, 9807270)  # Default gray

        # Emoji mapping
        emoji_map = {
            'CRITICAL': '🚨',
            'WARNING': '⚠️',
            'INFO': 'ℹ️'
        }
        emoji = emoji_map.get(severity, '📢')

        # Type name mapping
        type_names = {
            'flood': 'Attack Flood Detected',
            'critical_attack': 'Critical Attack',
            'config_change': 'Configuration Change',
            'system_health': 'System Health Alert'
        }
        title = f"{emoji} {type_names.get(alert_type, 'WAF Alert')}"

        # Build fields
        fields = [
            {
                "name": "Alert Type",
                "value": alert_type.replace('_', ' ').title(),
                "inline": True
            },
            {
                "name": "Severity",
                "value": f"**{severity}**",
                "inline": True
            },
            {
                "name": "Timestamp",
                "value": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                "inline": False
            }
        ]

        # Add detail fields
        if details:
            if 'ip' in details:
                fields.append({
                    "name": "Source IP",
                    "value": f"`{details['ip']}`",
                    "inline": True
                })

            if 'attack_count' in details:
                fields.append({
                    "name": "Attack Count",
                    "value": str(details['attack_count']),
                    "inline": True
                })

            if 'time_window' in details:
                fields.append({
                    "name": "Time Window",
                    "value": details['time_window'],
                    "inline": True
                })

            if 'attack_types' in details:
                attack_breakdown = '\n'.join([
                    f"• **{attack_type}**: {count} attacks"
                    for attack_type, count in details['attack_types'].items()
                ])
                fields.append({
                    "name": "Attack Breakdown",
                    "value": attack_breakdown,
                    "inline": False
                })

            if 'user' in details:
                fields.append({
                    "name": "Modified By",
                    "value": f"`{details['user']}`",
                    "inline": True
                })

            if 'change_details' in details:
                fields.append({
                    "name": "Change Details",
                    "value": details['change_details'][:1024],  # Discord limit
                    "inline": False
                })

            if 'error' in details:
                fields.append({
                    "name": "Error",
                    "value": f"```{details['error'][:1000]}```",  # Code block, limited length
                    "inline": False
                })

        # Add recommended actions based on alert type
        if alert_type == 'flood':
            actions = (
                "• Review attack logs in dashboard\n"
                "• Verify if legitimate traffic spike\n"
                "• Consider IP-based rate limiting\n"
                "• Review firewall rules"
            )
        elif alert_type == 'critical_attack':
            actions = (
                "• Investigate attack source immediately\n"
                "• Review application logs\n"
                "• Check system integrity\n"
                "• Consider blocking source IP"
            )
        elif alert_type == 'config_change':
            actions = (
                "• Verify change was authorized\n"
                "• Review configuration changes\n"
                "• Test WAF functionality\n"
                "• Document for audit trail"
            )
        elif alert_type == 'system_health':
            actions = (
                "• Check system logs\n"
                "• Verify WAF services running\n"
                "• Monitor system resources\n"
                "• Contact administrator if needed"
            )
        else:
            actions = "• Review the alert details above"

        fields.append({
            "name": "Recommended Actions",
            "value": actions,
            "inline": False
        })

        # Build embed
        embed = {
            "title": title,
            "description": message,
            "color": color,
            "fields": fields,
            "footer": {
                "text": "WAF Alert System",
                "icon_url": "https://cdn-icons-png.flaticon.com/512/2913/2913133.png"
            },
            "timestamp": datetime.utcnow().isoformat()
        }

        return embed

    def test_connection(self):
        """Test Discord webhook configuration"""
        try:
            webhook_url = self.config.get('discord_webhook_url')

            if not webhook_url:
                return False, "Discord webhook URL not configured"

            # Send test message
            payload = {
                "username": "WAF Alert System",
                "embeds": [{
                    "title": "✅ Test Alert",
                    "description": "This is a test alert to verify Discord webhook connectivity.",
                    "color": 3066993,  # Green
                    "fields": [
                        {
                            "name": "Status",
                            "value": "Connection successful",
                            "inline": True
                        },
                        {
                            "name": "Timestamp",
                            "value": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                            "inline": True
                        }
                    ],
                    "footer": {
                        "text": "WAF Alert System - Test"
                    }
                }]
            }

            response = requests.post(webhook_url, json=payload, timeout=10)

            if response.status_code == 204:
                return True, "Discord webhook test successful"
            else:
                return False, f"Discord webhook returned status {response.status_code}"

        except requests.exceptions.Timeout:
            return False, "Discord webhook request timed out"
        except requests.exceptions.RequestException as e:
            return False, f"Discord webhook request failed: {str(e)}"
        except Exception as e:
            return False, f"Test failed: {str(e)}"


# Global Discord sender instance
discord_sender = DiscordSender()
