"""
Email Alert Sender Module

Handles sending email alerts via SMTP
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from alerts_config import alert_config
from constants import (
    ALERT_SEVERITY_EMOJI,
    ALERT_TYPE_NAMES,
    ALERT_SEVERITY_COLORS_HTML
)


class EmailSender:
    """Handles email alert delivery"""

    def __init__(self):
        """Initialize email sender"""
        self.config = alert_config

    def send_alert(self, alert_type, severity, message, details=None):
        """
        Send email alert

        Args:
            alert_type: Type of alert (flood, critical_attack, config_change, etc.)
            severity: Severity level (INFO, WARNING, CRITICAL)
            message: Alert message/summary
            details: Dictionary with additional details

        Returns:
            tuple: (success: bool, error_message: str or None)
        """
        if not self.config.is_email_enabled():
            return False, "Email alerts not enabled or not configured"

        try:
            # Get email configuration
            smtp_server = self.config.get('smtp_server')
            smtp_port = self.config.get('smtp_port')
            smtp_username = self.config.get('smtp_username')
            smtp_password = self.config.get('smtp_password')
            email_from = self.config.get('email_from') or smtp_username
            recipients = self.config.get('email_recipients', [])

            # Build email content
            subject = self._build_subject(alert_type, severity)
            body = self._build_body(alert_type, severity, message, details)

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = email_from
            msg['To'] = ', '.join(recipients)
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

            # Attach plain text and HTML versions
            text_part = MIMEText(body, 'plain')
            html_part = MIMEText(self._build_html_body(alert_type, severity, message, details), 'html')
            msg.attach(text_part)
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)

            print(f"[Email Alert] Sent {alert_type} alert to {len(recipients)} recipients")
            return True, None

        except smtplib.SMTPAuthenticationError:
            error = "SMTP authentication failed - check username/password"
            print(f"[Email Alert] Error: {error}")
            return False, error

        except smtplib.SMTPException as e:
            error = f"SMTP error: {str(e)}"
            print(f"[Email Alert] Error: {error}")
            return False, error

        except Exception as e:
            error = f"Failed to send email: {str(e)}"
            print(f"[Email Alert] Error: {error}")
            return False, error

    def _build_subject(self, alert_type, severity):
        """Build email subject line"""
        emoji = ALERT_SEVERITY_EMOJI.get(severity, '📧')
        type_name = ALERT_TYPE_NAMES.get(alert_type, 'WAF Alert')
        return f"{emoji} WAF Alert - {type_name} [{severity}]"

    def _build_body(self, alert_type, severity, message, details):
        """Build plain text email body"""
        lines = [
            "=" * 70,
            "WAF ALERT NOTIFICATION",
            "=" * 70,
            "",
            f"Alert Type:  {alert_type.replace('_', ' ').title()}",
            f"Severity:    {severity}",
            f"Timestamp:   {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "",
            "ALERT MESSAGE",
            "-" * 70,
            message,
            ""
        ]

        # Add details if provided
        if details:
            lines.append("DETAILS")
            lines.append("-" * 70)

            if 'ip' in details:
                lines.append(f"Source IP:        {details['ip']}")

            if 'attack_count' in details:
                lines.append(f"Attack Count:     {details['attack_count']}")

            if 'time_window' in details:
                lines.append(f"Time Window:      {details['time_window']}")

            if 'attack_types' in details:
                lines.append(f"\nAttack Breakdown:")
                for attack_type, count in details['attack_types'].items():
                    lines.append(f"  - {attack_type}: {count} attacks")

            if 'user' in details:
                lines.append(f"Modified By:      {details['user']}")

            if 'change_details' in details:
                lines.append(f"\nChange Details:")
                lines.append(f"  {details['change_details']}")

            if 'error' in details:
                lines.append(f"\nError Details:")
                lines.append(f"  {details['error']}")

            lines.append("")

        # Add action recommendations
        lines.extend([
            "RECOMMENDED ACTIONS",
            "-" * 70,
        ])

        if alert_type == 'flood':
            lines.extend([
                "1. Review attack logs in the WAF dashboard",
                "2. Check if this is a legitimate traffic spike",
                "3. Consider implementing IP-based rate limiting",
                "4. Review firewall rules to block malicious IPs"
            ])
        elif alert_type == 'critical_attack':
            lines.extend([
                "1. Investigate the attack source immediately",
                "2. Review application logs for any successful exploitation",
                "3. Check system integrity and sensitive data",
                "4. Consider blocking the source IP if confirmed malicious"
            ])
        elif alert_type == 'config_change':
            lines.extend([
                "1. Verify this change was authorized",
                "2. Review the configuration changes made",
                "3. Test WAF functionality after changes",
                "4. Document the change for audit purposes"
            ])
        elif alert_type == 'system_health':
            lines.extend([
                "1. Check system logs for detailed error information",
                "2. Verify WAF services are running properly",
                "3. Monitor system resources (CPU, memory, disk)",
                "4. Contact system administrator if issue persists"
            ])

        lines.extend([
            "",
            "-" * 70,
            "Dashboard: http://localhost:5000/monitor",
            "Alert Config: http://localhost:5000/alerts",
            "",
            "This is an automated alert from your WAF system.",
            "=" * 70
        ])

        return '\n'.join(lines)

    def _build_html_body(self, alert_type, severity, message, details):
        """Build HTML email body"""
        # Severity color mapping
        color = ALERT_SEVERITY_COLORS_HTML.get(severity, '#6c757d')

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
                .content {{ background-color: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; }}
                .section {{ margin-bottom: 20px; }}
                .section-title {{ font-weight: bold; color: {color}; border-bottom: 2px solid {color}; padding-bottom: 5px; margin-bottom: 10px; }}
                .detail-row {{ padding: 5px 0; }}
                .detail-label {{ font-weight: bold; display: inline-block; width: 150px; }}
                .footer {{ background-color: #343a40; color: white; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; font-size: 12px; }}
                .btn {{ display: inline-block; padding: 10px 20px; margin: 5px; background-color: {color}; color: white; text-decoration: none; border-radius: 5px; }}
                ul {{ margin: 10px 0; padding-left: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>WAF Alert Notification</h1>
                    <h2>{alert_type.replace('_', ' ').title()}</h2>
                </div>
                <div class="content">
                    <div class="section">
                        <div class="detail-row">
                            <span class="detail-label">Severity:</span>
                            <strong style="color: {color};">{severity}</strong>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Timestamp:</span>
                            {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC
                        </div>
                    </div>

                    <div class="section">
                        <div class="section-title">Alert Message</div>
                        <p>{message}</p>
                    </div>
        """

        # Add details section
        if details:
            html += '<div class="section"><div class="section-title">Details</div>'

            if 'ip' in details:
                html += f'<div class="detail-row"><span class="detail-label">Source IP:</span> {details["ip"]}</div>'

            if 'attack_count' in details:
                html += f'<div class="detail-row"><span class="detail-label">Attack Count:</span> {details["attack_count"]}</div>'

            if 'time_window' in details:
                html += f'<div class="detail-row"><span class="detail-label">Time Window:</span> {details["time_window"]}</div>'

            if 'attack_types' in details:
                html += '<div class="detail-row"><span class="detail-label">Attack Breakdown:</span></div><ul>'
                for attack_type, count in details['attack_types'].items():
                    html += f'<li>{attack_type}: {count} attacks</li>'
                html += '</ul>'

            if 'user' in details:
                html += f'<div class="detail-row"><span class="detail-label">Modified By:</span> {details["user"]}</div>'

            if 'change_details' in details:
                html += f'<div class="detail-row"><span class="detail-label">Changes:</span> {details["change_details"]}</div>'

            html += '</div>'

        # Add action buttons
        html += """
                    <div class="section">
                        <div class="section-title">Quick Actions</div>
                        <a href="http://localhost:5000/monitor" class="btn">View Dashboard</a>
                        <a href="http://localhost:5000/alerts" class="btn">Alert Settings</a>
                    </div>
                </div>
                <div class="footer">
                    <p>This is an automated alert from your WAF Alert System</p>
                    <p>&copy; 2025 WAF Security System</p>
                </div>
            </div>
        </body>
        </html>
        """

        return html

    def test_connection(self):
        """Test email configuration and connectivity"""
        try:
            smtp_server = self.config.get('smtp_server')
            smtp_port = self.config.get('smtp_port')
            smtp_username = self.config.get('smtp_username')
            smtp_password = self.config.get('smtp_password')

            with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)

            return True, "Email connection successful"

        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed - check username/password"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"


# Global email sender instance
email_sender = EmailSender()
