#!/usr/bin/env python3
"""
WAF Penetration Testing Script
Tests the WAF against OWASP Top 10 attack vectors
"""

import requests
import time
from urllib.parse import quote

# ANSI colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color

TARGET = "http://localhost:5000"
RESULTS = {
    'total': 0,
    'blocked': 0,
    'passed': 0,
    'errors': 0
}

def test_attack(category, name, payload, path="/search"):
    """Test a single attack payload"""
    global RESULTS
    RESULTS['total'] += 1

    url = f"{TARGET}{path}?q={quote(payload)}"

    print(f"{BLUE}[Test {RESULTS['total']}]{NC} {category} - {name}")
    print(f"  Payload: {payload[:60]}...")

    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 403:
            print(f"  {RED}✓ BLOCKED{NC} (HTTP 403) - WAF Working!")
            RESULTS['blocked'] += 1
            return True
        elif response.status_code == 200:
            print(f"  {GREEN}✗ PASSED{NC} (HTTP 200) - Potential Vulnerability!")
            RESULTS['passed'] += 1
            return False
        else:
            print(f"  {YELLOW}? UNKNOWN{NC} (HTTP {response.status_code})")
            RESULTS['errors'] += 1
            return None
    except requests.exceptions.RequestException as e:
        print(f"  {YELLOW}✗ ERROR{NC}: {str(e)}")
        RESULTS['errors'] += 1
        return None

def main():
    print("=" * 70)
    print(f"{BLUE}WAF Penetration Testing - OWASP Top 10{NC}")
    print(f"Target: {TARGET}")
    print("=" * 70)
    print()

    # Check if WAF is running
    try:
        response = requests.get(TARGET, timeout=5)
        print(f"{GREEN}✓ WAF is running{NC}")
        print()
    except:
        print(f"{RED}✗ WAF is not running!{NC}")
        print(f"Start it with: python3 app.py")
        return

    # SQL Injection Tests
    print(f"\n{YELLOW}=== SQL Injection Tests ==={NC}")
    test_attack("SQL", "UNION SELECT", "test' UNION SELECT 1,2,3--")
    test_attack("SQL", "OR 1=1", "admin' OR '1'='1")
    test_attack("SQL", "DROP TABLE", "test'; DROP TABLE users--")
    test_attack("SQL", "Time-based blind", "test' AND SLEEP(5)--")
    test_attack("SQL", "Boolean-based blind", "test' AND 1=1--")
    test_attack("SQL", "Stacked queries", "test'; SELECT * FROM users--")

    # XSS Tests
    print(f"\n{YELLOW}=== Cross-Site Scripting (XSS) Tests ==={NC}")
    test_attack("XSS", "Script tag", "<script>alert(1)</script>")
    test_attack("XSS", "IMG onerror", "<img src=x onerror=alert(1)>")
    test_attack("XSS", "SVG onload", "<svg/onload=alert('XSS')>")
    test_attack("XSS", "Event handler", "<body onload=alert(1)>")
    test_attack("XSS", "JavaScript protocol", "<a href='javascript:alert(1)'>Click</a>")
    test_attack("XSS", "Data URI", "<iframe src='data:text/html,<script>alert(1)</script>'>")

    # Command Injection Tests
    print(f"\n{YELLOW}=== Command Injection Tests ==={NC}")
    test_attack("CMD", "Semicolon separator", "test;ls -la")
    test_attack("CMD", "Pipe operator", "test|whoami")
    test_attack("CMD", "Backticks", "test`id`")
    test_attack("CMD", "Dollar substitution", "test$(whoami)")
    test_attack("CMD", "AND operator", "test && cat /etc/passwd")

    # Path Traversal Tests
    print(f"\n{YELLOW}=== Path Traversal Tests ==={NC}")
    test_attack("Path", "Dot-dot-slash", "../../../../etc/passwd")
    test_attack("Path", "URL encoded", "..%2F..%2F..%2Fetc%2Fpasswd")
    test_attack("Path", "Windows path", "..\\..\\..\\windows\\system32\\config\\sam")
    test_attack("Path", "Null byte", "../../../../etc/passwd%00")

    # LDAP Injection Tests
    print(f"\n{YELLOW}=== LDAP Injection Tests ==={NC}")
    test_attack("LDAP", "OR filter bypass", "admin*)(&(password=*))")
    test_attack("LDAP", "Wildcard injection", "*)(uid=*")

    # XML/XXE Tests
    print(f"\n{YELLOW}=== XML Injection Tests ==={NC}")
    test_attack("XML", "External entity", "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>")

    # SSTI Tests
    print(f"\n{YELLOW}=== Server-Side Template Injection Tests ==={NC}")
    test_attack("SSTI", "Jinja2 injection", "{{7*7}}")
    test_attack("SSTI", "Variable access", "{{config}}")
    test_attack("SSTI", "RCE attempt", "{{''.__class__.__mro__[1].__subclasses__()}}")

    # Rate Limiting Test
    print(f"\n{YELLOW}=== Rate Limiting Test ==={NC}")
    print("Testing rapid requests (should trigger rate limiting)...")
    for i in range(20):
        try:
            response = requests.get(f"{TARGET}/search?q=test{i}", timeout=2)
            if response.status_code == 429:
                print(f"{RED}✓ Rate limit triggered at request {i+1}{NC}")
                RESULTS['blocked'] += 1
                break
        except:
            pass
        time.sleep(0.1)

    # Print summary
    print("\n" + "=" * 70)
    print(f"{BLUE}Test Results Summary{NC}")
    print("=" * 70)
    print(f"Total Tests:        {RESULTS['total']}")
    print(f"{RED}Blocked by WAF:     {RESULTS['blocked']}{NC}")
    print(f"{GREEN}Passed (Vulnerable): {RESULTS['passed']}{NC}")
    print(f"{YELLOW}Errors:             {RESULTS['errors']}{NC}")
    print()

    # Calculate effectiveness
    if RESULTS['total'] > 0:
        effectiveness = (RESULTS['blocked'] / RESULTS['total']) * 100
        print(f"WAF Effectiveness: {effectiveness:.1f}%")
        print()

        if effectiveness >= 90:
            print(f"{GREEN}✓ EXCELLENT - WAF is highly effective!{NC}")
        elif effectiveness >= 70:
            print(f"{YELLOW}⚠ GOOD - WAF is working but can be improved{NC}")
        else:
            print(f"{RED}✗ POOR - WAF needs significant improvement{NC}")

    print()
    print(f"View detailed logs at: {TARGET}/dashboard")
    print("=" * 70)

if __name__ == "__main__":
    main()
