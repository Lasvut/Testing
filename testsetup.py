# test_setup.py
# Run this to test if your WAF monitoring setup is working

import os
import sys

def test_files():
    """Check if all required files exist"""
    print("=" * 50)
    print("CHECKING FILES...")
    print("=" * 50)
    
    required_files = {
        'app.py': 'Main application file',
        'database.py': 'Database functions',
        'middleware.py': 'WAF middleware',
        'rules.py': 'Security rules',
        'templates/login.html': 'Login template',
        'templates/dashboard.html': 'Dashboard template',
        'templates/monitor.html': 'Monitor template',
    }
    
    all_exist = True
    for file, description in required_files.items():
        exists = os.path.exists(file)
        status = "✓" if exists else "✗"
        print(f"{status} {file:30s} - {description}")
        if not exists:
            all_exist = False
    
    return all_exist

def test_database():
    """Check database schema"""
    print("\n" + "=" * 50)
    print("CHECKING DATABASE...")
    print("=" * 50)
    
    try:
        from database import get_connection, init_db
        
        # Initialize database
        init_db()
        print("✓ Database initialized")
        
        # Check tables
        conn = get_connection()
        c = conn.cursor()
        
        # Check users table
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if c.fetchone():
            print("✓ Users table exists")
        else:
            print("✗ Users table missing")
            return False
        
        # Check logs table schema
        c.execute("PRAGMA table_info(logs)")
        columns = [row[1] for row in c.fetchall()]
        required_columns = ['id', 'time', 'ip', 'type', 'payload', 'path', 'user_agent']
        
        missing_columns = [col for col in required_columns if col not in columns]
        if missing_columns:
            print(f"✗ Logs table missing columns: {', '.join(missing_columns)}")
            print("  Solution: Delete app_data.db and run again")
            return False
        else:
            print("✓ Logs table has correct schema")
        
        # Check if user exists
        c.execute("SELECT COUNT(*) as count FROM users")
        user_count = c.fetchone()[0]
        print(f"✓ Found {user_count} user(s)")
        
        if user_count == 0:
            print("  ⚠ Warning: No users found. Run createuser.py")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"✗ Database error: {e}")
        return False

def test_imports():
    """Test if all imports work"""
    print("\n" + "=" * 50)
    print("CHECKING IMPORTS...")
    print("=" * 50)
    
    try:
        import flask
        print("✓ Flask installed")
    except ImportError:
        print("✗ Flask not installed. Run: pip install flask")
        return False
    
    try:
        import werkzeug
        print("✓ Werkzeug installed")
    except ImportError:
        print("✗ Werkzeug not installed. Run: pip install werkzeug")
        return False
    
    try:
        from database import get_attack_stats, get_recent_logs
        print("✓ Database functions imported successfully")
    except ImportError as e:
        print(f"✗ Database import error: {e}")
        return False
    
    try:
        from rules import RULES
        print(f"✓ Security rules imported ({len(RULES)} categories)")
    except ImportError as e:
        print(f"✗ Rules import error: {e}")
        return False
    
    return True

def create_test_data():
    """Create some test attack logs"""
    print("\n" + "=" * 50)
    print("CREATING TEST DATA...")
    print("=" * 50)
    
    try:
        from database import log_attack
        
        test_attacks = [
            ('192.168.1.100', 'SQL Injection', "' OR '1'='1", '/login', 'Mozilla/5.0'),
            ('192.168.1.101', 'Cross-Site Scripting', '<script>alert("xss")</script>', '/search', 'Chrome/90.0'),
            ('192.168.1.102', 'Command Injection', '; cat /etc/passwd', '/api/exec', 'curl/7.68.0'),
            ('192.168.1.100', 'SQL Injection', 'UNION SELECT * FROM users', '/api/data', 'Python-requests'),
            ('192.168.1.103', 'Directory Traversal', '../../../etc/passwd', '/files', 'wget/1.20'),
        ]
        
        for ip, attack_type, payload, path, user_agent in test_attacks:
            log_attack(ip, attack_type, payload, path, user_agent)
        
        print(f"✓ Created {len(test_attacks)} test attack logs")
        return True
        
    except Exception as e:
        print(f"✗ Error creating test data: {e}")
        return False

def test_monitor_route():
    """Test if monitor route is accessible"""
    print("\n" + "=" * 50)
    print("TESTING MONITOR ROUTE...")
    print("=" * 50)
    
    try:
        from app import app
        
        with app.test_client() as client:
            # Test without login (should redirect)
            response = client.get('/monitor')
            if response.status_code in [302, 401]:
                print("✓ Monitor route requires authentication")
            else:
                print(f"✗ Unexpected response: {response.status_code}")
                return False
        
        print("✓ Monitor route is configured")
        return True
        
    except Exception as e:
        print(f"✗ Error testing route: {e}")
        return False

def main():
    print("\n")
    print("╔" + "=" * 48 + "╗")
    print("║  WAF MONITORING SYSTEM - DIAGNOSTIC TEST      ║")
    print("╚" + "=" * 48 + "╝")
    print()
    
    results = []
    
    # Run tests
    results.append(("Files", test_files()))
    results.append(("Imports", test_imports()))
    results.append(("Database", test_database()))
    results.append(("Test Data", create_test_data()))
    results.append(("Routes", test_monitor_route()))
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:10s} - {test_name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ ALL TESTS PASSED!")
        print("\nYou can now:")
        print("1. Run: python app.py")
        print("2. Visit: http://127.0.0.1:5000")
        print("3. Login with: testuser / Test@1234")
        print("4. Click: Security Monitor button")
    else:
        print("✗ SOME TESTS FAILED")
        print("\nPlease fix the issues above and run again.")
    print("=" * 50 + "\n")

if __name__ == '__main__':
    main()