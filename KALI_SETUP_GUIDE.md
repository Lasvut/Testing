# WAF Setup Guide for Kali Linux

Complete guide to deploy your Web Application Firewall on Kali Linux.

---

## 🚀 Quick Setup (5 Minutes)

### Step 1: Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Dependencies
```bash
# Install Python and pip
sudo apt install python3 python3-pip git -y

# Install required Python packages
pip3 install flask scikit-learn xgboost numpy pandas

# Verify installations
python3 --version  # Should show Python 3.x
pip3 list | grep -E "flask|scikit-learn"
```

### Step 3: Clone Repository
```bash
# Navigate to your workspace
cd ~

# Clone the WAF repository
git clone https://github.com/Lasvut/Testing.git

# Enter directory
cd Testing

# Verify files
ls -la
```

You should see these key files:
```
app.py                          # Main application
middleware.py                   # WAF engine
improved_svm_detector.py        # ML model
improved_svm_model.pkl          # Pre-trained model (403 KB)
train_improved_svm.py           # Training script
create_admin.py                 # Admin user creation
```

### Step 4: Create Admin User
```bash
python3 create_admin.py
```

**Enter when prompted:**
- Username: `admin`
- Password: `your_secure_password`
- Confirm password: `your_secure_password`

**Expected output:**
```
✅ Admin user 'admin' created successfully!
```

### Step 5: Verify Model File
```bash
ls -lh improved_svm_model.pkl
```

**Expected:**
```
-rw-r--r-- 1 user user 403K improved_svm_model.pkl
```

✅ **If you see this file, you're ready!** (Skip to Step 7)

⚠️ **If file is missing**, train the model:

### Step 6: Train ML Model (Only if .pkl missing)
```bash
# This takes 2-3 minutes
python3 train_improved_svm.py
```

**Expected output:**
```
================================================================================
IMPROVED LINEAR SVM TRAINING
================================================================================

Training data: 8000 normal + 5000 attacks
Preprocessing requests...
Extracting character trigram features...
✅ Extracted 10000 trigram features

Training Linear SVM classifier (C=0.5, balanced)...
✅ Base Linear SVM trained

Calibrating probabilities (Platt scaling)...
✅ Probability calibration complete

================================================================================
TRAINING COMPLETE
================================================================================

Expected Performance (on CSIC 2010 test set):
  • Accuracy: ~86.4%
  • Precision: ~80%
  • Recall: ~87%
  • False Positives: ~293 (out of 2100 normal)
```

### Step 7: Start the WAF
```bash
python3 app.py
```

**Expected startup output:**
```
[WAF] Pre-compiling regex patterns for optimal performance...
[WAF] ✅ Pre-compiled 613 regex patterns (0 skipped)
[WAF] ✅ Loaded pre-trained SVM model (86.4% acc, 87% recall, 293 FP)
[WAF] SVM Anomaly Detector Ready:
  - Model: Calibrated Linear SVM (C=0.5)
  - Trained: Yes
  - Performance: 86.4% acc, 87% recall, 293 FP
  - Features: 10,000 character trigrams (TF-IDF)
[App] Alert system loaded successfully
[App] WAF configuration and rate limiter loaded successfully
[App] ✅ Improved SVM model loaded (86.4% acc, 87% recall, 293 FP)
 * Running on http://127.0.0.1:5000
 * Debug mode: on
```

✅ **WAF is now running!**

### Step 8: Access the Dashboard
```bash
# Open browser (new terminal)
firefox http://localhost:5000 &
```

**Login with:**
- Username: `admin`
- Password: `your_secure_password`

---

## 🧪 Verify Setup (Test Attack Blocking)

### Test 1: SQL Injection
```bash
# In new terminal
curl "http://localhost:5000/search?q=' OR '1'='1"
```

**Expected response:**
```
⚠️ Request blocked: suspicious activity detected.
```

### Test 2: XSS Attack
```bash
curl "http://localhost:5000/search?q=<script>alert(1)</script>"
```

**Expected response:**
```
⚠️ Request blocked: suspicious activity detected.
```

### Test 3: Command Injection
```bash
curl "http://localhost:5000/search?q=;ls -la"
```

**Expected response:**
```
⚠️ Request blocked: suspicious activity detected.
```

✅ **If all three return 403 errors, your WAF is working perfectly!**

### Test 4: Automated Test Suite
```bash
# Run comprehensive tests
python3 test_waf_python.py
```

**Expected:**
```
Total Tests:        40
Blocked by WAF:     40
Passed (Vulnerable): 0
Effectiveness:      100.0%

✓ EXCELLENT - WAF is highly effective!
```

---

## 🌐 Make WAF Accessible from Network (For Testing)

If you want to test from another machine:

### Option 1: Modify app.py (Permanent)
```bash
nano app.py
```

**Find the last lines (~line 900):**
```python
if __name__ == "__main__":
    try:
        app.run(debug=True, use_reloader=False)  # Current
```

**Change to:**
```python
if __name__ == "__main__":
    try:
        app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
```

**Save:** `Ctrl+O` → Enter → `Ctrl+X`

### Option 2: Use SSH Tunnel (Temporary)
```bash
# From remote machine
ssh -L 5000:localhost:5000 user@kali-ip
```

Then access `http://localhost:5000` on remote machine.

### Option 3: Use ngrok (Public URL)
```bash
# Install ngrok
wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz
tar -xvzf ngrok-v3-stable-linux-amd64.tgz
sudo mv ngrok /usr/local/bin/

# Start WAF first
python3 app.py &

# Expose with ngrok
ngrok http 5000
```

**You'll get a public URL like:**
```
https://abc123.ngrok.io → http://localhost:5000
```

---

## 🔥 Testing with Kali Tools

### SQLMap
```bash
sqlmap -u "http://localhost:5000/search?q=test" \
  --batch --level=3 --risk=2
```

**Expected:**
```
[CRITICAL] WAF/IPS detected
[WARNING] all parameters appear to be not injectable
```

### Nikto
```bash
nikto -h http://localhost:5000
```

**Expected:**
```
+ WAF/IPS detected - Many requests blocked
```

### Burp Suite
```bash
# Start Burp Suite
burpsuite &

# Configure proxy: 127.0.0.1:8080
# Use Intruder with payloads from burp_payloads.txt
# Target: http://localhost:5000/search?q=§PAYLOAD§
```

**Expected:** All payloads return HTTP 403

---

## ⚙️ Configuration

### Adjust ML Threshold
```bash
# Edit middleware.py line 300
nano middleware.py +300
```

**Change threshold:**
```python
threshold=0.5  # Default (balanced)
threshold=0.3  # More sensitive (more FP)
threshold=0.7  # Less sensitive (more FN)
```

### View Attack Logs
```bash
# Real-time log monitoring
tail -f waf.db  # SQLite database

# Or use database directly
sqlite3 waf.db "SELECT * FROM logs ORDER BY id DESC LIMIT 10;"
```

### Check Performance
```bash
# Benchmark
ab -n 1000 -c 10 http://localhost:5000/

# Monitor resources
htop
```

---

## 🐛 Troubleshooting

### Issue: ModuleNotFoundError: No module named 'flask'
**Solution:**
```bash
pip3 install flask --user
# Or with sudo
sudo pip3 install flask
```

### Issue: ModuleNotFoundError: No module named 'sklearn'
**Solution:**
```bash
pip3 install scikit-learn --user
```

### Issue: Port 5000 already in use
**Solution:**
```bash
# Find and kill process
sudo lsof -i :5000
sudo kill -9 <PID>

# Or use different port
python3 app.py --port 5001
```

### Issue: improved_svm_model.pkl not found
**Solution:**
```bash
# Train the model
python3 train_improved_svm.py

# Or download pre-trained (if available)
wget https://github.com/Lasvut/Testing/raw/main/improved_svm_model.pkl
```

### Issue: WAF not blocking attacks
**Check detection mode:**
```bash
# Access: http://localhost:5000/waf-config
# Ensure "Detection Mode" is set to "Blocking"
```

### Issue: Too many false positives
**Adjust threshold:**
```bash
# In browser: http://localhost:5000/anomaly-testing
# Increase threshold from 50 to 60 or 70
```

---

## 📦 Complete Dependencies List

**System packages:**
```bash
sudo apt install -y \
  python3 \
  python3-pip \
  python3-dev \
  git \
  build-essential \
  libssl-dev
```

**Python packages:**
```bash
pip3 install \
  flask==2.3.0 \
  scikit-learn==1.3.0 \
  xgboost==1.7.0 \
  numpy==1.24.0 \
  pandas==2.0.0
```

**Or use requirements.txt (if available):**
```bash
pip3 install -r requirements.txt
```

---

## 🎯 Production Deployment (Optional)

### Using Gunicorn (Production Server)
```bash
# Install Gunicorn
pip3 install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using systemd (Auto-start on boot)
```bash
# Create service file
sudo nano /etc/systemd/system/waf.service
```

**Content:**
```ini
[Unit]
Description=Web Application Firewall
After=network.target

[Service]
Type=simple
User=kali
WorkingDirectory=/home/kali/Testing
ExecStart=/usr/bin/python3 /home/kali/Testing/app.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable waf.service
sudo systemctl start waf.service
sudo systemctl status waf.service
```

### Using Docker (Containerized)
```bash
# Build image
docker build -t waf-app .

# Run container
docker run -d -p 5000:5000 --name waf waf-app
```

---

## 🔐 Security Hardening (Production)

### Change Secret Key
```bash
nano app.py
```

**Line ~70:**
```python
app.secret_key = "replace-with-a-secure-random-secret"
```

**Change to:**
```python
import secrets
app.secret_key = secrets.token_hex(32)
```

### Enable HTTPS
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes \
  -out cert.pem -keyout key.pem -days 365
```

**Modify app.py:**
```python
app.run(host='0.0.0.0', port=5000,
        ssl_context=('cert.pem', 'key.pem'))
```

### Firewall Rules
```bash
# Allow only specific IPs
sudo ufw allow from 192.168.1.0/24 to any port 5000
sudo ufw enable
```

---

## 📊 Performance Tuning

### For High Traffic (>1000 req/sec)
```python
# app.py - Use production WSGI server
# Don't use Flask development server

# Use: Gunicorn, uWSGI, or Waitress
gunicorn -w 8 -b 0.0.0.0:5000 --worker-class gevent app:app
```

### Database Optimization
```bash
# Use PostgreSQL instead of SQLite
pip3 install psycopg2-binary
```

---

## ✅ Setup Verification Checklist

- [ ] Python 3.x installed
- [ ] All pip packages installed
- [ ] Repository cloned
- [ ] Admin user created
- [ ] improved_svm_model.pkl exists (403 KB)
- [ ] WAF starts without errors
- [ ] Dashboard accessible (http://localhost:5000)
- [ ] Can login with admin credentials
- [ ] Test attacks are blocked (SQL, XSS, CMD)
- [ ] Automated tests pass (test_waf_python.py)

**If all checked ✅, your WAF is ready for FYP demo!**

---

## 🎓 For FYP Demo

### Pre-Demo Checklist
```bash
# 1. Clear old logs
sqlite3 waf.db "DELETE FROM logs;"

# 2. Restart WAF for clean slate
pkill -f app.py
python3 app.py

# 3. Open dashboard in browser
firefox http://localhost:5000 &

# 4. Prepare attack terminal
# Ready to run: ./test_waf_python.py

# 5. Test one attack manually
curl "http://localhost:5000/search?q=' OR '1'='1"
```

### During Demo
1. Show clean dashboard (0 attacks)
2. Run automated tests
3. Refresh dashboard (show logged attacks)
4. Navigate to Anomaly Testing
5. Run ML test (show 86.4% accuracy)
6. Show attack log details

---

## 🆘 Quick Help

**WAF won't start?**
```bash
python3 -c "import flask; import sklearn; print('Dependencies OK')"
```

**Attacks not blocking?**
```bash
# Check WAF config
curl http://localhost:5000/api/waf/config
```

**Need to reset?**
```bash
# Stop WAF
pkill -f app.py

# Clear database
rm waf.db

# Restart fresh
python3 app.py
```

---

**Setup Complete! 🎉**

Your WAF is now running on Kali Linux and ready for penetration testing and FYP demonstration.

For video demo script, see: `FYP_VIDEO_DEMO_SCRIPT.md`
For penetration testing, see: `PENETRATION_TESTING_GUIDE.md`
