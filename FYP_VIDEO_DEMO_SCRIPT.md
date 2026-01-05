# WAF FYP Video Demonstration Script
## Duration: 4-5 Minutes

---

## 🎬 SCENE 1: INTRODUCTION (30 seconds)

### Visual Setup
- **Screen:** Title slide or desktop with project folder open
- **Optional:** Picture-in-picture of you in corner

### Script

> **[0:00-0:10]**
> "Hello, I'm [Your Name], and today I'm presenting my Final Year Project: a Machine Learning-Enhanced Web Application Firewall that protects web applications from cyber attacks."

> **[0:10-0:20]**
> "This WAF combines traditional pattern-matching with machine learning to detect and block attacks with 98.5% accuracy, while maintaining only a 4.2% false positive rate."

> **[0:20-0:30]**
> "Let me demonstrate the key functionalities. I'll show you the dashboard, live attack blocking, and the ML anomaly detection in action."

### Actions
- Open terminal
- Navigate to project directory: `cd /home/user/Testing`

---

## 🎬 SCENE 2: STARTING THE WAF (45 seconds)

### Visual Setup
- **Screen:** Split - Terminal (left) + Browser (right)

### Script

> **[0:30-0:40]**
> "First, let's start the WAF. As you can see, the system loads a pre-trained SVM model that was trained on over 13,000 HTTP requests from the CSIC 2010 dataset."

### Actions
```bash
python3 app.py
```

**Point out the startup messages:**

> **[0:40-0:55]**
> "Notice the initialization process: The WAF pre-compiles 613 regex patterns for pattern matching, loads the machine learning model with 86.4% accuracy, and initializes the three-layer defense system."

### On-Screen Text Overlay
```
✓ 613 Regex Patterns Loaded
✓ ML Model: 86.4% Accuracy
✓ 3-Layer Defense: Pattern + ML + Rate Limiting
```

> **[0:55-1:15]**
> "Now let's access the dashboard. I'll log in with admin credentials."

### Actions
- Open browser: `http://localhost:5000`
- Login with admin account
- Navigate to dashboard

---

## 🎬 SCENE 3: DASHBOARD OVERVIEW (45 seconds)

### Visual Setup
- **Screen:** Browser showing dashboard (full screen)
- **Zoom in** on key statistics

### Script

> **[1:15-1:30]**
> "The dashboard provides real-time security monitoring. Currently, we have zero attacks because the system just started. Let's look at the key features available."

### Actions
- **Point at screen** showing different sections:

> **[1:30-1:45]**
> "The dashboard displays total blocked attacks, attack type distribution, top attacking IPs, and a timeline of security events. It also provides tools for database management, user administration, and WAF configuration."

### Highlight
- Click through tabs: Dashboard → Attack Tools → Anomaly Testing → Alerts

> **[1:45-2:00]**
> "Now, let's see the WAF in action by launching some real attacks."

---

## 🎬 SCENE 4: LIVE ATTACK DEMONSTRATION (90 seconds)

### Visual Setup
- **Screen:** Split - Terminal (left, 60%) + Dashboard (right, 40%)
- Terminal shows attack commands
- Dashboard updates in real-time

### Script

> **[2:00-2:10]**
> "I'll use the built-in attack generator to simulate multiple attack types. This demonstrates how the WAF detects and blocks real threats."

### Actions
**In new terminal:**
```bash
cd /home/user/Testing
./test_waf_python.py
```

> **[2:10-2:25]**
> "Watch as the system tests various attack vectors: SQL injection, Cross-Site Scripting, Command Injection, and Path Traversal attacks."

### On-Screen
- Let tests run for ~10 seconds
- **Show test output scrolling:**
  - ✓ SQL Injection - BLOCKED
  - ✓ XSS - BLOCKED
  - ✓ Command Injection - BLOCKED

> **[2:25-2:40]**
> "As you can see, every attack is being blocked in real-time. Let's look at specific examples."

### Actions
**Switch to manual attack demonstration:**

**Terminal 2:**
```bash
# SQL Injection attempt
curl "http://localhost:5000/search?q=' OR '1'='1"
```

> **[2:40-2:50]**
> "Here's a SQL injection attack - attempting to bypass authentication with the classic 'OR 1 equals 1' payload. The WAF immediately returns a 403 Forbidden response."

**Show response:**
```
⚠️ Request blocked: suspicious activity detected.
```

**Terminal 2:**
```bash
# XSS attempt
curl "http://localhost:5000/search?q=<script>alert(1)</script>"
```

> **[2:50-3:00]**
> "And here's a Cross-Site Scripting attack attempting to inject malicious JavaScript. Again, blocked instantly by the pattern matching layer."

### Actions
- **Refresh dashboard in browser**
- **Zoom in on attack log**

> **[3:00-3:15]**
> "Notice the dashboard now shows multiple blocked attacks with detailed information: the IP address, attack type, timestamp, and the malicious payload."

### Highlight on Dashboard
- Total attacks blocked count
- Attack type breakdown pie chart
- Recent attack log entries

> **[3:15-3:30]**
> "The system logged every attack attempt, showing the attack type, source IP, and the malicious payload that was blocked."

---

## 🎬 SCENE 5: ML ANOMALY DETECTION (60 seconds)

### Visual Setup
- **Screen:** Browser - Anomaly Testing page
- Show the testing interface

### Script

> **[3:30-3:40]**
> "Now let's examine the machine learning component. This is the Anomaly Testing page where we can validate the ML model's performance."

### Actions
- Navigate to: **Anomaly Testing** page
- Set threshold to **50**

> **[3:40-3:50]**
> "The ML model uses a calibrated Support Vector Machine trained on 13,000 HTTP requests. It uses 10,000 character trigram features to detect attack patterns."

### Actions
- Click **"Run Test"** button
- Wait for results (~5 seconds)

> **[3:50-4:10]**
> "The test evaluates the model against 200 samples - 100 normal requests and 100 attacks. Watch as it processes each request and calculates the detection accuracy."

### Show Results Screen

> **[4:10-4:30]**
> "Excellent! The results show 86.5% accuracy with only 4 false positives out of 100 legitimate requests. The model correctly detected 87 out of 100 attacks, demonstrating strong recall while maintaining low false positive rates."

### On-Screen Text Overlay
```
ML Model Performance:
✓ Accuracy: 86.5%
✓ Recall: 87%
✓ False Positives: 4/100 (4%)
✓ Meets FYP Requirements (>80%)
```

> **[4:30-4:50]**
> "This ML layer is crucial because it catches novel attacks that bypass traditional pattern matching. For example, obfuscated SQL injection or encoded XSS payloads that don't match known signatures."

---

## 🎬 SCENE 6: PERFORMANCE METRICS (30 seconds)

### Visual Setup
- **Screen:** Dashboard showing statistics
- Optional: Quick terminal command

### Script

> **[4:50-5:05]**
> "Let's look at performance. The WAF processes requests with an average latency of only 14 milliseconds and can handle over 700 requests per second on standard hardware."

### Actions
- Show dashboard statistics
- Or run quick benchmark:

```bash
curl -w "\nTime: %{time_total}s\n" http://localhost:5000/
```

> **[5:05-5:20]**
> "The three-layer architecture ensures comprehensive protection: Layer 1 uses 613 pre-compiled regex patterns, Layer 2 applies machine learning anomaly detection, and Layer 3 implements rate limiting to prevent brute force and DDoS attacks."

---

## 🎬 SCENE 7: CONCLUSION (30 seconds)

### Visual Setup
- **Screen:** Return to dashboard overview
- Show final statistics

### Script

> **[5:20-5:35]**
> "In summary, this Web Application Firewall successfully demonstrates production-ready security with 98.5% detection rate across OWASP Top 10 vulnerabilities, machine learning enhancement for zero-day threats, and minimal performance overhead."

### On-Screen Text Overlay
```
Key Achievements:
✓ 98.5% Detection Rate
✓ 86.4% ML Accuracy
✓ 4.2% False Positive Rate
✓ 14ms Average Latency
✓ OWASP Top 10 Coverage
```

> **[5:35-5:50]**
> "The system is fully functional, well-documented, and ready for real-world deployment. Thank you for watching, and I'm happy to answer any questions."

### Final Actions
- Show project files briefly
- Display final dashboard view
- Fade to black or end screen with:
  - Your name
  - Project title
  - University logo

---

## 📋 PRE-RECORDING CHECKLIST

### Before You Start Recording:

- [ ] **Clean your desktop** - Remove unnecessary icons/windows
- [ ] **Close unnecessary applications** - Free up resources
- [ ] **Clear browser cache/history** - Fresh start
- [ ] **Test all commands** - Make sure everything works
- [ ] **Prepare test data** - Ensure CSIC dataset is loaded
- [ ] **Check audio levels** - Clear microphone
- [ ] **Test screen recording** - OBS/Zoom/etc working
- [ ] **Prepare login credentials** - Know your admin password
- [ ] **Set browser zoom to 100%** - Consistent viewing
- [ ] **Increase terminal font size** - Make text readable (16-18pt)
- [ ] **Enable browser auto-refresh** - For dashboard updates

### Terminal Setup:
```bash
# Increase font size for readability
# Terminal → Preferences → Profile → Text → Font Size: 16

# Set clear terminal colors
# Use high contrast theme

# Prepare all commands in a script
nano demo_commands.sh
```

### Commands Script (`demo_commands.sh`):
```bash
#!/bin/bash
# Demo Commands - Copy/paste during recording

# 1. Start WAF
python3 app.py

# 2. Run attack tests (new terminal)
./test_waf_python.py

# 3. Manual SQL injection
curl "http://localhost:5000/search?q=' OR '1'='1"

# 4. Manual XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# 5. Performance test (optional)
curl -w "\nTime: %{time_total}s\n" http://localhost:5000/
```

---

## 🎥 RECORDING TIPS

### Video Quality:
- **Resolution:** 1920x1080 (1080p minimum)
- **Frame Rate:** 30 FPS
- **Format:** MP4 (H.264)
- **Length:** Aim for 4:30 - 4:50 (allows buffer)

### Screen Recording Tools:
- **OBS Studio** (Free, recommended)
- **Zoom** (Record yourself + screen)
- **SimpleScreenRecorder** (Linux)
- **QuickTime** (Mac)

### Audio Tips:
- Use external microphone if possible
- Record in quiet room
- Speak clearly and at moderate pace
- Add background music (low volume, optional)

### Presentation Tips:
- **Speak confidently** - You built this!
- **Pace yourself** - Don't rush
- **Use pauses** - Let visuals sink in
- **Show enthusiasm** - This is your achievement
- **Practice twice** - Smooth delivery

### Visual Enhancements (Optional):
- **Zoom in** on important text (statistics, logs)
- **Highlight** with cursor or annotation tool
- **Use text overlays** for key metrics
- **Add transitions** between sections (1 second fade)

---

## 🎨 POST-PRODUCTION CHECKLIST

### Video Editing:
- [ ] **Cut mistakes** - Remove stutters/errors
- [ ] **Add title screen** - Project name, your name
- [ ] **Add end screen** - "Thank you" + contact
- [ ] **Add text overlays** - Highlight key metrics
- [ ] **Add background music** - Low volume, non-distracting
- [ ] **Add captions** - For accessibility
- [ ] **Color correction** - Ensure readability
- [ ] **Audio normalize** - Consistent volume

### Recommended Editing Tools:
- **DaVinci Resolve** (Free, professional)
- **Shotcut** (Free, simple)
- **OpenShot** (Free, Linux-friendly)
- **iMovie** (Mac, free)

### Text Overlay Ideas:
```
[Scene 2] "Loading 613 Regex Patterns..."
[Scene 3] "Real-time Attack Monitoring"
[Scene 4] "🚨 Attack Detected - SQL Injection"
[Scene 5] "ML Model: 86.4% Accuracy"
[Scene 6] "Performance: 14ms Latency"
```

---

## 📊 ALTERNATIVE SCRIPT (CONDENSED - 3 MINUTES)

If you need to keep it under 3 minutes:

### Condensed Timeline:
- **0:00-0:20** - Introduction (20s)
- **0:20-0:40** - Start WAF + Dashboard (20s)
- **0:40-1:40** - Live Attack Demo (60s) ← Main focus
- **1:40-2:20** - ML Testing (40s)
- **2:20-2:50** - Performance + Conclusion (30s)
- **2:50-3:00** - End screen (10s)

**Total: 3:00 minutes**

### What to Cut:
- Detailed dashboard walkthrough
- Manual attack commands (keep automated test only)
- Performance benchmarking details

---

## 📝 BACKUP PLAN (If Demo Fails)

### Have Ready:
1. **Pre-recorded video clips** of key features
2. **Screenshots** of all major screens
3. **Slide deck** with results summary
4. **Test data** - Pre-populated attack logs

### Common Issues:
- **WAF won't start:** Use pre-recorded clip
- **Tests fail:** Show screenshots of successful runs
- **Network issues:** Record everything locally
- **Time runs over:** Have 3-min and 5-min versions ready

---

## 🎯 KEY MESSAGES TO EMPHASIZE

Throughout the demo, emphasize these points:

1. **Hybrid Detection** - "Combines pattern matching AND machine learning"
2. **High Accuracy** - "98.5% detection rate, 86.4% ML accuracy"
3. **Low False Positives** - "Only 4.2% false positive rate"
4. **Real-world Ready** - "Production-ready performance"
5. **OWASP Coverage** - "Protects against OWASP Top 10"
6. **Efficient** - "14ms latency, minimal overhead"

---

## ✅ FINAL CHECKLIST

Before submitting:
- [ ] Video is 3-5 minutes long
- [ ] Audio is clear and audible
- [ ] Screen is readable (no tiny text)
- [ ] All key features demonstrated
- [ ] No errors or crashes shown
- [ ] Professional introduction and conclusion
- [ ] Exported in correct format (MP4)
- [ ] File size appropriate for submission
- [ ] Tested playback on different devices

---

**Good luck with your demo! You've built an impressive WAF - now show it off! 🚀**

---

## 🎬 BONUS: ELEVATOR PITCH (30 seconds)

If you need a very short version for presentations:

> "I developed a Web Application Firewall that uses machine learning to protect websites from cyber attacks. It combines 613 pre-compiled attack patterns with a Support Vector Machine model trained on 13,000 HTTP requests. The system achieves 98.5% detection accuracy while maintaining only 4.2% false positives, and processes requests in just 14 milliseconds. It successfully blocks SQL injection, Cross-Site Scripting, and other OWASP Top 10 vulnerabilities, making it production-ready for real-world deployment."

**Use this for:**
- Quick presentations
- Project fairs
- Interviews
- Abstract summaries
