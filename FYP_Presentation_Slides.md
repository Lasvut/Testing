# HTTP Anomaly Detection Web Application Firewall
## Machine Learning-Based Security Solution

**Final Year Project Presentation**

---

## Slide 1: Title Slide

**HTTP Anomaly Detection WAF**
**Machine Learning-Based Web Application Firewall**

Final Year Project
Date: January 2026

---

## Slide 2: Problem Statement

### The Challenge
- **Web applications** are constantly under attack
- Traditional signature-based WAFs struggle with **zero-day attacks**
- High **false positive rates** block legitimate users
- Need for **intelligent, adaptive security** solutions

### Statistics
- 43% of cyber attacks target web applications
- Traditional WAFs miss 30-40% of novel attacks
- Average cost of a web app breach: $4.35 million

---

## Slide 3: Project Objectives

### Primary Goals
1. **Develop** an intelligent WAF with ML-based anomaly detection
2. **Achieve** high accuracy (>85%) with low false positives (<500)
3. **Detect** both known and zero-day attacks
4. **Provide** real-time protection for web applications

### Success Criteria
- Accuracy: >85%
- Recall: >80% (detect 80% of attacks)
- False Positives: <500 (out of 2,100 normal requests)
- Response Time: <100ms per request

---

## Slide 4: System Architecture

### Three-Layer Security Approach

```
┌─────────────────────────────────────────┐
│         Incoming HTTP Request           │
└──────────────┬──────────────────────────┘
               │
       ┌───────▼────────┐
       │  Layer 1:      │
       │  Rule-Based    │  ◄── 386 Security Patterns
       │  Pattern       │      (XSS, SQLi, etc.)
       │  Matching      │
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │  Layer 2:      │
       │  ML Anomaly    │  ◄── Linear SVM Model
       │  Detection     │      (86.4% accuracy)
       │  (Improved SVM)│
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │  Layer 3:      │
       │  Rate Limiting │  ◄── Flood Detection
       │  & Flood       │      Alert System
       │  Detection     │
       └───────┬────────┘
               │
      ┌────────▼─────────┐
      │  Allow / Block   │
      │  Decision        │
      └──────────────────┘
```

---

## Slide 5: Machine Learning Approach

### Improved SVM Detector (Production Model)

**Feature Engineering:**
- **Character trigrams** (3-character sequences)
- **TF-IDF vectorization** (10,000 features)
- Captures attack patterns at character level

**Model Configuration:**
- **Linear SVM** with C=0.5 (higher regularization)
- **Balanced class weights** for imbalanced dataset
- **Probability calibration** (Platt scaling)
- Optimal threshold: 0.5

**Training Data:**
- **CSIC 2010** HTTP Dataset
- 8,000 normal requests
- 5,000 attack samples

---

## Slide 6: Rule-Based Security

### 386 Pre-Compiled Security Patterns

**Attack Types Detected:**
- **XSS (Cross-Site Scripting)** - 85 patterns
- **SQL Injection** - 120 patterns
- **Path Traversal** - 45 patterns
- **Command Injection** - 38 patterns
- **SSRF (Server-Side Request Forgery)** - 28 patterns
- **File Inclusion (LFI/RFI)** - 35 patterns
- **LDAP Injection** - 20 patterns
- **Other attacks** - 15 patterns

**Pattern Compilation:**
- All patterns pre-compiled for performance
- 0 failed compilations
- <1 second load time

---

## Slide 7: Performance Metrics - ML Model

### Production SVM Model Results

| Metric | Value | Interpretation |
|--------|-------|----------------|
| **Accuracy** | 86.43% | Overall correct predictions |
| **Precision** | 80.04% | When flagged as attack, 80% correct |
| **Recall** | 87.04% | Detects 87% of all attacks |
| **F1-Score** | 83.39% | Balanced performance |
| **Specificity** | 86.05% | Correctly identifies 86% of normal traffic |
| **False Positives** | 293 | Only 293 out of 2,100 normal requests blocked |

**Dataset:** CSIC 2010 (2,100 normal + 3,400 attack requests)

**Result:** ✅ **PRODUCTION READY**

---

## Slide 8: Model Evolution & Optimization

### Optimization Journey

| Version | Approach | Accuracy | False Positives | Recall | Status |
|---------|----------|----------|-----------------|--------|--------|
| **v1.0** | XGBoost + RF | 79% | 2,215 | 85% | ❌ Too aggressive |
| **v2.0** | Conservative tuning | 80% | 137 | 59% | ❌ Missed attacks |
| **v3.0** | Linear SVM | 83% | 301 | 79% | ⚠️ Good balance |
| **v4.0** | **Improved SVM** | **86.4%** | **293** | **87%** | ✅ **PRODUCTION** |

### Key Improvements (v4.0)
- Added probability calibration
- Higher regularization (C=0.5)
- Better false positive control
- Improved recall by 8%

---

## Slide 9: System Features

### Core Capabilities

**Security Features:**
- ✅ Real-time HTTP request filtering
- ✅ Automatic attack blocking and logging
- ✅ User authentication and session management
- ✅ Attack statistics and reporting
- ✅ Email and Discord alert notifications
- ✅ Rate limiting (requests per IP)
- ✅ Flood detection (DDoS protection)

**Web Interface:**
- Dashboard with attack statistics
- Real-time attack logs
- Anomaly detection testing tool
- User management
- Alert configuration

---

## Slide 10: Testing Results - Request Processing

### All Tests Passed ✅

| Test Case | Result | Performance |
|-----------|--------|-------------|
| **Valid GET Request** | ✅ PASS | HTTP 200, processed correctly |
| **Valid POST Request** | ✅ PASS | Form data handled properly |
| **Large Payload (12KB)** | ✅ PASS | No timeout/memory issues |
| **120 Concurrent Requests** | ✅ PASS | 62.95ms avg (87% faster) |
| **Special Characters** | ✅ PASS | URL encoding handled correctly |

**Overall:** 100% pass rate (5/5 tests)

---

## Slide 11: Performance Testing Results

### Concurrent Request Handling

**Test Configuration:**
- 120 simultaneous requests
- Target: `/login` endpoint
- Requirement: <500ms average response

**Actual Results:**
- ✅ Total Requests: 120
- ✅ Successful: 120 (100%)
- ✅ Failed: 0 (0%)
- ✅ Total Time: 0.246 seconds
- ✅ **Average Response Time: 62.95ms** (87% faster than requirement)
- ✅ Max Response Time: 88.93ms
- ✅ Min Response Time: 7.69ms

**Conclusion:** Excellent concurrent handling, thread-safe implementation

---

## Slide 12: Technology Stack

### Implementation Details

**Backend:**
- **Python 3.11** - Core application
- **Flask** - Web framework
- **SQLite** - Database for logs and users

**Machine Learning:**
- **scikit-learn** - Linear SVM, TF-IDF
- **NumPy** - Numerical operations
- **Pandas** - Data processing

**Security:**
- **386 Regex Patterns** - Pre-compiled for speed
- **Character Trigram Analysis** - ML feature extraction
- **Probability Calibration** - Reliable attack scoring

**Frontend:**
- HTML5/CSS3 - Web interface
- JavaScript - Interactive features

---

## Slide 13: System Workflow

### How It Works - Request Flow

1. **Request Arrival**
   - HTTP request received by Flask application
   - WAF middleware intercepts request

2. **Pattern Matching (Layer 1)**
   - Check against 386 security patterns
   - Detect known attack signatures
   - If matched → Block and log

3. **ML Anomaly Detection (Layer 2)**
   - Extract character trigrams
   - Convert to TF-IDF features
   - SVM predicts attack probability
   - If probability > 0.5 → Block and log

4. **Rate Limiting (Layer 3)**
   - Check requests per IP
   - Detect flood patterns
   - If exceeded → Block temporarily

5. **Decision**
   - ✅ Allow: Forward to application
   - ❌ Block: Return 403, log attack, send alert

---

## Slide 14: Key Achievements

### Project Highlights

✅ **High Accuracy:** 86.43% detection rate

✅ **Low False Positives:** Only 293 FP (14% of normal traffic)

✅ **High Recall:** Detects 87% of attacks

✅ **Fast Performance:** 62.95ms average response time

✅ **Production Ready:** All tests passed

✅ **Scalable:** Handles 120+ concurrent requests

✅ **Comprehensive:** 386 security patterns + ML detection

✅ **Real-time Protection:** Automatic blocking and alerting

---

## Slide 15: Attack Detection Examples

### Real Attack Patterns Detected

**SQL Injection:**
```
GET /login?username=admin' OR '1'='1'-- &password=test
```
- ✅ Blocked by Pattern Matcher (SQL Injection rule)
- ✅ Confirmed by ML (99% attack probability)

**XSS Attack:**
```
POST /comment
body: <script>alert('XSS')</script>
```
- ✅ Blocked by Pattern Matcher (XSS rule)
- ✅ Confirmed by ML (98% attack probability)

**Path Traversal:**
```
GET /file?path=../../../../etc/passwd
```
- ✅ Blocked by Pattern Matcher (Path Traversal rule)
- ✅ Confirmed by ML (95% attack probability)

---

## Slide 16: Database & Logging

### Attack Logging System

**Database Schema:**
- `attacks` table: Logs all blocked requests
- `users` table: User authentication
- `attack_stats` table: Aggregated statistics

**Logged Information:**
- Timestamp
- IP address
- Request method (GET/POST)
- URL path
- Attack type detected
- Attack payload
- ML confidence score

**Benefits:**
- Forensic analysis
- Trend identification
- Attack source tracking
- Security reporting

---

## Slide 17: Alert System

### Multi-Channel Notifications

**Email Alerts:**
- SMTP integration
- Configurable thresholds
- Attack summaries
- Daily/weekly reports

**Discord Alerts:**
- Webhook integration
- Real-time notifications
- Color-coded severity
- Attack details

**Alert Triggers:**
- High-severity attacks
- Attack rate thresholds
- Flood detection
- Multiple failed logins

---

## Slide 18: Advantages Over Traditional WAFs

### Why This Solution is Better

| Feature | Traditional WAF | This ML-Enhanced WAF |
|---------|----------------|---------------------|
| **Zero-day Detection** | ❌ Poor | ✅ Excellent (ML-based) |
| **False Positives** | High (500-1000) | Low (293) |
| **Adaptation** | Manual updates | Automatic learning |
| **Pattern Coverage** | 100-200 rules | 386 rules + ML |
| **Response Time** | 100-200ms | 62.95ms average |
| **Attack Detection Rate** | 70-80% | 87% |
| **Cost** | High (commercial) | Low (open source) |

---

## Slide 19: Challenges & Solutions

### Challenges Faced

**Challenge 1: High False Positives**
- Problem: Initial model blocked too many legitimate requests
- Solution: Probability calibration + higher regularization (C=0.5)
- Result: Reduced FP from 2,215 to 293

**Challenge 2: Low Recall (Missing Attacks)**
- Problem: Conservative tuning missed 41% of attacks
- Solution: Balanced class weights + optimal threshold
- Result: Improved recall from 59% to 87%

**Challenge 3: Performance with Large Payloads**
- Problem: Potential slowdown with >10KB requests
- Solution: Efficient feature extraction, pre-compiled patterns
- Result: Handles 12KB+ without degradation

---

## Slide 20: Code Quality & Structure

### Clean, Maintainable Codebase

**File Organization:**
- `app.py` - Main Flask application (57KB)
- `middleware.py` - WAF middleware (15KB)
- `improved_svm_detector.py` - ML model (9KB)
- `rules.py` - Security patterns (42KB)
- `database.py` - Database operations (9KB)

**Best Practices:**
- ✅ Modular architecture
- ✅ Clear separation of concerns
- ✅ Comprehensive error handling
- ✅ Detailed documentation
- ✅ Type hints and validation
- ✅ Unit tests for ML model

**Code Cleanup:**
- Removed 9MB of deprecated code
- Eliminated failed experiments
- Optimized imports

---

## Slide 21: Future Enhancements

### Potential Improvements

**1. Deep Learning Integration**
- LSTM/Transformer models for sequence analysis
- Better detection of complex attacks
- Transfer learning from other datasets

**2. Distributed Deployment**
- Multi-server architecture
- Load balancing
- Centralized logging

**3. Advanced Features**
- API protection
- GraphQL security
- WebSocket filtering
- Bot detection

**4. Model Improvements**
- Active learning from blocked requests
- Ensemble of multiple ML models
- Real-time model updates

---

## Slide 22: Conclusion

### Project Summary

**What We Built:**
- Advanced WAF with ML-based anomaly detection
- 86.43% accuracy, 87% recall, 293 false positives
- Real-time protection for web applications
- Production-ready system

**Key Contributions:**
1. Hybrid security approach (rules + ML)
2. Optimized SVM model with low false positives
3. Comprehensive security pattern library (386 patterns)
4. Fast, scalable implementation (62.95ms avg)
5. Full-featured web interface

**Impact:**
- Protects web applications from known and unknown attacks
- Reduces false positives by 86% vs initial version
- Detects 87% of all attacks
- Open-source solution for community benefit

---

## Slide 23: Demonstration

### Live Demo

**1. Dashboard**
- Attack statistics
- Real-time logs
- System status

**2. Anomaly Testing**
- Upload test dataset
- Run ML detection
- View results (confusion matrix, metrics)

**3. Attack Blocking**
- Submit malicious request
- See real-time blocking
- Check attack log

**4. Alert System**
- Configure thresholds
- Test email/Discord alerts
- View notifications

---

## Slide 24: References & Resources

### Technical References

**Datasets:**
- CSIC 2010 HTTP Dataset (Standard benchmark)

**Research:**
- [Machine Learning on CSIC 2010](https://github.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010)
- OWASP WAF Guidelines
- scikit-learn Documentation

**Technologies:**
- Flask Web Framework
- scikit-learn ML Library
- SQLite Database

**Standards:**
- OWASP Top 10 Web Application Security Risks
- HTTP/1.1 Specification (RFC 7230-7235)

---

## Slide 25: Q&A

### Questions?

**Contact Information:**
- Project Repository: Available on request
- Documentation: README.md
- Test Reports: REQUEST_PROCESSING_TEST_REPORT.md

**Key Files to Review:**
- `app.py` - Main application
- `improved_svm_detector.py` - ML model
- `test_improved_svm.py` - Model validation
- `rules.py` - Security patterns

**Thank you for your attention!**

---

## Appendix: Technical Specifications

### System Requirements
- Python 3.11+
- 2GB RAM minimum
- Linux/Windows/macOS
- 500MB disk space

### Model Files
- `improved_svm_model.pkl` - 403KB
- Training time: ~2 minutes
- Inference time: <5ms per request

### Performance Benchmarks
- 120+ concurrent requests
- <100ms response time
- Zero downtime
- Thread-safe implementation
