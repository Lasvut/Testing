# HTTP Anomaly Detection WAF

Advanced Web Application Firewall with Machine Learning-based anomaly detection for HTTP traffic.

## 🎯 Performance

**Production ML Model (Improved SVM):**
- **Accuracy:** 86.43%
- **Precision:** 80.04%
- **Recall:** 87.04%
- **F1-Score:** 83.39%
- **Specificity:** 86.05%
- **False Positives:** 293 (out of 2,100 normal requests)

Validated on CSIC 2010 HTTP dataset.

## 📁 Repository Structure

### Core Application Files

- **`app.py`** - Main Flask application
  - Web interface for WAF management
  - Anomaly detection testing endpoint
  - User authentication and session management

- **`middleware.py`** - WAF middleware
  - Real-time HTTP request filtering
  - Attack blocking and logging

- **`database.py`** - Database operations
  - SQLite database for attack logs
  - User management
  - Attack statistics

- **`rules.py`** - WAF security rules
  - XSS protection patterns
  - SQL injection detection
  - Path traversal prevention
  - Command injection blocking

### Machine Learning Models

- **`improved_svm_detector.py`** - **Production ML Model** ⭐
  - Calibrated Linear SVM with character trigram features
  - 86.4% accuracy, 87% recall, only 293 false positives
  - Optimal threshold: 0.5 (50 in UI)

- **`ultra_anomaly_detection.py`** - Conservative backup model
  - XGBoost + Random Forest ensemble
  - Used as fallback if SVM unavailable

- **`improved_svm_model.pkl`** - **Production model file** (403 KB)
- **`anomaly_detector_model.pkl`** - Backup model file (5.8 MB)

### Training Scripts

- **`train_improved_svm.py`** - Train the production SVM model
  - Loads CSIC 2010 dataset
  - Trains with optimal hyperparameters (C=0.5, balanced)
  - Applies probability calibration
  - Saves to `improved_svm_model.pkl`

- **`test_improved_svm.py`** - Test and validate SVM performance
  - Tests multiple thresholds
  - Generates confusion matrices
  - Validates production metrics

### Utilities

- **`attack_generator.py`** - Background attack generator for testing
- **`attack_generator_gui.py`** - GUI for manual attack generation
- **`create_admin.py`** - Create admin users
- **`ATTACK_GENERATOR_README.md`** - Documentation for attack generator

### Templates & Static Files

- `templates/` - HTML templates for web interface
- `static/` - CSS, JavaScript, images
- `datasets/` - CSIC 2010 HTTP dataset

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install flask scikit-learn xgboost numpy pandas
```

### 2. Initialize Database

```bash
python3 create_admin.py
```

### 3. Run Application

```bash
python3 app.py
```

Access at: `http://localhost:5000`

## 🧪 Testing Anomaly Detection

### Via Web Interface

1. Navigate to **Anomaly Testing** page
2. Set threshold to **50** (optimal for production)
3. Click "Run Anomaly Detection Test"

Expected results:
- ~86.4% accuracy
- ~87% recall
- ~293 false positives (out of ~2,100 normal requests)

### Via Command Line

```bash
python3 test_improved_svm.py
```

## 🔧 Training a New Model

If you need to retrain the model with new data:

```bash
python3 train_improved_svm.py
```

Requirements:
- `datasets/csic2010/CSIC_2010.csv` must exist
- Minimum 100 normal samples, 50 attack samples

## 📊 Model Architecture

**Improved SVM Detector:**

```
HTTP Request
     ↓
URL Decode + Lowercase
     ↓
Character Trigrams (3-char sequences)
     ↓
TF-IDF Vectorization (10,000 features)
     ↓
Linear SVM (C=0.5, balanced)
     ↓
Probability Calibration (Platt scaling)
     ↓
Attack Probability (0.0-1.0)
     ↓
Threshold (0.5) → Attack/Normal Decision
```

**Key Features:**
- Character-level n-grams capture attack patterns
- TF-IDF weighting emphasizes important features
- Higher regularization (C=0.5) reduces false positives
- Balanced class weights handle dataset imbalance
- Probability calibration provides reliable thresholds

## 🎯 Optimization History

**v1.0 - Initial Models:**
- XGBoost + Random Forest ensemble
- 79% accuracy, 2,215 false positives
- Too aggressive

**v2.0 - Conservative Tuning:**
- Reduced weights and thresholds
- 80% accuracy, 137 FP
- But only 59% recall (missed 41% of attacks)

**v3.0 - Linear SVM:**
- Integrated from research paper
- 83% accuracy, 301 FP, 79% recall
- Better balance

**v4.0 - Improved SVM (Current):** ⭐
- Added probability calibration
- Higher regularization (C=0.5)
- **86.4% accuracy, 293 FP, 87% recall**
- **PRODUCTION READY**

## 📈 Performance Metrics Explanation

- **Accuracy:** Overall correct predictions (both attack and normal)
- **Precision:** When model says "attack", how often is it correct?
- **Recall:** Of all real attacks, what % does model detect?
- **F1-Score:** Harmonic mean of precision and recall
- **Specificity:** Of all normal requests, what % are correctly identified?
- **False Positives:** Normal requests incorrectly flagged as attacks

**Production Goal:** Balance all metrics while minimizing FP < 500

## 🔒 Security Features

**WAF Protection:**
- XSS attack prevention
- SQL injection blocking
- Path traversal detection
- Command injection filtering
- SSRF protection
- File inclusion blocking
- LDAP injection prevention

**ML Anomaly Detection:**
- Detects zero-day attacks
- Learns from HTTP traffic patterns
- Adapts to new attack vectors
- Low false positive rate

## 📝 Cleanup Summary (Latest)

**Removed deprecated files:**
- Old model files: `linear_svm_detector.py`, `linear_svm_model.pkl`
- Failed experiments: `ultimate_hybrid_detector.py`, `simple_hybrid_detector.py`
- Old testing scripts: `test_accuracy.py`, `testcomparison.py`
- One-time utilities: `analyze.py`, `fix_rules.py`
- Temporary files: `temp/`, `tempCodeRunnerFile.py`
- Backup files: `rules_backup.py`

**Total cleanup:** ~9 MB of deprecated code and models removed

**Optimized files:**
- `app.py`: Removed deprecated imports, cleaner code
- `improved_svm_detector.py`: Better error handling, validation, documentation

## 🤝 Contributing

To add new features or improve models:

1. Create feature branch
2. Test thoroughly with `test_improved_svm.py`
3. Ensure no performance regression
4. Submit pull request

## 📄 License

This project is for educational and research purposes.

## 🎓 References

- CSIC 2010 HTTP Dataset
- Linear SVM research: [Monkey-D-Groot/Machine-Learning-on-CSIC-2010](https://github.com/Monkey-D-Groot/Machine-Learning-on-CSIC-2010)
- Scikit-learn documentation
- OWASP WAF guidelines

---

**Built with ❤️ for web security**
