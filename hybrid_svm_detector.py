#!/usr/bin/env python3
"""
Hybrid Anomaly Detector: Combines SVM Trigram Approach (99.75%) + Feature Engineering

This integrates:
1. Linear SVM with TF-IDF character trigrams (from 99.75% accuracy repo)
2. XGBoost + Random Forest with engineered features (our approach)
3. Super ensemble combining all three models

Target: 99%+ accuracy with <500 false positives
"""

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.ensemble import VotingClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import re
from urllib.parse import unquote
try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False
    print("⚠️  XGBoost not available")

from sklearn.ensemble import RandomForestClassifier


class HybridSVMAnomalyDetector:
    """
    Hybrid detector combining:
    - Linear SVM with character trigrams (99.75% accuracy approach)
    - XGBoost + Random Forest with behavioral features
    """

    def __init__(self):
        # SVM Components (from 99.75% accuracy approach)
        self.tfidf_vectorizer = TfidfVectorizer(
            min_df=0.0,
            analyzer="char",
            sublinear_tf=True,
            ngram_range=(3, 3),  # Character trigrams
            max_features=10000   # Limit features for performance
        )
        self.svm_model = LinearSVC(C=1.0, max_iter=2000, random_state=42)

        # Tree-based models (our engineered features approach)
        self.xgb_model = None
        self.rf_model = None
        self.scaler = StandardScaler()

        # Super ensemble combining all three
        self.super_ensemble = None
        self.trained = False

    def preprocess_request(self, request_data):
        """
        Preprocess request like the 99.75% accuracy approach:
        - Extract URL/payload
        - URL decode
        - Lowercase normalization
        """
        # Get the raw request string
        if isinstance(request_data, dict):
            path = request_data.get('path', '')
            payload = request_data.get('payload', '')
            request_str = f"{path}?{payload}" if payload else path
        else:
            request_str = str(request_data)

        # URL decode
        request_str = unquote(request_str)

        # Lowercase normalization
        request_str = request_str.lower()

        return request_str

    def extract_behavioral_features(self, request_data):
        """
        Extract our 38 behavioral features for tree-based models
        """
        if isinstance(request_data, dict):
            path = request_data.get('path', '')
            payload = request_data.get('payload', '')
        else:
            path = payload = str(request_data)

        combined = f"{path}{payload}"

        features = []

        # Length features
        features.append(len(combined))
        features.append(len(path))
        features.append(len(payload))

        # Special character counts
        features.append(combined.count("'"))
        features.append(combined.count('"'))
        features.append(combined.count('<'))
        features.append(combined.count('>'))
        features.append(combined.count('('))
        features.append(combined.count(')'))
        features.append(combined.count(';'))
        features.append(combined.count('--'))
        features.append(combined.count('='))
        features.append(combined.count('&'))
        features.append(combined.count('%'))
        features.append(combined.count('..'))
        features.append(combined.count('/'))
        features.append(combined.count('\\'))

        # SQL injection patterns
        sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop',
                       'exec', 'script', 'or', 'and', 'where']
        features.append(sum(1 for kw in sql_keywords if kw in combined.lower()))

        # XSS patterns
        xss_patterns = ['<script', 'javascript:', 'onerror', 'onload', 'eval(', 'alert(']
        features.append(sum(1 for pat in xss_patterns if pat in combined.lower()))

        # Path traversal
        features.append(1 if '../' in combined or '..\\' in combined else 0)

        # Encoded characters
        features.append(combined.count('%20'))
        features.append(combined.count('%27'))
        features.append(combined.count('%3C'))
        features.append(combined.count('%3E'))

        # Entropy (randomness)
        try:
            from collections import Counter
            if combined:
                freq = Counter(combined)
                entropy = -sum((count/len(combined)) * np.log2(count/len(combined))
                              for count in freq.values())
                features.append(entropy)
            else:
                features.append(0)
        except:
            features.append(0)

        # Digit ratio
        digit_count = sum(c.isdigit() for c in combined)
        features.append(digit_count / len(combined) if combined else 0)

        # Uppercase ratio
        upper_count = sum(c.isupper() for c in combined)
        features.append(upper_count / len(combined) if combined else 0)

        # Alphanumeric ratio
        alnum_count = sum(c.isalnum() for c in combined)
        features.append(alnum_count / len(combined) if combined else 0)

        # Number of parameters
        features.append(payload.count('&') + 1 if payload else 0)

        # Average parameter length
        if payload and '&' in payload:
            params = payload.split('&')
            avg_len = sum(len(p) for p in params) / len(params)
            features.append(avg_len)
        else:
            features.append(0)

        # Suspicious file extensions
        suspicious_ext = ['.exe', '.bat', '.cmd', '.sh', '.php', '.asp', '.jsp']
        features.append(sum(1 for ext in suspicious_ext if ext in combined.lower()))

        # Database keywords
        db_keywords = ['database', 'table', 'column', 'schema', 'information_schema']
        features.append(sum(1 for kw in db_keywords if kw in combined.lower()))

        # Command injection patterns
        cmd_patterns = ['|', '`', '$', '&&', '||']
        features.append(sum(combined.count(p) for p in cmd_patterns))

        # Null byte
        features.append(1 if '%00' in combined or '\\x00' in combined else 0)

        # LDAP injection
        features.append(1 if any(p in combined for p in ['*)(', ')(', '*))']) else 0)

        # XML injection
        features.append(1 if any(p in combined for p in ['<!', '<![CDATA', '<?xml']) else 0)

        return np.array(features).reshape(1, -1)

    def train(self, normal_requests, attack_requests):
        """
        Train hybrid model with both approaches
        """
        print("=" * 80)
        print("HYBRID MODEL TRAINING: SVM Trigrams + Feature Engineering")
        print("=" * 80)
        print()

        # Prepare data
        all_requests = normal_requests + attack_requests
        labels = [0] * len(normal_requests) + [1] * len(attack_requests)

        print(f"Training data: {len(normal_requests)} normal + {len(attack_requests)} attacks")
        print()

        # ========================================
        # APPROACH 1: Linear SVM with Trigrams
        # ========================================
        print("[1/3] Training Linear SVM with Character Trigrams...")

        # Preprocess all requests
        preprocessed_requests = [self.preprocess_request(req) for req in all_requests]

        # Extract TF-IDF trigram features
        X_trigrams = self.tfidf_vectorizer.fit_transform(preprocessed_requests)

        # Train SVM
        self.svm_model.fit(X_trigrams, labels)
        print(f"✅ Linear SVM trained on {X_trigrams.shape[1]} trigram features")
        print()

        # ========================================
        # APPROACH 2: XGBoost + RF with Features
        # ========================================
        print("[2/3] Training XGBoost + Random Forest with Engineered Features...")

        # Extract behavioral features
        X_features_list = [self.extract_behavioral_features(req) for req in all_requests]
        X_features = np.vstack(X_features_list)

        # Scale features
        X_features_scaled = self.scaler.fit_transform(X_features)

        # Train XGBoost
        if XGBOOST_AVAILABLE:
            n_neg = len(normal_requests)
            n_pos = len(attack_requests)
            scale_pos_weight = (n_neg / n_pos) * 3.5  # Balanced

            self.xgb_model = XGBClassifier(
                n_estimators=400,
                max_depth=7,
                learning_rate=0.05,
                scale_pos_weight=scale_pos_weight,
                random_state=42,
                n_jobs=-1
            )
            self.xgb_model.fit(X_features_scaled, labels)
            print("✅ XGBoost trained on 38 behavioral features")

        # Train Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=300,
            max_depth=12,
            class_weight={0: 1.0, 1: 4.0},
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(X_features_scaled, labels)
        print("✅ Random Forest trained on 38 behavioral features")
        print()

        # ========================================
        # APPROACH 3: Super Ensemble
        # ========================================
        print("[3/3] Creating Super Ensemble (SVM + XGBoost + RF)...")

        # We can't use VotingClassifier directly because different feature sets
        # So we'll use weighted prediction in the predict method

        self.trained = True
        print("✅ Hybrid model training complete!")
        print()
        print("Model Components:")
        print(f"  • Linear SVM: {X_trigrams.shape[1]} trigram features")
        print(f"  • XGBoost: 38 behavioral features")
        print(f"  • Random Forest: 38 behavioral features")
        print(f"  • Ensemble: Weighted voting (SVM=0.5, XGB=0.3, RF=0.2)")
        print()

    def predict_proba(self, request_data):
        """
        Predict probability using super ensemble
        """
        if not self.trained:
            raise ValueError("Model not trained yet!")

        # Get SVM prediction
        preprocessed = self.preprocess_request(request_data)
        X_trigram = self.tfidf_vectorizer.transform([preprocessed])
        svm_decision = self.svm_model.decision_function(X_trigram)[0]
        # Convert decision function to probability (sigmoid)
        svm_prob = 1 / (1 + np.exp(-svm_decision))

        # Get XGBoost prediction
        X_features = self.extract_behavioral_features(request_data)
        X_features_scaled = self.scaler.transform(X_features)

        if self.xgb_model:
            xgb_prob = self.xgb_model.predict_proba(X_features_scaled)[0][1]
        else:
            xgb_prob = 0

        # Get Random Forest prediction
        rf_prob = self.rf_model.predict_proba(X_features_scaled)[0][1]

        # Weighted ensemble (SVM gets highest weight due to 99.75% accuracy)
        ensemble_prob = (0.5 * svm_prob) + (0.3 * xgb_prob) + (0.2 * rf_prob)

        return ensemble_prob

    def is_anomalous(self, request_data, threshold=0.5):
        """
        Detect if request is anomalous
        """
        prob = self.predict_proba(request_data)
        is_attack = prob >= threshold

        score = prob * 100  # Convert to 0-100 scale

        return is_attack, score, {
            'probability': prob,
            'threshold': threshold,
            'score': score
        }

    def save_model(self, filepath):
        """Save trained model"""
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(self, f)
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False

    @staticmethod
    def load_model(filepath):
        """Load trained model"""
        try:
            with open(filepath, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error loading model: {e}")
            return None
