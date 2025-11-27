#!/usr/bin/env python3
"""
Improved Linear SVM Anomaly Detector with Calibration

Enhancements over basic Linear SVM:
- Probability calibration using CalibratedClassifierCV
- Higher regularization (C=0.5) to reduce false positives
- Better threshold tuning capabilities

Target: <500 FP while maintaining 85%+ accuracy and recall
"""

import numpy as np
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from urllib.parse import unquote


class ImprovedSVMAnomalyDetector:
    """
    Improved Linear SVM detector with calibration for better FP control

    Target: <500 FP, 85%+ accuracy, 85%+ recall
    """

    def __init__(self):
        # TF-IDF Vectorizer with character trigrams
        self.tfidf_vectorizer = TfidfVectorizer(
            min_df=0.0,
            analyzer="char",
            sublinear_tf=True,
            ngram_range=(3, 3),  # Character trigrams
            max_features=10000   # Limit features for performance
        )

        # Linear SVM classifier with higher regularization
        self.svm_model = LinearSVC(
            C=0.5,              # Higher regularization (was 1.0) - reduces overfitting
            max_iter=3000,      # More iterations for convergence
            random_state=42,
            class_weight='balanced'  # Handle class imbalance
        )

        # Calibrated classifier for better probabilities
        self.calibrated_model = None

        self.trained = False

    def preprocess_request(self, request_data):
        """
        Preprocess HTTP request for feature extraction

        Steps:
        1. Extract path and payload
        2. URL decode
        3. Lowercase normalization
        """
        # Get the raw request string
        if isinstance(request_data, dict):
            path = request_data.get('path', '')
            payload = request_data.get('payload', '')
            request_str = f"{path}?{payload}" if payload else path
        else:
            request_str = str(request_data)

        # URL decode
        try:
            request_str = unquote(request_str)
        except:
            pass

        # Lowercase normalization
        request_str = request_str.lower()

        return request_str

    def train(self, normal_requests, attack_requests):
        """
        Train the improved SVM model with calibration

        Args:
            normal_requests: List of normal HTTP requests
            attack_requests: List of attack HTTP requests
        """
        print("="*80)
        print("IMPROVED LINEAR SVM TRAINING - With Calibration")
        print("="*80)
        print()

        # Prepare training data
        all_requests = normal_requests + attack_requests
        labels = [0] * len(normal_requests) + [1] * len(attack_requests)

        print(f"Training data: {len(normal_requests)} normal + {len(attack_requests)} attacks")
        print()

        # Preprocess all requests
        print("Preprocessing requests...")
        preprocessed_requests = [self.preprocess_request(req) for req in all_requests]

        # Extract TF-IDF trigram features
        print("Extracting character trigram features...")
        X_train = self.tfidf_vectorizer.fit_transform(preprocessed_requests)
        print(f"✅ Extracted {X_train.shape[1]} trigram features")
        print()

        # Train base SVM
        print("Training Linear SVM classifier (C=0.5, balanced)...")
        self.svm_model.fit(X_train, labels)
        print("✅ Base Linear SVM trained")
        print()

        # Calibrate probabilities using sigmoid method
        print("Calibrating probabilities for better threshold control...")
        self.calibrated_model = CalibratedClassifierCV(
            self.svm_model,
            method='sigmoid',  # Platt scaling
            cv='prefit'  # Use pre-fitted model
        )
        self.calibrated_model.fit(X_train, labels)
        print("✅ Probability calibration complete")
        print()

        self.trained = True

        print("="*80)
        print("TRAINING COMPLETE")
        print("="*80)
        print()
        print("Model Details:")
        print(f"  • Feature Type: Character trigrams (3-char sequences)")
        print(f"  • Feature Count: {X_train.shape[1]}")
        print(f"  • Classifier: Linear SVM (C=0.5, balanced)")
        print(f"  • Calibration: Sigmoid (Platt scaling)")
        print(f"  • Training Samples: {len(all_requests)}")
        print()
        print("Improvements over basic SVM:")
        print(f"  • Higher regularization (C=0.5 vs 1.0) → fewer false positives")
        print(f"  • Balanced class weights → better minority class handling")
        print(f"  • Probability calibration → more reliable threshold tuning")
        print()
        print("Expected Performance:")
        print(f"  • Accuracy: 85-88%")
        print(f"  • False Positives: <500 (at optimal threshold)")
        print(f"  • Recall: 85-90%")
        print(f"  • Precision: 82-88%")
        print()

    def predict_proba(self, request_data):
        """
        Get calibrated attack probability for a request

        Returns:
            float: Calibrated probability of being an attack (0-1)
        """
        if not self.trained:
            raise ValueError("Model not trained yet!")

        # Preprocess request
        preprocessed = self.preprocess_request(request_data)

        # Extract features
        X = self.tfidf_vectorizer.transform([preprocessed])

        # Get calibrated probability
        probabilities = self.calibrated_model.predict_proba(X)[0]

        # Return probability of attack class (class 1)
        return probabilities[1]

    def is_anomalous(self, request_data, threshold=0.5):
        """
        Detect if a request is anomalous

        Args:
            request_data: HTTP request (dict or string)
            threshold: Decision threshold (default 0.5, recommend 0.6-0.7 for <500 FP)

        Returns:
            tuple: (is_attack, score, details)
        """
        if not self.trained:
            raise ValueError("Model not trained yet!")

        # Get calibrated probability
        probability = self.predict_proba(request_data)

        # Make decision
        is_attack = probability >= threshold

        # Convert to 0-100 score
        score = probability * 100

        details = {
            'probability': probability,
            'threshold': threshold,
            'score': score,
            'model': 'Improved Linear SVM (Calibrated, C=0.5)'
        }

        return is_attack, score, details

    def save_model(self, filepath):
        """Save trained model to file"""
        if not self.trained:
            print("⚠️  Model not trained yet")
            return False

        try:
            with open(filepath, 'wb') as f:
                pickle.dump(self, f)
            return True
        except Exception as e:
            print(f"❌ Error saving model: {e}")
            return False

    @staticmethod
    def load_model(filepath):
        """Load trained model from file"""
        try:
            with open(filepath, 'rb') as f:
                model = pickle.load(f)
            if model.trained:
                return model
            else:
                print("⚠️  Loaded model is not trained")
                return None
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            return None
