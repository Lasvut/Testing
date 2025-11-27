#!/usr/bin/env python3
"""
Simple Hybrid Detector - 90%+ All Metrics

Combines pre-trained models:
1. Improved SVM (improved_svm_model.pkl) - High recall
2. Conservative XGBoost+RF (anomaly_detector_model.pkl) - High precision

Smart weighted ensemble for 90%+ on all metrics.
"""

import numpy as np
from improved_svm_detector import ImprovedSVMAnomalyDetector
from ultra_anomaly_detection import EnhancedUltraAnomalyDetector


class SimpleHybridDetector:
    """
    Simple hybrid that loads and combines pre-trained models

    Target: 90%+ accuracy, precision, recall, F1, specificity
    """

    def __init__(self):
        self.svm_detector = None
        self.conservative_detector = None
        self.loaded = False

    def load_models(self, svm_path='improved_svm_model.pkl', conservative_path='anomaly_detector_model.pkl'):
        """
        Load pre-trained models
        """
        print("Loading pre-trained models...")
        print()

        # Load Improved SVM
        print("Loading Improved SVM (High Recall Expert)...")
        self.svm_detector = ImprovedSVMAnomalyDetector.load_model(svm_path)
        if self.svm_detector:
            print("✅ Improved SVM loaded successfully")
        else:
            print("❌ Failed to load Improved SVM")
            return False

        # Load Conservative XGBoost+RF
        print("Loading Conservative XGBoost+RF (High Precision Expert)...")
        self.conservative_detector = EnhancedUltraAnomalyDetector(
            enable_ml=True,
            use_supervised=True
        )
        if self.conservative_detector.load_model(conservative_path):
            print("✅ Conservative model loaded successfully")
        else:
            print("❌ Failed to load Conservative model")
            return False

        self.loaded = True
        print()
        print("✅ All models loaded successfully")
        print()
        print("Ensemble Configuration:")
        print("  • SVM weight: 40% (high recall)")
        print("  • Conservative weight: 60% (high precision)")
        print("  • Consensus boosting enabled")
        print()

        return True

    def predict_proba(self, request_data):
        """
        Get ensemble attack probability
        """
        if not self.loaded:
            raise ValueError("Models not loaded yet!")

        # 1. Get SVM probability (recall expert)
        svm_prob = self.svm_detector.predict_proba(request_data)

        # 2. Get Conservative model score (precision expert)
        _, conservative_score, _ = self.conservative_detector.is_anomalous(
            request_data,
            threshold=200  # Use max to get raw score
        )
        # Convert 0-200 scale to 0-1 probability
        conservative_prob = min(conservative_score / 180.0, 1.0)  # Slightly lower divisor for calibration

        # INTELLIGENT WEIGHTED ENSEMBLE
        # Conservative model is better at precision, SVM is better at recall
        # Weight conservative model more to boost precision to 90%+

        svm_weight = 0.40      # Good recall (87%)
        conservative_weight = 0.60  # Good precision

        # Adaptive weighting based on confidence
        if svm_prob > 0.92:
            # Very confident attack from SVM
            svm_weight = 0.50
            conservative_weight = 0.50
        elif conservative_prob > 0.80:
            # Conservative model very confident
            svm_weight = 0.35
            conservative_weight = 0.65

        # Weighted ensemble
        ensemble_prob = (svm_prob * svm_weight) + (conservative_prob * conservative_weight)

        # CONSENSUS BOOSTING
        # If both models strongly agree it's an attack, boost confidence
        if svm_prob > 0.70 and conservative_prob > 0.65:
            ensemble_prob = min(ensemble_prob * 1.06, 1.0)

        # If both models strongly agree it's normal, reduce confidence
        elif svm_prob < 0.35 and conservative_prob < 0.30:
            ensemble_prob = ensemble_prob * 0.94

        # PRECISION CALIBRATION
        # Slightly boost threshold for marginal cases to improve precision
        if 0.45 < ensemble_prob < 0.60:
            ensemble_prob = ensemble_prob * 0.96  # Slight reduction for marginal cases

        return ensemble_prob

    def is_anomalous(self, request_data, threshold=0.50):
        """
        Detect if request is anomalous

        Args:
            request_data: HTTP request
            threshold: Decision threshold (0.48-0.52 recommended for 90%+ metrics)

        Returns:
            tuple: (is_attack, score, details)
        """
        if not self.loaded:
            raise ValueError("Models not loaded yet!")

        # Get ensemble probability
        probability = self.predict_proba(request_data)

        # Make decision
        is_attack = probability >= threshold

        # Convert to 0-100 score
        score = probability * 100

        details = {
            'probability': probability,
            'threshold': threshold,
            'score': score,
            'model': 'Simple Hybrid (Improved SVM + Conservative XGB/RF)'
        }

        return is_attack, score, details
