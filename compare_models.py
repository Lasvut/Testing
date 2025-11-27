#!/usr/bin/env python3
"""
Compare Model Performance:
1. Linear SVM Only (99.75% claimed)
2. Hybrid Ensemble (SVM + XGBoost + RF)
3. Conservative XGBoost+RF Only

Tests on full CSIC dataset to find the best performer
"""

import os
import csv
import time
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from urllib.parse import unquote


def load_csic_samples(csv_file, label, max_samples=10000):
    """Load samples from CSIC 2010 CSV dataset"""
    samples = []

    if not os.path.exists(csv_file):
        print(f"❌ Error: {csv_file} not found")
        return samples

    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header

            for row in reader:
                if len(row) >= 3 and row[0].strip() == label:
                    url = row[-1].strip()
                    samples.append({
                        'ip': '192.168.1.100' if label == 'Normal' else '10.0.0.100',
                        'path': '',
                        'payload': url,
                        'timestamp': time.time()
                    })

                    if len(samples) >= max_samples:
                        break

    except Exception as e:
        print(f"❌ Error loading samples: {e}")

    return samples


def preprocess_request(request_data):
    """Preprocess like the 99.75% accuracy approach"""
    if isinstance(request_data, dict):
        path = request_data.get('path', '')
        payload = request_data.get('payload', '')
        request_str = f"{path}?{payload}" if payload else path
    else:
        request_str = str(request_data)

    request_str = unquote(request_str)
    request_str = request_str.lower()

    return request_str


def evaluate_model(y_true, y_pred, model_name):
    """Calculate and display metrics"""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    accuracy = accuracy_score(y_true, y_pred) * 100
    precision = precision_score(y_true, y_pred) * 100
    recall = recall_score(y_true, y_pred) * 100
    f1 = f1_score(y_true, y_pred) * 100
    specificity = (tn / (tn + fp)) * 100 if (tn + fp) > 0 else 0

    print(f"\n{'='*80}")
    print(f"{model_name} RESULTS")
    print(f"{'='*80}")
    print(f"Confusion Matrix:")
    print(f"  TP (Detected attacks):    {tp:5d}")
    print(f"  FP (False positives):     {fp:5d}  ← LOWER IS BETTER")
    print(f"  TN (Normal passed):       {tn:5d}")
    print(f"  FN (Missed attacks):      {fn:5d}")
    print()
    print(f"Performance Metrics:")
    print(f"  {'Accuracy:':<20} {accuracy:6.2f}%  {'✅' if accuracy >= 90 else '⚠️'}")
    print(f"  {'Precision:':<20} {precision:6.2f}%  {'✅' if precision >= 90 else '⚠️'}")
    print(f"  {'Recall:':<20} {recall:6.2f}%  {'✅' if recall >= 90 else '⚠️'}")
    print(f"  {'F1-Score:':<20} {f1:6.2f}%  {'✅' if f1 >= 90 else '⚠️'}")
    print(f"  {'Specificity:':<20} {specificity:6.2f}%  {'✅' if specificity >= 90 else '⚠️'}")
    print(f"{'='*80}")

    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'specificity': specificity,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn
    }


def main():
    print("="*80)
    print("MODEL COMPARISON TEST")
    print("="*80)
    print()
    print("Testing:")
    print("  1️⃣  Linear SVM Only (character trigrams) - 99.75% claimed")
    print("  2️⃣  Hybrid Model (SVM + XGBoost + RF)")
    print("  3️⃣  Conservative Model (XGBoost + RF only)")
    print()

    csv_file = 'datasets/csic2010/CSIC_2010.csv'

    # Load data
    print("Loading CSIC 2010 dataset...")
    normal_samples = load_csic_samples(csv_file, 'Normal', max_samples=7000)
    attack_samples = load_csic_samples(csv_file, 'Anomalous', max_samples=4500)

    print(f"✅ Loaded {len(normal_samples)} normal samples")
    print(f"✅ Loaded {len(attack_samples)} attack samples")
    print()

    # Split data: 70% train, 30% test
    train_size_normal = int(len(normal_samples) * 0.7)
    train_size_attack = int(len(attack_samples) * 0.7)

    train_normal = normal_samples[:train_size_normal]
    test_normal = normal_samples[train_size_normal:]
    train_attack = attack_samples[:train_size_attack]
    test_attack = attack_samples[train_size_attack:]

    print(f"Training: {len(train_normal)} normal + {len(train_attack)} attack")
    print(f"Testing:  {len(test_normal)} normal + {len(test_attack)} attack")
    print()

    # Prepare test data
    all_test = test_normal + test_attack
    y_test = [0] * len(test_normal) + [1] * len(test_attack)

    # ========================================
    # MODEL 1: Linear SVM Only (99.75% approach)
    # ========================================
    print("="*80)
    print("[1/3] Training Linear SVM with Character Trigrams...")
    print("="*80)

    # Prepare training data
    all_train = train_normal + train_attack
    y_train = [0] * len(train_normal) + [1] * len(train_attack)

    # Preprocess
    train_preprocessed = [preprocess_request(req) for req in all_train]
    test_preprocessed = [preprocess_request(req) for req in all_test]

    # TF-IDF Vectorization
    tfidf = TfidfVectorizer(
        min_df=0.0,
        analyzer="char",
        sublinear_tf=True,
        ngram_range=(3, 3),
        max_features=10000
    )

    X_train_tfidf = tfidf.fit_transform(train_preprocessed)
    X_test_tfidf = tfidf.transform(test_preprocessed)

    print(f"✅ Extracted {X_train_tfidf.shape[1]} trigram features")

    # Train SVM
    svm_model = LinearSVC(C=1.0, max_iter=2000, random_state=42)
    svm_model.fit(X_train_tfidf, y_train)
    print("✅ Linear SVM trained")

    # Predict
    y_pred_svm = svm_model.predict(X_test_tfidf)

    # Evaluate
    svm_results = evaluate_model(y_test, y_pred_svm, "LINEAR SVM ONLY (99.75% Approach)")

    # ========================================
    # MODEL 2: Hybrid Model (if exists)
    # ========================================
    print("\n\n")
    print("="*80)
    print("[2/3] Testing Hybrid Model (SVM + XGBoost + RF)...")
    print("="*80)

    hybrid_results = None
    try:
        from hybrid_svm_detector import HybridSVMAnomalyDetector

        if os.path.exists('hybrid_svm_model.pkl'):
            print("Loading pre-trained hybrid model...")
            hybrid_detector = HybridSVMAnomalyDetector.load_model('hybrid_svm_model.pkl')

            if hybrid_detector:
                print("✅ Hybrid model loaded")

                # Predict
                y_pred_hybrid = []
                for req in all_test:
                    is_attack, _, _ = hybrid_detector.is_anomalous(req, threshold=0.5)
                    y_pred_hybrid.append(1 if is_attack else 0)

                # Evaluate
                hybrid_results = evaluate_model(y_test, y_pred_hybrid, "HYBRID MODEL (SVM + XGB + RF)")
            else:
                print("⚠️  Could not load hybrid model")
        else:
            print("⚠️  Hybrid model not found (hybrid_svm_model.pkl)")
    except Exception as e:
        print(f"⚠️  Error testing hybrid model: {e}")

    # ========================================
    # MODEL 3: Conservative Model (XGB+RF only)
    # ========================================
    print("\n\n")
    print("="*80)
    print("[3/3] Testing Conservative Model (XGBoost + RF)...")
    print("="*80)

    conservative_results = None
    try:
        from ultra_anomaly_detection import EnhancedUltraAnomalyDetector

        if os.path.exists('anomaly_detector_model.pkl'):
            print("Loading pre-trained conservative model...")
            conservative_detector = EnhancedUltraAnomalyDetector(enable_ml=True, use_supervised=True)

            if conservative_detector.load_model('anomaly_detector_model.pkl'):
                print("✅ Conservative model loaded")

                # Predict
                y_pred_conservative = []
                for req in all_test:
                    is_attack, _, _ = conservative_detector.is_anomalous(req, threshold=80)
                    y_pred_conservative.append(1 if is_attack else 0)

                # Evaluate
                conservative_results = evaluate_model(y_test, y_pred_conservative, "CONSERVATIVE MODEL (XGB + RF)")
            else:
                print("⚠️  Could not load conservative model")
        else:
            print("⚠️  Conservative model not found (anomaly_detector_model.pkl)")
    except Exception as e:
        print(f"⚠️  Error testing conservative model: {e}")

    # ========================================
    # COMPARISON SUMMARY
    # ========================================
    print("\n\n")
    print("="*80)
    print("FINAL COMPARISON")
    print("="*80)
    print()

    models = []
    if svm_results:
        models.append(("Linear SVM Only", svm_results))
    if hybrid_results:
        models.append(("Hybrid Ensemble", hybrid_results))
    if conservative_results:
        models.append(("Conservative XGB+RF", conservative_results))

    print(f"{'Model':<25} {'Acc':<8} {'Prec':<8} {'Rec':<8} {'F1':<8} {'Spec':<8} {'FP':<8}")
    print("-"*80)

    best_model = None
    best_score = 0

    for name, results in models:
        # Calculate composite score (accuracy + low FP penalty)
        fp_penalty = results['fp'] / 100  # Penalize false positives
        composite = results['accuracy'] - fp_penalty

        status = "👑 BEST" if composite > best_score else ""
        if composite > best_score:
            best_score = composite
            best_model = name

        print(f"{name:<25} "
              f"{results['accuracy']:>6.2f}% "
              f"{results['precision']:>6.2f}% "
              f"{results['recall']:>6.2f}% "
              f"{results['f1']:>6.2f}% "
              f"{results['specificity']:>6.2f}% "
              f"{results['fp']:>6d}  {status}")

    print("="*80)
    print()
    print(f"🏆 WINNER: {best_model}")
    print()
    print("Recommendation:")
    if best_model == "Linear SVM Only":
        print("  ✅ Use Linear SVM Only - Highest accuracy, proven 99.75% approach")
        print("  📦 File: Use simple SVM model")
        print("  💡 Benefits: Lightweight, fast, proven performance")
    elif best_model == "Hybrid Ensemble":
        print("  ✅ Use Hybrid Model - Best overall performance")
        print("  📦 File: hybrid_svm_model.pkl")
        print("  💡 Benefits: Combines multiple approaches, robust")
    elif best_model == "Conservative XGB+RF":
        print("  ✅ Use Conservative Model - Best for low false positives")
        print("  📦 File: anomaly_detector_model.pkl")
        print("  💡 Benefits: Very low FP rate, behavioral analysis")

    return 0


if __name__ == '__main__':
    try:
        exit_code = main()
        import sys
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        import sys
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        import sys
        sys.exit(1)
