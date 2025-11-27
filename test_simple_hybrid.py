#!/usr/bin/env python3
"""
Test Simple Hybrid Detector - Find 90%+ Sweet Spot

Tests combination of:
- Improved SVM (high recall)
- Conservative XGBoost+RF (high precision)

Goal: Find threshold that achieves 90%+ on ALL metrics
"""

import os
import csv
import time
from simple_hybrid_detector import SimpleHybridDetector
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


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


def evaluate_threshold(detector, test_samples, y_test, threshold):
    """Evaluate model at specific threshold"""
    y_pred = []

    for sample in test_samples:
        is_attack, _, _ = detector.is_anomalous(sample, threshold=threshold)
        y_pred.append(1 if is_attack else 0)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    accuracy = accuracy_score(y_test, y_pred) * 100
    precision = precision_score(y_test, y_pred) * 100 if (tp + fp) > 0 else 0
    recall = recall_score(y_test, y_pred) * 100 if (tp + fn) > 0 else 0
    f1 = f1_score(y_test, y_pred) * 100
    specificity = (tn / (tn + fp)) * 100 if (tn + fp) > 0 else 0

    return {
        'threshold': threshold,
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
    print("SIMPLE HYBRID DETECTOR - 90%+ ALL METRICS TEST")
    print("="*80)
    print()
    print("Strategy: Combine Improved SVM + Conservative XGBoost+RF")
    print()
    print("Target Performance:")
    print("  🎯 Accuracy: ≥90%")
    print("  🎯 Precision: ≥90%")
    print("  🎯 Recall: ≥90%")
    print("  🎯 F1-Score: ≥90%")
    print("  🎯 Specificity: ≥90%")
    print()

    # Load detector
    detector = SimpleHybridDetector()

    if not detector.load_models():
        print("❌ Failed to load models")
        print()
        print("Required files:")
        print("  • improved_svm_model.pkl")
        print("  • anomaly_detector_model.pkl")
        print()
        print("Run these scripts first:")
        print("  python3 train_improved_svm.py")
        print("  python3 train_optimized_model.py")
        return 1

    # Load test data
    csv_file = 'datasets/csic2010/CSIC_2010.csv'

    print("Loading CSIC 2010 dataset...")
    normal_samples = load_csic_samples(csv_file, 'Normal', max_samples=7000)
    attack_samples = load_csic_samples(csv_file, 'Anomalous', max_samples=4500)

    print(f"✅ Loaded {len(normal_samples)} normal samples")
    print(f"✅ Loaded {len(attack_samples)} attack samples")
    print()

    # Use 70/30 split
    train_size_normal = int(len(normal_samples) * 0.7)
    train_size_attack = int(len(attack_samples) * 0.7)

    test_normal = normal_samples[train_size_normal:]
    test_attack = attack_samples[train_size_attack:]

    all_test = test_normal + test_attack
    y_test = [0] * len(test_normal) + [1] * len(test_attack)

    print(f"Test set: {len(test_normal)} normal + {len(test_attack)} attack = {len(all_test)} total")
    print()

    # Test range of thresholds to find 90%+ sweet spot
    print("="*80)
    print("THRESHOLD SWEEP - Finding 90%+ Sweet Spot")
    print("="*80)
    print()

    thresholds = [0.42, 0.44, 0.46, 0.48, 0.50, 0.52, 0.54, 0.56, 0.58, 0.60]

    print(f"{'Thresh':<8} {'Acc':<8} {'Prec':<8} {'Rec':<8} {'F1':<8} {'Spec':<8} {'FP':<8} {'Status':<20}")
    print("-"*90)

    best_result = None
    best_composite = 0

    for threshold in thresholds:
        result = evaluate_threshold(detector, all_test, y_test, threshold)

        # Check if meets ALL targets
        meets_all = (
            result['accuracy'] >= 90 and
            result['precision'] >= 90 and
            result['recall'] >= 90 and
            result['f1'] >= 90 and
            result['specificity'] >= 90
        )

        # Check how many targets met
        targets_met = sum([
            result['accuracy'] >= 90,
            result['precision'] >= 90,
            result['recall'] >= 90,
            result['f1'] >= 90,
            result['specificity'] >= 90
        ])

        status = ""
        if meets_all:
            status = "✅ ALL 90%+ TARGETS!"
        elif targets_met >= 4:
            status = f"✅ {targets_met}/5 targets"
        elif targets_met >= 3:
            status = f"⚠️  {targets_met}/5 targets"

        # Calculate composite score (all metrics must be close to 90%)
        composite = min(
            result['accuracy'],
            result['precision'],
            result['recall'],
            result['f1'],
            result['specificity']
        )

        if composite > best_composite:
            best_composite = composite
            best_result = result

        print(f"{result['threshold']:<8.2f} "
              f"{result['accuracy']:>6.2f}% "
              f"{result['precision']:>6.2f}% "
              f"{result['recall']:>6.2f}% "
              f"{result['f1']:>6.2f}% "
              f"{result['specificity']:>6.2f}% "
              f"{result['fp']:>6d}  {status}")

    print("="*90)
    print()

    # Summary
    print("="*80)
    print("RESULTS SUMMARY")
    print("="*80)
    print()

    if best_result:
        print(f"🏆 BEST THRESHOLD: {best_result['threshold']:.2f}")
        print()
        print("Performance at Best Threshold:")
        print(f"  {'Accuracy:':<20} {best_result['accuracy']:6.2f}%  {'✅' if best_result['accuracy'] >= 90 else '⚠️  Need ' + str(round(90 - best_result['accuracy'], 1)) + '%'}")
        print(f"  {'Precision:':<20} {best_result['precision']:6.2f}%  {'✅' if best_result['precision'] >= 90 else '⚠️  Need ' + str(round(90 - best_result['precision'], 1)) + '%'}")
        print(f"  {'Recall:':<20} {best_result['recall']:6.2f}%  {'✅' if best_result['recall'] >= 90 else '⚠️  Need ' + str(round(90 - best_result['recall'], 1)) + '%'}")
        print(f"  {'F1-Score:':<20} {best_result['f1']:6.2f}%  {'✅' if best_result['f1'] >= 90 else '⚠️  Need ' + str(round(90 - best_result['f1'], 1)) + '%'}")
        print(f"  {'Specificity:':<20} {best_result['specificity']:6.2f}%  {'✅' if best_result['specificity'] >= 90 else '⚠️  Need ' + str(round(90 - best_result['specificity'], 1)) + '%'}")
        print()
        print("Confusion Matrix:")
        print(f"  True Positives:     {best_result['tp']:5d}")
        print(f"  False Positives:    {best_result['fp']:5d}  {'✅ <300' if best_result['fp'] < 300 else ('✅ <500' if best_result['fp'] < 500 else '⚠️')}")
        print(f"  True Negatives:     {best_result['tn']:5d}")
        print(f"  False Negatives:    {best_result['fn']:5d}")
        print()

        # Check if all targets met
        all_90_plus = all([
            best_result['accuracy'] >= 90,
            best_result['precision'] >= 90,
            best_result['recall'] >= 90,
            best_result['f1'] >= 90,
            best_result['specificity'] >= 90
        ])

        if all_90_plus:
            print("🎉 SUCCESS: ALL TARGETS ACHIEVED! 90%+ ON ALL METRICS!")
            print()
            print("Recommendation:")
            print(f"  • Use threshold {best_result['threshold']:.2f} (or {int(best_result['threshold'] * 100)} in UI)")
            print(f"  • Expected performance: ALL metrics 90%+")
            print(f"  • False positives: ~{best_result['fp']} (excellent!)")
        else:
            print("⚠️  CLOSE BUT NOT QUITE: Some metrics below 90%")
            print()
            print("Closest Result:")
            print(f"  • Threshold {best_result['threshold']:.2f} achieves {best_composite:.1f}% minimum")
            print()
            print("To reach 90%+ on ALL metrics, consider:")
            print("  • Fine-tuning ensemble weights")
            print("  • Adding more training data")
            print("  • Additional feature engineering")

    print()
    print("="*80)

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
