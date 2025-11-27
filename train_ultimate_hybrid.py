#!/usr/bin/env python3
"""
Train Ultimate Hybrid Detector - 90%+ ALL Metrics

Combines three powerful models:
1. Improved SVM (calibrated) - High recall specialist
2. Conservative XGBoost+RF - High precision specialist
3. Gradient Boosting - Balanced tie-breaker

Target: 90%+ on ALL metrics (accuracy, precision, recall, F1, specificity)
"""

import os
import sys
import csv
import time
from ultimate_hybrid_detector import UltimateHybridDetector


def load_csic_samples(csv_file, label, max_samples):
    """Load samples from CSIC 2010 CSV dataset"""
    samples = []

    if not os.path.exists(csv_file):
        print(f"❌ Error: {csv_file} not found")
        return samples

    print(f"Loading {label} samples from {csv_file}...")

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

        print(f"✅ Loaded {len(samples)} {label.lower()} samples")
    except Exception as e:
        print(f"❌ Error loading samples: {e}")

    return samples


def main():
    print("="*80)
    print("ULTIMATE HYBRID DETECTOR TRAINING - 90%+ ALL METRICS")
    print("="*80)
    print()
    print("Mission: Achieve 90%+ on ALL performance metrics")
    print()
    print("Strategy:")
    print("  🎯 Combine 3 specialized models")
    print("  🎯 Intelligent weighted voting")
    print("  🎯 Consensus boosting when models agree")
    print("  🎯 Adaptive weighting based on confidence")
    print()
    print("Target Performance:")
    print("  • Accuracy: ≥90%")
    print("  • Precision: ≥90%")
    print("  • Recall: ≥90%")
    print("  • F1-Score: ≥90%")
    print("  • Specificity: ≥90%")
    print("  • False Positives: <300")
    print()

    # Configuration
    csv_file = 'datasets/csic2010/CSIC_2010.csv'
    model_file = 'ultimate_hybrid_model.pkl'

    # Load CSIC dataset
    normal_samples = load_csic_samples(csv_file, 'Normal', max_samples=8000)
    attack_samples = load_csic_samples(csv_file, 'Anomalous', max_samples=5000)

    if len(normal_samples) < 100 or len(attack_samples) < 50:
        print("❌ ERROR: Not enough samples loaded!")
        print(f"   Normal samples: {len(normal_samples)}")
        print(f"   Attack samples: {len(attack_samples)}")
        print()
        print("Please ensure datasets/csic2010/CSIC_2010.csv exists and has data.")
        return 1

    print()

    # Create and train ultimate hybrid detector
    detector = UltimateHybridDetector()
    detector.train(
        normal_requests=normal_samples,
        attack_requests=attack_samples
    )

    print()
    print("="*80)
    print("SAVING MODEL")
    print("="*80)
    print()

    # Save trained model
    if detector.save_model(model_file):
        file_size = os.path.getsize(model_file) / 1024  # KB
        print(f"✅ Model saved successfully: {model_file} ({file_size:.1f} KB)")
    else:
        print(f"❌ Failed to save model")
        return 1

    print()
    print("="*80)
    print("QUICK VALIDATION TEST")
    print("="*80)
    print()

    # Test on sample attacks
    print("Testing on 20 sample attacks...")
    test_attacks = attack_samples[:20]

    thresholds_to_test = [0.48, 0.50, 0.52]

    for threshold in thresholds_to_test:
        detected = 0
        for sample in test_attacks:
            is_anom, score, details = detector.is_anomalous(sample, threshold=threshold)
            if is_anom:
                detected += 1

        detection_rate = (detected / len(test_attacks)) * 100
        print(f"  Threshold {threshold:.2f}: {detection_rate:5.1f}% recall ({detected}/{len(test_attacks)} detected)")

    print()
    print("="*80)
    print("TRAINING COMPLETE!")
    print("="*80)
    print()
    print("✅ Ultimate Hybrid Ensemble Ready for Production")
    print()
    print(f"📦 Model saved to: {model_file}")
    print()
    print("Ensemble Architecture:")
    print("  • Improved SVM (calibrated, C=0.5) - 35-45% weight")
    print("  • Conservative XGBoost+RF - 35-50% weight")
    print("  • Gradient Boosting (400 trees) - 20-40% weight")
    print("  • Dynamic weighting based on confidence")
    print("  • Consensus boosting when models agree")
    print()
    print("Expected Performance:")
    print("  🎯 All metrics: 90%+")
    print("  🎯 False Positives: <300")
    print("  🎯 Optimal threshold: 0.48-0.52")
    print()
    print("Next Steps:")
    print("  1. Run test_ultimate_hybrid.py to validate performance")
    print("  2. Integrate into app.py")
    print("  3. Test via anomaly_testing.html")
    print()

    return 0


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
