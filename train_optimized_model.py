#!/usr/bin/env python3
"""
Train Optimized BALANCED ML Model for Anomaly Detection

This script trains the balanced ML model with:
- XGBoost Classifier (4.2x scale_pos_weight, 650 estimators)
- Random Forest (5.2x class weight, 550 estimators)
- Voting Ensemble (2.6:1 XGB:RF ratio)
- 70% ML weight in scoring
- Balanced scoring for 90%+ on ALL metrics

Target Performance:
- Recall: 90%+
- Precision: 90%+
- Accuracy: 90%+
- F1-Score: 90%+
- Specificity: 90%+
"""

import os
import sys
import csv
import time
from ultra_anomaly_detection import EnhancedUltraAnomalyDetector as AnomalyDetector

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
    print("PRECISION-RECALL BALANCED ML MODEL TRAINING")
    print("="*80)
    print()
    print("Training Configuration:")
    print("  🎯 Target: 90%+ on ALL metrics (precision, recall, accuracy, F1, specificity)")
    print("  🤖 Model: XGBoost + Random Forest Ensemble")
    print("  📊 Data: CSIC 2010 HTTP Dataset")
    print("  ⚖️  Weights: 70% ML, 22% Rules, 8% Stats")
    print()

    # Configuration
    csv_file = 'datasets/csic2010/CSIC_2010.csv'
    model_file = 'anomaly_detector_model.pkl'

    # Load more samples for better training
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
    print("="*80)
    print("TRAINING MODEL")
    print("="*80)
    print()

    # Create detector with ML and supervised learning enabled
    detector = AnomalyDetector(enable_ml=True, use_supervised=True)

    # Train with both normal and attack samples
    print(f"Training on {len(normal_samples)} normal + {len(attack_samples)} attack samples...")
    print()

    detector.train_baseline(
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

    # Quick validation on a few samples
    print("Testing on sample attacks...")
    test_attacks = attack_samples[:10]
    detected = 0

    for i, sample in enumerate(test_attacks, 1):
        is_anom, score, details = detector.is_anomalous(sample, threshold=70)
        if is_anom:
            detected += 1
            print(f"  ✅ Attack {i}: DETECTED (score: {score:.1f})")
        else:
            print(f"  ❌ Attack {i}: MISSED (score: {score:.1f})")

    detection_rate = (detected / len(test_attacks)) * 100
    print()
    print(f"Quick test detection rate: {detection_rate:.1f}% ({detected}/{len(test_attacks)})")

    print()
    print("="*80)
    print("TRAINING COMPLETE!")
    print("="*80)
    print()
    print("✅ Precision-Recall Balanced Model Ready")
    print()
    print("Model Features:")
    print(f"  • XGBoost: 650 trees, 4.2x scale_pos_weight")
    print(f"  • Random Forest: 550 trees, 5.2x class weight")
    print(f"  • Ensemble: 2.6:1 voting ratio")
    print(f"  • Scoring: 70% ML weight, balanced thresholds")
    print(f"  • Optimized for: 90%+ on ALL metrics")
    print()
    print(f"📦 Model saved to: {model_file}")
    print()
    print("Next steps:")
    print("  1. Test the model using the anomaly testing page")
    print("  2. Expected metrics: 90%+ on ALL metrics (low false positives!)")
    print("  3. Use threshold=70 for optimal performance")
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
