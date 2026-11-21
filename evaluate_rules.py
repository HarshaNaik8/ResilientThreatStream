"""
evaluate_rules.py — Offline Evaluation of the Heuristic Threat Detector.

CRITICAL EVALUATION POLICY:
1. Predictions are generated strictly from metadata (ttl, total_len, protocol, t_delta).
2. The ground-truth 'label' is isolated and accessed only during post-prediction evaluation.
3. Zero Data Leakage: detect_threat() is called without knowledge of the label.
"""

import argparse
import csv
import os
import sys
from collections import Counter
from threat_detector import detect_threat, DetectorConfig


def safe_int(value):
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None
    try:
        return int(val_str)
    except ValueError:
        try:
            return int(float(val_str))
        except ValueError:
            return None


def safe_float(value):
    if value is None:
        return None
    val_str = str(value).strip()
    if not val_str:
        return None
    try:
        return float(val_str)
    except ValueError:
        return None


def run_evaluation(csv_path: str, config: DetectorConfig = None):
    if not os.path.isfile(csv_path):
        print(f"Error: Dataset file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    if config is None:
        config = DetectorConfig()

    total_scanned = 0
    excluded_records = 0
    evaluated_records = 0

    tp = 0  # Predicted Attack (1), Ground Truth Attack (1)
    fp = 0  # Predicted Attack (1), Ground Truth Benign (0)
    tn = 0  # Predicted Benign (0), Ground Truth Benign (0)
    fn = 0  # Predicted Benign (0), Ground Truth Attack (1)

    rule_trigger_counts = Counter()
    class_eval_counts = Counter()
    class_detected_counts = Counter()

    print(f"[Evaluation] Scanning '{csv_path}' incrementally...")

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_scanned += 1

            # ---------------------------------------------------------
            # Step 1: Extract ONLY allowed metadata fields for detector
            # ---------------------------------------------------------
            ttl = safe_int(row.get("ttl"))
            total_len = safe_int(row.get("total_len"))
            protocol = (row.get("protocol") or "").strip().lower()
            t_delta = safe_float(row.get("t_delta"))

            # ---------------------------------------------------------
            # Step 2: Generate Prediction WITHOUT ground-truth label
            # ---------------------------------------------------------
            detection_result = detect_threat(
                ttl=ttl,
                total_len=total_len,
                protocol=protocol,
                t_delta=t_delta,
                config=config
            )
            predicted_attack = detection_result["predicted_attack"]

            for r_name in detection_result["triggered_rules"]:
                rule_trigger_counts[r_name] += 1

            # ---------------------------------------------------------
            # Step 3: Access Ground-Truth Label ONLY for evaluation
            # ---------------------------------------------------------
            raw_label = (row.get("label") or "").strip()
            if not raw_label or raw_label.upper() == "UNKNOWN":
                excluded_records += 1
                continue

            evaluated_records += 1
            norm_label = raw_label.upper()
            ground_truth_attack = 0 if norm_label == "BENIGN" else 1

            class_eval_counts[raw_label] += 1
            if predicted_attack == 1:
                class_detected_counts[raw_label] += 1

            # ---------------------------------------------------------
            # Step 4: Populate Confusion Matrix
            # ---------------------------------------------------------
            if predicted_attack == 1 and ground_truth_attack == 1:
                tp += 1
            elif predicted_attack == 1 and ground_truth_attack == 0:
                fp += 1
            elif predicted_attack == 0 and ground_truth_attack == 0:
                tn += 1
            elif predicted_attack == 0 and ground_truth_attack == 1:
                fn += 1

    # -------------------------------------------------------------
    # Step 5: Metric Calculations with Safe Zero-Division Handling
    # -------------------------------------------------------------
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    accuracy = ((tp + tn) / evaluated_records) if evaluated_records > 0 else 0.0

    total_ground_truth_attacks = tp + fn
    total_ground_truth_benign = tn + fp
    total_predicted_alerts = tp + fp

    # -------------------------------------------------------------
    # Step 6: Formatted Reporting
    # -------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  OFFLINE EVALUATION REPORT — RULE-BASED THREAT DETECTOR")
    print("=" * 70)
    print(f"Dataset path:             {csv_path}")
    print(f"Total rows scanned:       {total_scanned:,}")
    print(f"Evaluated rows:           {evaluated_records:,}")
    print(f"Excluded / Missing rows:  {excluded_records:,}")
    print("-" * 70)
    print("CLASS DISTRIBUTION (Ground Truth):")
    print(f"  Benign records:         {total_ground_truth_benign:,} ({total_ground_truth_benign/evaluated_records*100:.2f}%)")
    print(f"  Attack records:         {total_ground_truth_attacks:,} ({total_ground_truth_attacks/evaluated_records*100:.2f}%)")
    print(f"  Total predicted alerts: {total_predicted_alerts:,} ({total_predicted_alerts/evaluated_records*100:.2f}%)")
    print("-" * 70)
    print("CONFUSION MATRIX:")
    print("                      Actual Attack (1)     Actual Benign (0)")
    print(f"Predicted Alert  (1):    TP = {tp:<6d}           FP = {fp:<6d}")
    print(f"Predicted Normal (0):    FN = {fn:<6d}           TN = {tn:<6d}")
    print("-" * 70)
    print("EVALUATION METRICS:")
    print(f"  Precision:              {precision:.4f}  (TP / [TP + FP])")
    print(f"  Recall (TPR):           {recall:.4f}  (TP / [TP + FN])")
    print(f"  F1-Score:               {f1:.4f}")
    print(f"  False Positive Rate:    {fpr:.4f}  (FP / [FP + TN])")
    print(f"  Accuracy (Reference):   {accuracy:.4f}")
    print("-" * 70)
    print("HEURISTIC RULE TRIGGER COUNTS:")
    for r_name, r_cnt in rule_trigger_counts.most_common():
        print(f"  - {r_name:<25}: {r_cnt:,} times")
    print("-" * 70)
    print("PER-ATTACK CLASS DETECTION RECALL (Breakdown by Ground-Truth Label):")
    print(f"  {'Attack Class':<30} {'Detected / Total':<18} {'Recall':<10}")
    print(f"  {'-'*28} {'-'*16} {'-'*8}")
    for lbl, total in class_eval_counts.most_common():
        if lbl.upper() == "BENIGN":
            continue
        det = class_detected_counts.get(lbl, 0)
        rec_class = (det / total * 100) if total > 0 else 0.0
        print(f"  {lbl:<30} {det:>5d} / {total:<5d}      {rec_class:>6.2f}%")
    print("=" * 70 + "\n")

    return {
        "total_scanned": total_scanned,
        "evaluated_records": evaluated_records,
        "excluded_records": excluded_records,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "accuracy": accuracy,
        "total_ground_truth_attacks": total_ground_truth_attacks,
        "total_ground_truth_benign": total_ground_truth_benign,
        "total_predicted_alerts": total_predicted_alerts,
        "class_eval_counts": dict(class_eval_counts),
        "class_detected_counts": dict(class_detected_counts)
    }


def main():
    parser = argparse.ArgumentParser(
        description="Offline evaluation for rule-based threat detector."
    )
    parser.add_argument(
        "--input",
        default="data/stream_sample_10k.csv",
        help="Path to CSV dataset sample (default: data/stream_sample_10k.csv)",
    )
    parser.add_argument(
        "--burst-delta",
        type=float,
        default=0.00005,
        help="Burst delta threshold in seconds (default: 0.00005)",
    )
    parser.add_argument(
        "--max-len",
        type=int,
        default=1500,
        help="Max normal packet length MTU (default: 1500)",
    )
    args = parser.parse_args()

    input_path = args.input
    if not os.path.exists(input_path):
        script_rel = os.path.join(os.path.dirname(os.path.abspath(__file__)), input_path)
        if os.path.exists(script_rel):
            input_path = script_rel

    cfg = DetectorConfig(
        burst_delta_threshold=args.burst_delta,
        max_packet_len=args.max_len
    )

    run_evaluation(input_path, config=cfg)


if __name__ == "__main__":
    main()
