#!/usr/bin/env python3
"""Compare ModSecurity (rule-based) alerts with LLM pipeline alerts.

Reads a ModSecurity audit log and an LLM alert log, maps both to a common
schema, and prints a side-by-side comparison table.  Optionally computes
Precision / Recall / F1 when a ground-truth file is supplied.

Usage examples:
    # Side-by-side comparison from real logs
    python3 compare_ids.py \
        --modsec-log /var/log/modsec_audit.log \
        --llm-log ~/.llm_pipeline/llm_alerts.log

    # With ground-truth labels for metrics
    python3 compare_ids.py \
        --modsec-log /var/log/modsec_audit.log \
        --llm-log ~/.llm_pipeline/llm_alerts.log \
        --ground-truth ground_truth.json
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# ─── OWASP CRS Rule-ID → Attack-Type Mapping ────────────────────────────────
# ModSecurity OWASP CRS organises rules by ID prefix.
CRS_RULE_MAP = {
    "910": "Automated vulnerability scanning",
    "913": "Automated vulnerability scanning",
    "920": "Automated vulnerability scanning",
    "930": "Directory or endpoint enumeration",
    "931": "Directory or endpoint enumeration",
    "932": "Command injection",
    "933": "Command injection",
    "934": "Command injection",
    "941": "Cross-Site Scripting (XSS)",
    "942": "SQL Injection",
    "943": "Brute-force authentication",
    "944": "Command injection",
    "949": None,              # anomaly score – skip
    "950": None,              # outbound – skip
    "951": None,              # outbound – skip
    "959": None,              # anomaly score – skip
    "980": None,              # correlation – skip
}

ATTACK_TYPES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Brute-force authentication",
    "Directory or endpoint enumeration",
    "Command injection",
    "Automated vulnerability scanning",
]

def parse_modsec_audit_log(path):
    """Parse a ModSecurity JSON audit log into a list of alert dicts.

    Expects one JSON object per line, where each object represents a complete
    audit entry with transaction details and matched rules in the 'messages' array.
    
    To configure ModSecurity for JSON output:
        SecAuditLogFormat JSON
    """
    alerts = []
    if not Path(path).exists():
        return alerts

    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Warning: skipping malformed JSON on line {lineno}: {e}", file=sys.stderr)
                continue
            
            # Extract transaction details
            transaction = entry.get("transaction", {})
            request = transaction.get("request", {})
            uri = request.get("uri", "")
            
            # Process each matched rule in the messages array
            messages = transaction.get("messages", [])
            if not messages:
                continue
                
            for msg in messages:
                details = msg.get("details", {})
                rule_id_str = details.get("ruleId", "")
                
                if not rule_id_str or not rule_id_str.isdigit():
                    continue
                
                rule_id = int(rule_id_str)
                prefix = rule_id_str[:3]
                attack_type = CRS_RULE_MAP.get(prefix)
                
                # Skip rules we don't track (anomaly scores, etc.)
                if attack_type is None:
                    continue
                
                # Map numeric severity to descriptive labels
                severity_map = {
                    "0": "EMERGENCY",
                    "1": "ALERT", 
                    "2": "CRITICAL",
                    "3": "ERROR",
                    "4": "WARNING",
                    "5": "NOTICE",
                }
                severity_num = details.get("severity", "")
                severity = severity_map.get(str(severity_num), severity_num or "UNKNOWN")
                
                alerts.append({
                    "source": "ModSecurity",
                    "malicious": True,
                    "attack_type": attack_type,
                    "rule_id": rule_id,
                    "message": msg.get("message", ""),
                    "severity": severity,
                    "uri": uri,
                    "confidence": 1.0,
                })
    
    return alerts


def parse_llm_alert_log(path):
    """Parse the LLM pipeline alert log (one JSON object per line)."""
    alerts = []
    if not Path(path).exists():
        return alerts

    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entry["source"] = "LLM"
                entry.setdefault("malicious", True)
                alerts.append(entry)
            except json.JSONDecodeError:
                print(f"Warning: skipping malformed JSON on line {lineno}", file=sys.stderr)
    return alerts


def summarise_alerts(alerts, label):
    """Produce a per-attack-type summary."""
    counts = Counter()
    for a in alerts:
        at = a.get("attack_type", "Unknown")
        if at and a.get("malicious"):
            counts[at] += 1
    return counts


def print_comparison(modsec_alerts, llm_alerts):
    """Print a side-by-side comparison table."""

    modsec_counts = summarise_alerts(modsec_alerts, "ModSecurity")
    llm_counts = summarise_alerts(llm_alerts, "LLM")

    all_types = sorted(set(list(modsec_counts.keys()) + list(llm_counts.keys()) + ATTACK_TYPES))

    header = f"{'Attack Type':<40} {'ModSecurity':>12} {'LLM':>12} {'Match':>8}"
    print("\n" + "=" * len(header))
    print("  COMPARISON: ModSecurity (Rule-Based) vs LLM Pipeline")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for at in all_types:
        mc = modsec_counts.get(at, 0)
        lc = llm_counts.get(at, 0)
        match = "✓" if mc > 0 and lc > 0 else ("—" if mc == 0 and lc == 0 else "✗")
        print(f"{at:<40} {mc:>12} {lc:>12} {match:>8}")

    print("-" * len(header))
    total_m = sum(modsec_counts.values())
    total_l = sum(llm_counts.values())
    print(f"{'TOTAL':<40} {total_m:>12} {total_l:>12}")
    print("=" * len(header))


def compute_metrics(alerts, ground_truth):
    """Compute per-type Precision, Recall, and F1 against ground truth.

    ground_truth: list of dicts with at least {"attack_type": str, "malicious": bool}
    alerts: list of dicts from either engine
    """
    gt_types = Counter()
    for gt in ground_truth:
        if gt.get("malicious"):
            gt_types[gt["attack_type"]] += 1

    pred_types = Counter()
    for a in alerts:
        if a.get("malicious"):
            pred_types[a.get("attack_type", "Unknown")] += 1

    all_types = sorted(set(list(gt_types.keys()) + list(pred_types.keys())))

    results = {}
    for at in all_types:
        tp = min(gt_types.get(at, 0), pred_types.get(at, 0))
        fp = max(0, pred_types.get(at, 0) - gt_types.get(at, 0))
        fn = max(0, gt_types.get(at, 0) - pred_types.get(at, 0))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        results[at] = {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}

    return results


def print_metrics(metrics, engine_name):
    """Print a metrics table."""
    header = f"{'Attack Type':<40} {'Prec':>8} {'Recall':>8} {'F1':>8} {'TP':>6} {'FP':>6} {'FN':>6}"
    print(f"\n--- Metrics: {engine_name} ---")
    print(header)
    print("-" * len(header))
    for at in sorted(metrics.keys()):
        m = metrics[at]
        print(f"{at:<40} {m['precision']:>8.2f} {m['recall']:>8.2f} {m['f1']:>8.2f} {m['tp']:>6} {m['fp']:>6} {m['fn']:>6}")
    print("-" * len(header))


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare ModSecurity and LLM pipeline alerts."
    )
    parser.add_argument(
        "--modsec-log",
        default="/var/log/apache2/modsec_audit.log",
        help="Path to the ModSecurity serial audit log",
    )
    parser.add_argument(
        "--llm-log",
        default=str(Path.home() / ".llm_pipeline" / "llm_alerts.log"),
        help="Path to the LLM pipeline alert log",
    )
    parser.add_argument(
        "--ground-truth",
        default=None,
        help="Optional JSON file with ground-truth labels for metrics",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"Reading ModSecurity log: {args.modsec_log}")
    modsec_alerts = parse_modsec_audit_log(args.modsec_log)
    print(f"  → {len(modsec_alerts)} alert(s) parsed")

    print(f"Reading LLM alert log:   {args.llm_log}")
    llm_alerts = parse_llm_alert_log(args.llm_log)
    print(f"  → {len(llm_alerts)} alert(s) parsed")

    print_comparison(modsec_alerts, llm_alerts)

    if args.ground_truth:
        gt_path = Path(args.ground_truth)
        if not gt_path.exists():
            print(f"Error: ground-truth file not found: {gt_path}", file=sys.stderr)
            return 1

        with open(gt_path, encoding="utf-8") as fh:
            ground_truth = json.load(fh)

        if not isinstance(ground_truth, list):
            ground_truth = ground_truth.get("findings", [])

        modsec_metrics = compute_metrics(modsec_alerts, ground_truth)
        llm_metrics = compute_metrics(llm_alerts, ground_truth)

        print_metrics(modsec_metrics, "ModSecurity")
        print_metrics(llm_metrics, "LLM Pipeline")

    return 0


if __name__ == "__main__":
    sys.exit(main())
