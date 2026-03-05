#!/usr/bin/env python3

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

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
    "949": None,   
    "950": None,   
    "951": None,  
    "959": None,   
    "980": None,   
}

_UID_RE = re.compile(r'"([A-Za-z0-9@_-]{20,})"\s*$')

_REQUEST_RE = re.compile(r'"(\w+ \S+ HTTP/\S+)"')



def parse_access_log(path, n_lines=0):
    entries = {}
    if not Path(path).exists():
        return entries

    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    if n_lines > 0:
        lines = lines[-n_lines:]

    for line in lines:
        line = line.strip()
        if not line:
            continue

        uid_match = _UID_RE.search(line)
        if not uid_match:
            continue

        uid = uid_match.group(1)
        ip = line.split()[0] if line.split() else ""

        req_match = _REQUEST_RE.search(line)
        request = req_match.group(1) if req_match else ""

        parts = line.split('"')
        status = ""
        if len(parts) >= 3:
            after_request = parts[2].strip().split()
            if after_request:
                status = after_request[0]

        entries[uid] = {
            "ip": ip,
            "request": request,
            "status": status,
            "line": line,
        }

    return entries


def parse_modsec_json_log(path):
    detections = {}
    if not Path(path).exists():
        return detections

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            transaction = entry.get("transaction", {})
            uid = transaction.get("unique_id", "")
            if not uid:
                continue

            messages = transaction.get("messages", [])
            rules = []
            for msg in messages:
                details = msg.get("details", {})
                rule_id_str = details.get("ruleId", "")
                if not rule_id_str or not rule_id_str.isdigit():
                    continue

                prefix = rule_id_str[:3]
                attack_type = CRS_RULE_MAP.get(prefix)
                if attack_type is None:
                    continue

                rules.append({
                    "rule_id": int(rule_id_str),
                    "attack_type": attack_type,
                    "msg": msg.get("message", ""),
                })

            if rules:
                detections.setdefault(uid, []).extend(rules)

    return detections


def parse_llm_alerts(path):
    detections = {}
    unmatched = []

    if not Path(path).exists():
        return detections, unmatched

    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue

            uids = finding.get("unique_ids", [])
            if not uids:
                unmatched.append(finding)
                continue

            for uid in uids:
                detections.setdefault(uid, []).append(finding)

    return detections, unmatched



def build_comparison(access_entries, modsec_detections, llm_detections):
    rows = []
    for uid, info in access_entries.items():
        modsec_rules = modsec_detections.get(uid, [])
        llm_findings = llm_detections.get(uid, [])

        modsec_types = set()
        modsec_rule_ids = []
        for r in modsec_rules:
            modsec_types.add(r["attack_type"])
            modsec_rule_ids.append(str(r["rule_id"]))

        llm_types = set()
        llm_confidence = 0.0
        for f in llm_findings:
            at = f.get("attack_type")
            if at and f.get("malicious"):
                llm_types.add(at)
                llm_confidence = max(llm_confidence, f.get("confidence", 0.0))

        modsec_detected = len(modsec_types) > 0
        llm_detected = len(llm_types) > 0

        if modsec_detected and llm_detected:
            overlap = modsec_types & llm_types
            if overlap:
                agree = "+ Both"
            else:
                agree = "~ Differ"
        elif not modsec_detected and not llm_detected:
            agree = "+ Benign"
        elif modsec_detected:
            agree = "- ModSec only"
        else:
            agree = "- LLM only"

        rows.append({
            "uid": uid,
            "request": info["request"],
            "ip": info["ip"],
            "status": info["status"],
            "modsec_rules": ", ".join(modsec_rule_ids) if modsec_rule_ids else "—",
            "modsec_types": ", ".join(sorted(modsec_types)) if modsec_types else "—",
            "llm_types": ", ".join(sorted(llm_types)) if llm_types else "—",
            "llm_confidence": f"{llm_confidence:.2f}" if llm_detected else "—",
            "agree": agree,
        })

    return rows


def print_per_request_table(rows):
    if not rows:
        print("\nNo access log entries to compare.")
        return

    max_req = 45

    header = (
        f"{'#':<4} {'Request':<{max_req}} "
        f"{'ModSecurity':<25} {'LLM':<25} {'Conf':>5} {'Agreement':<15}"
    )

    print("\n" + "=" * len(header))
    print("  PER-REQUEST COMPARISON (correlated by UNIQUE_ID)")
    print("=" * len(header))
    print(header)
    print("-" * len(header))

    for i, row in enumerate(rows, 1):
        req = row["request"]
        if len(req) > max_req:
            req = req[:max_req - 3] + "..."

        modsec_col = row["modsec_types"]
        if modsec_col != "—" and len(modsec_col) > 23:
            modsec_col = modsec_col[:20] + "..."

        llm_col = row["llm_types"]
        if llm_col != "—" and len(llm_col) > 23:
            llm_col = llm_col[:20] + "..."

        print(
            f"{i:<4} {req:<{max_req}} "
            f"{modsec_col:<25} {llm_col:<25} "
            f"{row['llm_confidence']:>5} {row['agree']:<15}"
        )

    print("-" * len(header))


def print_summary(rows):
    both = sum(1 for r in rows if r["agree"].startswith("# Both"))
    benign = sum(1 for r in rows if r["agree"] == "+ Benign")
    differ = sum(1 for r in rows if r["agree"].startswith("~"))
    modsec_only = sum(1 for r in rows if r["agree"] == "- ModSec only")
    llm_only = sum(1 for r in rows if r["agree"] == "- LLM only")
    total = len(rows)

    print(f"\n{'─' * 50}")
    print("  SUMMARY")
    print(f"{'─' * 50}")
    print(f"  Total requests analysed:  {total}")
    print(f"  + Both detected:          {both}")
    print(f"  + Both benign:            {benign}")
    print(f"  ~ Different attack type:  {differ}")
    print(f"  - ModSecurity only:       {modsec_only}")
    print(f"  - LLM only:              {llm_only}")
    print(f"{'─' * 50}")

    modsec_counts = Counter()
    llm_counts = Counter()
    for r in rows:
        for t in r["modsec_types"].split(", "):
            if t != "—":
                modsec_counts[t] += 1
        for t in r["llm_types"].split(", "):
            if t != "—":
                llm_counts[t] += 1

    all_types = sorted(set(list(modsec_counts.keys()) + list(llm_counts.keys())))
    if all_types:
        type_header = f"\n  {'Attack Type':<40} {'ModSec':>8} {'LLM':>8}"
        print(type_header)
        print(f"  {'-' * 56}")
        for at in all_types:
            mc = modsec_counts.get(at, 0)
            lc = llm_counts.get(at, 0)
            print(f"  {at:<40} {mc:>8} {lc:>8}")
        print(f"  {'-' * 56}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare ModSecurity and LLM pipeline alerts per request (via UNIQUE_ID)."
    )
    parser.add_argument(
        "--access-log",
        default="/var/log/apache2/dvwa_access.log",
        help="Path to the Apache access log (combined_uid format)",
    )
    parser.add_argument(
        "--modsec-log",
        default="/var/log/apache2/modsec_audit.log",
        help="Path to the ModSecurity JSON audit log",
    )
    parser.add_argument(
        "--llm-log",
        default="/var/log/llm_alerts.log",
        help="Path to the LLM pipeline alert log",
    )
    parser.add_argument(
        "--lines",
        type=int,
        default=50,
        help="Number of last access log lines to compare (0 = all)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f"Access log:      {args.access_log}")
    access_entries = parse_access_log(args.access_log, args.lines)
    print(f"  - {len(access_entries)} request(s) with UNIQUE_ID")

    print(f"ModSecurity log: {args.modsec_log}")
    modsec_detections = parse_modsec_json_log(args.modsec_log)
    print(f" - {len(modsec_detections)} request(s) with rule matches")

    print(f"LLM alerts log:  {args.llm_log}")
    llm_detections, unmatched = parse_llm_alerts(args.llm_log)
    print(f" - {len(llm_detections)} request(s) with findings")
    if unmatched:
        print(f" - {len(unmatched)} finding(s) without unique_id (not correlated)")

    rows = build_comparison(access_entries, modsec_detections, llm_detections)
    print_per_request_table(rows)
    print_summary(rows)

    return 0


if __name__ == "__main__":
    sys.exit(main())
