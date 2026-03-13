#!/usr/bin/env python3
"""
Heuristic triage filter for scanner output.

Reads JSONL detections, deduplicates by file+line+rule category,
filters known false positive patterns, and outputs filtered JSONL.
"""

import json
import re
import sys
from collections import defaultdict


# Known false positive patterns — common in large Rails apps
# Each entry: (rule_pattern, file_pattern, reason)
KNOWN_FP_PATTERNS = [
    # html_safe on static strings or known-safe content
    (r"html.safe", r"app/helpers/.*_helper\.rb", "html_safe in helpers is typically on pre-sanitized content"),
    # Redirect to known-safe destinations
    (r"redirect", r"app/controllers/.*sessions.*", "Session redirects are typically to safe URLs"),
    # Mass assignment in admin-only contexts
    (r"mass.assign", r"app/controllers/admin/", "Admin controllers are behind admin auth"),
    # Unscoped find in policy checks
    (r"unscoped.find", r"app/policies/", "Policy checks need unscoped finds by design"),
]

# Minimum severity to keep (ordered)
SEVERITY_ORDER = {"ERROR": 3, "WARNING": 2, "INFO": 1}


def normalize_rule_category(rule: str) -> str:
    """Extract a normalized category from a rule ID."""
    rule_lower = rule.lower()

    if any(kw in rule_lower for kw in ("sql", "inject")):
        return "sqli"
    elif any(kw in rule_lower for kw in ("xss", "html.safe", "cross.site", "html_safe")):
        return "xss"
    elif any(kw in rule_lower for kw in ("command", "exec", "system", "execute")):
        return "command_injection"
    elif any(kw in rule_lower for kw in ("ssrf", "redirect", "open.redirect")):
        return "ssrf_or_redirect"
    elif any(kw in rule_lower for kw in ("csrf",)):
        return "csrf"
    elif any(kw in rule_lower for kw in ("mass.assign", "attr.accessible")):
        return "mass_assignment"
    elif any(kw in rule_lower for kw in ("unscoped", "idor")):
        return "unscoped_find"
    elif any(kw in rule_lower for kw in ("reflect",)):
        return "unsafe_reflection"
    elif any(kw in rule_lower for kw in ("hash", "sha1", "md5", "weak")):
        return "weak_crypto"
    elif any(kw in rule_lower for kw in ("send.file",)):
        return "path_traversal"
    elif any(kw in rule_lower for kw in ("session",)):
        return "session"
    elif any(kw in rule_lower for kw in ("verb.confusion",)):
        return "http_verb_confusion"
    else:
        return "other"


def is_known_fp(detection: dict) -> tuple:
    """Check if a detection matches a known false positive pattern.
    Returns (is_fp: bool, reason: str)."""
    rule = detection.get("rule", "")
    filepath = detection.get("file", "")

    for rule_pat, file_pat, reason in KNOWN_FP_PATTERNS:
        if re.search(rule_pat, rule, re.IGNORECASE) and re.search(file_pat, filepath):
            return True, reason

    return False, ""


def deduplicate(detections: list) -> list:
    """Deduplicate detections by file + line + rule category."""
    seen = set()
    unique = []

    for det in detections:
        key = (det.get("file"), det.get("line"), normalize_rule_category(det.get("rule", "")))
        if key not in seen:
            seen.add(key)
            unique.append(det)

    return unique


def filter_detections(
    detections: list,
    min_severity: str = "WARNING",
    apply_fp_filter: bool = True,
) -> tuple:
    """
    Filter and deduplicate detections.

    Returns:
        (filtered_detections, stats_dict)
    """
    stats = {
        "input_count": len(detections),
        "severity_filtered": 0,
        "fp_filtered": 0,
        "deduplicated": 0,
        "output_count": 0,
    }

    min_sev_value = SEVERITY_ORDER.get(min_severity, 1)

    # Step 1: Severity filter
    severity_passed = []
    for det in detections:
        sev = det.get("severity", "WARNING")
        if SEVERITY_ORDER.get(sev, 1) >= min_sev_value:
            severity_passed.append(det)
        else:
            stats["severity_filtered"] += 1

    # Step 2: Known FP filter
    fp_passed = []
    for det in severity_passed:
        if apply_fp_filter:
            is_fp, reason = is_known_fp(det)
            if is_fp:
                stats["fp_filtered"] += 1
                continue
        fp_passed.append(det)

    # Step 3: Deduplicate
    before_dedup = len(fp_passed)
    unique = deduplicate(fp_passed)
    stats["deduplicated"] = before_dedup - len(unique)

    # Add normalized category to each detection
    for det in unique:
        det["category"] = normalize_rule_category(det.get("rule", ""))

    stats["output_count"] = len(unique)
    return unique, stats


def main():
    """CLI entry point. Reads JSONL from stdin or file, outputs filtered JSONL."""
    import argparse

    parser = argparse.ArgumentParser(description="Filter scanner detections")
    parser.add_argument("input", nargs="?", help="Input JSONL file (default: stdin)")
    parser.add_argument("-o", "--output", help="Output JSONL file (default: stdout)")
    parser.add_argument(
        "--min-severity",
        default="WARNING",
        choices=["INFO", "WARNING", "ERROR"],
        help="Minimum severity to keep",
    )
    parser.add_argument(
        "--no-fp-filter",
        action="store_true",
        help="Disable known false positive filtering",
    )
    args = parser.parse_args()

    # Read input
    detections = []
    if args.input:
        with open(args.input) as f:
            for line in f:
                line = line.strip()
                if line:
                    detections.append(json.loads(line))
    else:
        for line in sys.stdin:
            line = line.strip()
            if line:
                detections.append(json.loads(line))

    # Filter
    filtered, stats = filter_detections(
        detections,
        min_severity=args.min_severity,
        apply_fp_filter=not args.no_fp_filter,
    )

    # Output
    if args.output:
        with open(args.output, "w") as f:
            for det in filtered:
                f.write(json.dumps(det) + "\n")
    else:
        for det in filtered:
            print(json.dumps(det))

    # Stats to stderr
    print(f"\nTriage stats:", file=sys.stderr)
    for k, v in stats.items():
        print(f"  {k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    main()
