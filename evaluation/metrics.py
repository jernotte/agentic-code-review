#!/usr/bin/env python3
"""
Evaluation metrics for the security harness.

Reads confirmed/rejected/candidate findings, compares against ground truth
(known GitLab CVEs), and produces a summary report.
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def read_findings(findings_dir: str) -> list:
    """Read all finding markdown files from a directory."""
    findings = []
    if not os.path.isdir(findings_dir):
        return findings

    for fname in sorted(os.listdir(findings_dir)):
        if not fname.endswith(".md"):
            continue
        fpath = os.path.join(findings_dir, fname)
        with open(fpath) as f:
            content = f.read()

        # Extract metadata
        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        file_match = re.search(r'File:\s*(.+?)(?::[\d–-]+)?$', content, re.MULTILINE)
        conf_match = re.search(r'##\s+Confidence\s*\n\s*(\w+)', content, re.MULTILINE)

        findings.append({
            "filename": fname,
            "title": title_match.group(1).strip() if title_match else fname,
            "file": file_match.group(1).strip() if file_match else "",
            "confidence": conf_match.group(1).strip().lower() if conf_match else "unknown",
            "content": content,
        })

    return findings


def load_ground_truth(gt_path: str) -> list:
    """Load known vulnerabilities from JSONL ground truth file."""
    vulns = []
    if not os.path.isfile(gt_path):
        return vulns

    with open(gt_path) as f:
        for line in f:
            line = line.strip()
            if line:
                vulns.append(json.loads(line))

    return vulns


def match_finding_to_gt(finding: dict, ground_truth: list) -> dict:
    """Check if a finding matches a known vulnerability."""
    finding_file = finding.get("file", "").lower()
    finding_title = finding.get("title", "").lower()

    for gt in ground_truth:
        gt_file = gt.get("file", "").lower()
        gt_component = gt.get("component", "").lower()
        gt_type = gt.get("type", "").lower()

        # Match by file path
        if gt_file and gt_file in finding_file:
            return gt
        # Match by component name
        if gt_component and gt_component in finding_file:
            return gt
        # Match by vuln type + component in title
        if gt_type and gt_component:
            if gt_type in finding_title and gt_component in finding_title:
                return gt

    return None


def compute_metrics(
    base_dir: str,
    ground_truth_path: str = None,
) -> dict:
    """
    Compute evaluation metrics.

    Returns dict with counts, rates, and details.
    """
    findings_base = os.path.join(base_dir, "memory", "findings")

    confirmed = read_findings(os.path.join(findings_base, "confirmed"))
    candidates = read_findings(os.path.join(findings_base, "candidates"))
    rejected = read_findings(os.path.join(findings_base, "rejected"))

    # Load ground truth
    if ground_truth_path is None:
        ground_truth_path = os.path.join(base_dir, "evaluation", "ground_truth", "gitlab_known_vulns.jsonl")
    ground_truth = load_ground_truth(ground_truth_path)

    # Basic counts
    metrics = {
        "counts": {
            "confirmed": len(confirmed),
            "candidates": len(candidates),
            "rejected": len(rejected),
            "total_findings": len(confirmed) + len(candidates),
            "ground_truth_vulns": len(ground_truth),
        },
        "confidence_distribution": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
        },
        "true_positives": [],
        "false_positives": [],
        "false_negatives": [],
    }

    # Confidence distribution across all findings
    for f in confirmed + candidates:
        conf = f.get("confidence", "unknown")
        if conf in metrics["confidence_distribution"]:
            metrics["confidence_distribution"][conf] += 1
        else:
            metrics["confidence_distribution"]["unknown"] += 1

    # Match findings against ground truth
    if ground_truth:
        matched_gt = set()

        for f in confirmed + candidates:
            gt_match = match_finding_to_gt(f, ground_truth)
            if gt_match:
                metrics["true_positives"].append({
                    "finding": f["title"],
                    "matched_cve": gt_match.get("cve", "unknown"),
                })
                matched_gt.add(gt_match.get("cve", ""))
            else:
                # Could be a novel finding or a false positive
                # Without dynamic confirmation, we can't be sure
                pass

        for f in rejected:
            gt_match = match_finding_to_gt(f, ground_truth)
            if gt_match:
                metrics["false_negatives"].append({
                    "finding": f["title"],
                    "missed_cve": gt_match.get("cve", "unknown"),
                    "reason": "rejected during analysis",
                })

        # Ground truth vulns not found at all
        for gt in ground_truth:
            cve = gt.get("cve", "")
            if cve and cve not in matched_gt:
                metrics["false_negatives"].append({
                    "cve": cve,
                    "component": gt.get("component", ""),
                    "type": gt.get("type", ""),
                    "reason": "not detected",
                })

    # Compute rates
    tp = len(metrics["true_positives"])
    total_findings = metrics["counts"]["total_findings"]
    total_gt = metrics["counts"]["ground_truth_vulns"]

    metrics["rates"] = {
        "true_positive_count": tp,
        "precision": tp / total_findings if total_findings > 0 else 0,
        "recall": tp / total_gt if total_gt > 0 else 0,
    }

    # Read analyzed paths count
    analyzed_path = os.path.join(base_dir, "memory", "hunt_state", "analyzed_paths.jsonl")
    if os.path.isfile(analyzed_path):
        with open(analyzed_path) as f:
            metrics["paths_analyzed"] = sum(1 for line in f if line.strip())
    else:
        metrics["paths_analyzed"] = 0

    return metrics


def write_report(metrics: dict, output_path: str = None) -> str:
    """Generate a markdown metrics report."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Evaluation Report",
        "",
        f"Generated: {ts}",
        "",
        "## Summary",
        "",
        f"- Confirmed findings: {metrics['counts']['confirmed']}",
        f"- Candidate findings: {metrics['counts']['candidates']}",
        f"- Rejected findings: {metrics['counts']['rejected']}",
        f"- Paths analyzed: {metrics['paths_analyzed']}",
        f"- Ground truth vulnerabilities: {metrics['counts']['ground_truth_vulns']}",
        "",
        "## Rates",
        "",
        f"- True positives: {metrics['rates']['true_positive_count']}",
        f"- Precision: {metrics['rates']['precision']:.2%}",
        f"- Recall: {metrics['rates']['recall']:.2%}",
        "",
        "## Confidence Distribution",
        "",
    ]

    for level, count in metrics["confidence_distribution"].items():
        lines.append(f"- {level}: {count}")

    if metrics["true_positives"]:
        lines.extend(["", "## True Positives", ""])
        for tp in metrics["true_positives"]:
            lines.append(f"- {tp['finding']} → {tp['matched_cve']}")

    if metrics["false_negatives"]:
        lines.extend(["", "## Missed Vulnerabilities (False Negatives)", ""])
        for fn in metrics["false_negatives"]:
            if "cve" in fn:
                lines.append(f"- {fn['cve']}: {fn.get('component', '')} ({fn.get('type', '')}) — {fn['reason']}")
            else:
                lines.append(f"- {fn['finding']} → {fn['missed_cve']} — {fn['reason']}")

    report = "\n".join(lines) + "\n"

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(report)

    return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Compute evaluation metrics")
    parser.add_argument(
        "--base-dir",
        default=".",
        help="Project base directory",
    )
    parser.add_argument(
        "--ground-truth",
        help="Path to ground truth JSONL",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output report markdown file",
    )
    args = parser.parse_args()

    metrics = compute_metrics(args.base_dir, args.ground_truth)
    report = write_report(metrics, args.output)
    print(report)


if __name__ == "__main__":
    main()
