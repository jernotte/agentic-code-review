#!/usr/bin/env python3
"""
Brakeman scanner wrapper for the security harness.

Runs Brakeman against the GitLab Rails app and normalizes output to JSONL.
Requires Ruby and the brakeman gem to be installed.
Handles missing dependencies gracefully.
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone


# Paths to exclude from results
EXCLUDE_PATTERNS = [
    "spec/", "test/", "vendor/", "db/migrate/",
    "node_modules/", "tmp/", "log/",
]


def should_exclude(filepath: str) -> bool:
    """Check if a file path should be excluded from results."""
    for pattern in EXCLUDE_PATTERNS:
        if pattern in filepath:
            return True
    return False


def check_brakeman() -> bool:
    """Check if brakeman is available."""
    return shutil.which("brakeman") is not None


def run_brakeman(
    rails_root: str,
    output_file: str = None,
    confidence_level: int = 1,
) -> list:
    """
    Run Brakeman against a Rails application root.

    Args:
        rails_root: Path to the Rails application root
        output_file: Optional JSONL file to write results to
        confidence_level: Minimum confidence (0=high, 1=medium, 2=weak)

    Returns:
        List of detection dicts
    """
    if not check_brakeman():
        print(
            "WARNING: brakeman not available. Install Ruby and run: gem install brakeman",
            file=sys.stderr,
        )
        return []

    cmd = [
        "brakeman",
        "--format", "json",
        "--quiet",
        "--no-pager",
        f"--confidence-level={confidence_level}",
        "--path", rails_root,
    ]

    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    print("Note: Brakeman on GitLab can take several minutes...", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900,  # 15 min timeout for large codebases
        )
    except subprocess.TimeoutExpired:
        print("ERROR: brakeman timed out after 900s", file=sys.stderr)
        return []

    try:
        brakeman_output = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Failed to parse Brakeman output", file=sys.stderr)
        print(f"stderr: {result.stderr[:500]}", file=sys.stderr)
        return []

    detections = []
    for warning in brakeman_output.get("warnings", []):
        filepath = warning.get("file", "")

        if should_exclude(filepath):
            continue

        # Map Brakeman confidence to severity
        confidence = warning.get("confidence", "Medium")
        severity_map = {"High": "ERROR", "Medium": "WARNING", "Weak": "INFO"}
        severity = severity_map.get(confidence, "WARNING")

        detection = {
            "file": filepath,
            "line": warning.get("line", 0),
            "end_line": warning.get("line", 0),
            "rule": warning.get("check_name", "unknown"),
            "severity": severity,
            "message": warning.get("message", "")[:500],
            "snippet": warning.get("code", "")[:300],
            "scanner": "brakeman",
            "confidence": confidence,
            "warning_type": warning.get("warning_type", ""),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        detections.append(detection)

    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w") as f:
            for det in detections:
                f.write(json.dumps(det) + "\n")
        print(f"Wrote {len(detections)} detections to {output_file}", file=sys.stderr)

    return detections


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Run Brakeman security scan")
    parser.add_argument("rails_root", help="Path to Rails application root")
    parser.add_argument("-o", "--output", help="Output JSONL file")
    parser.add_argument(
        "--confidence",
        type=int,
        default=1,
        choices=[0, 1, 2],
        help="Min confidence: 0=high, 1=medium, 2=weak",
    )
    args = parser.parse_args()

    if not check_brakeman():
        print("Brakeman is not installed. Requires Ruby + gem install brakeman.", file=sys.stderr)
        sys.exit(1)

    detections = run_brakeman(
        rails_root=args.rails_root,
        output_file=args.output,
        confidence_level=args.confidence,
    )

    if not args.output:
        for det in detections:
            print(json.dumps(det))

    print(f"\nTotal detections: {len(detections)}", file=sys.stderr)


if __name__ == "__main__":
    main()
