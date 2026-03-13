#!/usr/bin/env python3
"""
Semgrep scanner wrapper for the security harness.

Runs Semgrep against specified targets with Ruby/Rails security rulesets.
Outputs normalized JSONL (one detection per line).
Filters out test files, vendored code, and migrations.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# Paths to exclude from results
EXCLUDE_PATTERNS = [
    "spec/", "test/", "vendor/", "db/migrate/",
    "node_modules/", "tmp/", "log/",
]

# Default rulesets for Ruby/Rails security scanning
DEFAULT_RULESETS = [
    "r/ruby.rails.security",
    "r/ruby.lang.security",
]


def should_exclude(filepath: str) -> bool:
    """Check if a file path should be excluded from results."""
    for pattern in EXCLUDE_PATTERNS:
        if pattern in filepath:
            return True
    return False


def run_semgrep(
    target_path: str,
    rulesets: list = None,
    output_file: str = None,
    extra_args: list = None,
) -> list:
    """
    Run Semgrep against a target path and return detections as dicts.

    Args:
        target_path: Path to scan (file or directory)
        rulesets: List of Semgrep rulesets (default: p/ruby, p/rails)
        output_file: Optional JSONL file to write results to
        extra_args: Additional Semgrep CLI arguments

    Returns:
        List of detection dicts
    """
    if rulesets is None:
        rulesets = DEFAULT_RULESETS

    cmd = ["semgrep", "--json", "--quiet"]

    for rs in rulesets:
        cmd.extend(["--config", rs])

    # Add exclusion patterns
    for pattern in EXCLUDE_PATTERNS:
        cmd.extend(["--exclude", pattern])

    if extra_args:
        cmd.extend(extra_args)

    cmd.append(target_path)

    print(f"Running: {' '.join(cmd)}", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        print("ERROR: semgrep not found. Install with: pip install semgrep", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print("ERROR: semgrep timed out after 600s", file=sys.stderr)
        return []

    if result.returncode not in (0, 1):
        # returncode 1 = findings found (not an error)
        print(f"Semgrep stderr: {result.stderr[:500]}", file=sys.stderr)

    try:
        semgrep_output = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"ERROR: Failed to parse Semgrep output", file=sys.stderr)
        print(f"stdout (first 500): {result.stdout[:500]}", file=sys.stderr)
        return []

    detections = []
    for finding in semgrep_output.get("results", []):
        filepath = finding.get("path", "")

        # Apply exclusion filter
        if should_exclude(filepath):
            continue

        severity = finding.get("extra", {}).get("severity", "WARNING")
        message = finding.get("extra", {}).get("message", "")
        rule_id = finding.get("check_id", "unknown")

        # Extract code snippet
        start_line = finding.get("start", {}).get("line", 0)
        end_line = finding.get("end", {}).get("line", start_line)
        snippet = finding.get("extra", {}).get("lines", "").strip()

        detection = {
            "file": filepath,
            "line": start_line,
            "end_line": end_line,
            "rule": rule_id,
            "severity": severity,
            "message": message[:500],  # Cap message length
            "snippet": snippet[:300],  # Cap snippet length
            "scanner": "semgrep",
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        detections.append(detection)

    # Write to output file if specified
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

    parser = argparse.ArgumentParser(description="Run Semgrep security scan")
    parser.add_argument("target", help="Path to scan")
    parser.add_argument("-o", "--output", help="Output JSONL file")
    parser.add_argument(
        "-r", "--ruleset",
        action="append",
        help="Semgrep ruleset (can specify multiple)",
    )
    parser.add_argument(
        "--extra",
        nargs="*",
        help="Extra arguments to pass to semgrep",
    )
    args = parser.parse_args()

    detections = run_semgrep(
        target_path=args.target,
        rulesets=args.ruleset,
        output_file=args.output,
        extra_args=args.extra,
    )

    if not args.output:
        for det in detections:
            print(json.dumps(det))

    print(f"\nTotal detections: {len(detections)}", file=sys.stderr)


if __name__ == "__main__":
    main()
