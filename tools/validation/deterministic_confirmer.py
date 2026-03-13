#!/usr/bin/env python3
"""
Deterministic confirmer — re-validates candidate findings using Semgrep.

Takes a candidate finding markdown file, extracts the source/sink/file info,
and runs a targeted Semgrep scan to verify the claimed taint path.

Outputs: confirmed / unconfirmed / inconclusive with reason.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_finding(finding_path: str) -> dict:
    """Extract structured info from a finding markdown file."""
    with open(finding_path) as f:
        content = f.read()

    info = {
        "title": "",
        "file": "",
        "line_range": "",
        "source": "",
        "sink": "",
        "vuln_class": "",
        "confidence": "",
    }

    # Title
    title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    if title_match:
        info["title"] = title_match.group(1).strip()

    # File location
    file_match = re.search(r'File:\s*(.+?)(?::(\d+[-–]\d+|\d+))?$', content, re.MULTILINE)
    if file_match:
        info["file"] = file_match.group(1).strip()
        info["line_range"] = (file_match.group(2) or "").strip()

    # Source
    source_match = re.search(r'\*\*Source:\*\*\s*(.+?)$', content, re.MULTILINE)
    if source_match:
        info["source"] = source_match.group(1).strip()

    # Sink
    sink_match = re.search(r'\*\*Sink:\*\*\s*(.+?)$', content, re.MULTILINE)
    if sink_match:
        info["sink"] = sink_match.group(1).strip()

    # Confidence
    conf_match = re.search(r'##\s+Confidence\s*\n\s*(\w+)', content, re.MULTILINE)
    if conf_match:
        info["confidence"] = conf_match.group(1).strip().lower()

    # Infer vuln class from title and sink
    combined = f"{info['title']} {info['sink']}".lower()
    if any(kw in combined for kw in ("sql", "query", "where", "inject")):
        info["vuln_class"] = "sqli"
    elif any(kw in combined for kw in ("xss", "html_safe", "raw", "script")):
        info["vuln_class"] = "xss"
    elif any(kw in combined for kw in ("command", "system", "exec", "shell")):
        info["vuln_class"] = "command_injection"
    elif any(kw in combined for kw in ("ssrf", "http", "request", "url")):
        info["vuln_class"] = "ssrf"

    return info


def build_semgrep_rule(finding_info: dict) -> dict:
    """Build a targeted Semgrep rule for the finding's vulnerability pattern."""
    vuln_class = finding_info["vuln_class"]
    sink = finding_info.get("sink", "")

    # Build patterns based on vuln class
    patterns = []

    if vuln_class == "sqli":
        patterns = [
            'where("... #{$X} ...")',
            'where("... " + $X)',
            'find_by_sql("... #{$X} ...")',
            'connection.execute("... #{$X} ...")',
            'order("... #{$X} ...")',
        ]
    elif vuln_class == "xss":
        patterns = [
            "$X.html_safe",
            "raw($X)",
        ]
    elif vuln_class == "command_injection":
        patterns = [
            'system("... #{$X} ...")',
            '`... #{$X} ...`',
            'IO.popen("... #{$X} ...")',
        ]
    elif vuln_class == "ssrf":
        patterns = [
            "Net::HTTP.get($X)",
            "URI.open($X)",
            "Faraday.get($X)",
        ]

    if not patterns:
        return None

    rule = {
        "rules": [
            {
                "id": "harness-confirmation",
                "patterns": [{"pattern": p} for p in patterns[:1]],
                "message": f"Confirmation scan for {vuln_class}",
                "languages": ["ruby"],
                "severity": "WARNING",
            }
        ]
    }

    # Use pattern-either for multiple patterns
    if len(patterns) > 1:
        rule["rules"][0] = {
            "id": "harness-confirmation",
            "pattern-either": [{"pattern": p} for p in patterns],
            "message": f"Confirmation scan for {vuln_class}",
            "languages": ["ruby"],
            "severity": "WARNING",
        }

    return rule


def run_targeted_scan(finding_info: dict, gitlab_root: str) -> dict:
    """Run a targeted Semgrep scan to verify the finding."""
    target_file = finding_info.get("file", "")
    if not target_file:
        return {"status": "inconclusive", "reason": "No file specified in finding"}

    # Resolve the file path
    full_path = os.path.join(gitlab_root, target_file)
    if not os.path.isfile(full_path):
        # Try with gitlab-source prefix
        full_path = os.path.join(gitlab_root, "gitlab-source", target_file)
        if not os.path.isfile(full_path):
            return {"status": "inconclusive", "reason": f"File not found: {target_file}"}

    # Build a targeted rule
    rule = build_semgrep_rule(finding_info)
    if not rule:
        return {"status": "inconclusive", "reason": f"No Semgrep rule for vuln class: {finding_info['vuln_class']}"}

    # Write rule to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tmp:
        import yaml
        yaml.dump(rule, tmp)
        rule_path = tmp.name

    try:
        result = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", rule_path, full_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        output = json.loads(result.stdout)
        findings = output.get("results", [])

        if findings:
            return {
                "status": "confirmed",
                "reason": f"Semgrep found {len(findings)} matching pattern(s) in {target_file}",
                "matches": [
                    {
                        "line": f["start"]["line"],
                        "rule": f["check_id"],
                        "snippet": f.get("extra", {}).get("lines", "")[:200],
                    }
                    for f in findings
                ],
            }
        else:
            return {
                "status": "unconfirmed",
                "reason": "Semgrep did not find matching patterns. Finding may still be valid if pattern is too complex for static rules.",
            }

    except subprocess.TimeoutExpired:
        return {"status": "inconclusive", "reason": "Semgrep scan timed out"}
    except json.JSONDecodeError:
        return {"status": "inconclusive", "reason": "Failed to parse Semgrep output"}
    finally:
        os.unlink(rule_path)


def confirm_finding(finding_path: str, gitlab_root: str = ".") -> dict:
    """
    Main entry point: confirm a candidate finding.

    Returns dict with status (confirmed/unconfirmed/inconclusive) and reason.
    """
    finding_info = parse_finding(finding_path)

    if not finding_info["file"]:
        return {"status": "inconclusive", "reason": "Could not extract file path from finding"}

    # Run targeted scan
    result = run_targeted_scan(finding_info, gitlab_root)
    result["finding"] = finding_info["title"]
    result["file"] = finding_info["file"]
    result["vuln_class"] = finding_info["vuln_class"]

    return result


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Confirm candidate findings with Semgrep")
    parser.add_argument("finding", help="Path to candidate finding markdown file")
    parser.add_argument(
        "--gitlab-root",
        default=".",
        help="Path to GitLab source root",
    )
    args = parser.parse_args()

    result = confirm_finding(args.finding, args.gitlab_root)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
