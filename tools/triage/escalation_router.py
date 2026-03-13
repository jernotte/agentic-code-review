#!/usr/bin/env python3
"""
Escalation router — routes filtered detections to specialist agents.

Reads filtered JSONL and matches each detection against escalation rules
defined in config/escalation_rules.yaml. Outputs an escalation queue as JSONL.
"""

import json
import os
import re
import sys

import yaml


def load_escalation_rules(rules_path: str) -> list:
    """Load escalation rules from YAML config."""
    with open(rules_path) as f:
        config = yaml.safe_load(f)
    return config.get("rules", [])


def match_detection(detection: dict, rules: list) -> dict:
    """
    Match a detection against escalation rules.

    Returns an escalation entry or None if no rule matches.
    """
    rule_id = detection.get("rule", "")
    category = detection.get("category", "")
    message = detection.get("message", "")
    warning_type = detection.get("warning_type", "")

    # Combine searchable text
    searchable = f"{rule_id} {category} {message} {warning_type}".lower()

    for rule in rules:
        detection_pattern = rule.get("detection", "")
        # Split pattern by | and check if any token matches
        tokens = [t.strip().lower() for t in detection_pattern.split("|")]
        for token in tokens:
            if token and token in searchable:
                return {
                    "detection": detection,
                    "agent": rule["agent"],
                    "mode": rule.get("mode", "hunting"),
                    "vuln_class": rule.get("vuln_class", "unknown"),
                    "note": rule.get("note", ""),
                    "priority": compute_priority(detection, rule),
                }

    return None


def compute_priority(detection: dict, rule: dict) -> int:
    """Compute priority score for escalation queue ordering."""
    score = 0

    # Severity boost
    severity = detection.get("severity", "WARNING")
    if severity == "ERROR":
        score += 10
    elif severity == "WARNING":
        score += 5

    # Vuln class priority
    vuln_class = rule.get("vuln_class", "")
    class_weights = {
        "sqli": 10,
        "command_injection": 9,
        "ssrf": 8,
        "xss": 6,
        "idor": 5,
    }
    score += class_weights.get(vuln_class, 3)

    # Brakeman confidence boost
    confidence = detection.get("confidence", "")
    if confidence == "High":
        score += 5
    elif confidence == "Medium":
        score += 2

    return score


def route_detections(
    detections: list,
    rules: list,
    phase: int = 1,
) -> tuple:
    """
    Route detections to agents via escalation rules.

    Args:
        detections: Filtered detection dicts
        rules: Escalation rules from config
        phase: Current phase (determines available agents)

    Returns:
        (escalation_queue, unrouted_detections)
    """
    # Phase 1 only has taint-hunter
    available_agents = {"taint-hunter"}
    if phase >= 2:
        available_agents.add("auth-hunter")
    if phase >= 3:
        available_agents.add("variant-hunter")

    queue = []
    unrouted = []

    for det in detections:
        match = match_detection(det, rules)
        if match and match["agent"] in available_agents:
            queue.append(match)
        elif match:
            # Rule matched but agent not available in this phase
            unrouted.append(det)
        else:
            unrouted.append(det)

    # Sort queue by priority (highest first)
    queue.sort(key=lambda x: -x["priority"])

    return queue, unrouted


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Route detections to agents")
    parser.add_argument("input", help="Filtered detections JSONL file")
    parser.add_argument("-o", "--output", help="Output escalation queue JSONL")
    parser.add_argument(
        "-r", "--rules",
        default="config/escalation_rules.yaml",
        help="Escalation rules YAML file",
    )
    parser.add_argument(
        "--phase",
        type=int,
        default=1,
        help="Current phase (determines available agents)",
    )
    args = parser.parse_args()

    # Load rules
    rules = load_escalation_rules(args.rules)

    # Read detections
    detections = []
    with open(args.input) as f:
        for line in f:
            line = line.strip()
            if line:
                detections.append(json.loads(line))

    # Route
    queue, unrouted = route_detections(detections, rules, phase=args.phase)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            for entry in queue:
                f.write(json.dumps(entry) + "\n")
    else:
        for entry in queue:
            print(json.dumps(entry))

    # Stats
    print(f"\nEscalation stats:", file=sys.stderr)
    print(f"  Routed: {len(queue)}", file=sys.stderr)
    print(f"  Unrouted: {len(unrouted)}", file=sys.stderr)
    if queue:
        agents = {}
        for e in queue:
            a = e["agent"]
            agents[a] = agents.get(a, 0) + 1
        for agent, count in agents.items():
            print(f"  → {agent}: {count}", file=sys.stderr)

        classes = {}
        for e in queue:
            c = e["vuln_class"]
            classes[c] = classes.get(c, 0) + 1
        for cls, count in sorted(classes.items(), key=lambda x: -x[1]):
            print(f"    {cls}: {count}", file=sys.stderr)


if __name__ == "__main__":
    main()
