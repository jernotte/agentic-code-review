#!/usr/bin/env python3
"""
Adversarial reviewer — challenges candidate findings via a second LLM call.

Takes a candidate finding markdown file and relevant source code,
constructs a skeptical review prompt, and calls the LLM to challenge
the finding's validity.

For Phase 1: outputs the review prompt to stdout (human runs it manually
or integrates with their LLM setup). In later phases, this calls the
Anthropic API directly.
"""

import json
import os
import re
import sys
from pathlib import Path


REVIEW_PROMPT_TEMPLATE = """You are a skeptical security reviewer. Your job is to find flaws in this vulnerability report. Challenge every claim. Look for sanitizers, authorization checks, or other defenses the analyst may have missed.

You must be thorough and adversarial. If the finding is invalid, explain exactly why. If it is valid, acknowledge it but note any weaknesses in the analysis.

## Vulnerability Report

{finding_content}

## Source Code Context

{code_context}

## Your Review

For each claim in the taint path, verify:
1. Is the source actually user-controlled? Could it be set by the system instead?
2. Does the data pass through any sanitizer the analyst missed?
3. Is there a before_action or authorization check that prevents this path?
4. Does Strong Parameters constrain the input?
5. Is the code path actually reachable from a route?
6. Does the framework provide built-in protection the analyst overlooked?

Provide your assessment:
- **VALID**: The finding holds up under scrutiny. Explain why each disproval attempt fails.
- **INVALID**: The finding has a fatal flaw. Explain exactly what breaks the taint path.
- **NEEDS MORE EVIDENCE**: The analysis has gaps that need investigation. List what's missing.
"""


def read_finding(finding_path: str) -> str:
    """Read the finding markdown content."""
    with open(finding_path) as f:
        return f.read()


def extract_file_path(finding_content: str) -> str:
    """Extract the target file path from the finding."""
    match = re.search(r'File:\s*(.+?)(?::[\d–-]+)?$', finding_content, re.MULTILINE)
    if match:
        return match.group(1).strip()
    return ""


def read_code_context(file_path: str, gitlab_root: str, context_lines: int = 100) -> str:
    """Read relevant source code for the finding."""
    if not file_path:
        return "(No file path specified in finding)"

    # Try to find the file
    candidates = [
        os.path.join(gitlab_root, file_path),
        os.path.join(gitlab_root, "gitlab-source", file_path),
    ]

    for fpath in candidates:
        if os.path.isfile(fpath):
            with open(fpath) as f:
                lines = f.readlines()
            # Return first N lines with line numbers
            numbered = []
            for i, line in enumerate(lines[:context_lines], 1):
                numbered.append(f"{i:4d} | {line.rstrip()}")
            if len(lines) > context_lines:
                numbered.append(f"... ({len(lines) - context_lines} more lines)")
            return f"### {file_path}\n```ruby\n" + "\n".join(numbered) + "\n```"

    return f"(File not found: {file_path})"


def generate_review(finding_path: str, gitlab_root: str = ".") -> dict:
    """
    Generate an adversarial review for a candidate finding.

    Returns dict with the review prompt and metadata.
    """
    finding_content = read_finding(finding_path)
    file_path = extract_file_path(finding_content)
    code_context = read_code_context(file_path, gitlab_root)

    prompt = REVIEW_PROMPT_TEMPLATE.format(
        finding_content=finding_content,
        code_context=code_context,
    )

    return {
        "finding_file": finding_path,
        "target_file": file_path,
        "review_prompt": prompt,
        "prompt_length": len(prompt),
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate adversarial review for a finding")
    parser.add_argument("finding", help="Path to candidate finding markdown file")
    parser.add_argument(
        "--gitlab-root",
        default=".",
        help="Path to project root (contains gitlab-source/)",
    )
    parser.add_argument(
        "--prompt-only",
        action="store_true",
        default=True,
        help="Output the review prompt only (default in Phase 1)",
    )
    args = parser.parse_args()

    result = generate_review(args.finding, args.gitlab_root)

    if args.prompt_only:
        print(result["review_prompt"])
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
