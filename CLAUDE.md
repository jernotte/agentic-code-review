# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Autonomous security research harness that reviews GitLab CE (Ruby on Rails) source code for injection vulnerabilities. Uses a multi-stage pipeline: deterministic scanners (Semgrep, Brakeman) flag suspicious locations → heuristic triage filters noise → an LLM agent traces data flow and reasons about exploitability → the agent attempts self-disproval → deterministic tools re-confirm → a second LLM call challenges the finding.

Currently in **Phase 1** — single taint analysis agent, end-to-end pipeline, methodology-only knowledge packs, persistent memory, baseline metrics. No over-engineering (no vector DBs, embeddings, or DSPy until later phases).

## Architecture

See `gitlab-security-harness-overview-v3.md` for full architecture and interface definitions. See `phase1-briefing.md` for Phase 1 build spec and constraints.

### Core Pipeline Flow
```
Attack Surface Map → Broad Scan (Semgrep/Brakeman) → Heuristic Triage → Agent Analysis → Self-Disproval → Validation
```

### Directory Structure (target)
```
memory/                          # Persistent state (markdown + JSONL only)
  hunt_state/                    # ledger.md, status.md, dead_ends.md, worklog.md, analyzed_paths.jsonl
  findings/{confirmed,candidates,rejected}/   # One markdown file per finding
  targets/gitlab/                # attack_surface.md, routes_map.jsonl, tech_profile.md
knowledge/packs/taint/           # methodology.md, sources_sinks.md, research_terms.md
tools/scanners/                  # semgrep_runner.py, brakeman_runner.py
tools/triage/                    # heuristic_filter.py, escalation_router.py
tools/validation/                # deterministic_confirmer.py, adversarial_reviewer.py
agents/skills/                   # taint_hunter.md (Crash Override 5-component format)
agents/configs/                  # YAML agent configs
scripts/                        # parse_gitlab_routes.py
evaluation/                     # metrics.py, ground_truth/
config/                         # harness.yaml, escalation_rules.yaml
```

### Key Interfaces
- **Code Access**: Input: target spec → Output: primary code + related context + metadata (auth filters, route, framework context)
- **Knowledge Retrieval**: Input: vuln_class → Output: methodology + research terms + framework patterns
- **Persistent Memory**: Append-only writes (ledger, dead ends, worklog, analyzed paths); overwrite for status.md only

## Critical Design Constraints

- **Markdown + JSONL only** — no standalone JSON files. JSON can't be appended, tailed, or grepped effectively.
- **A detection is not a finding** — scanner output = detection; agent-confirmed taint path = candidate finding; surviving self-disproval = validated finding.
- **Self-disproval is built into the agent** — before reporting any finding, check for missed sanitizers, unreachable code paths, before_actions, Strong Parameters constraints.
- **Methodology-only knowledge packs** — no specific bug examples in Phase 1. Examples anchor to known patterns and may reduce ability to find novel vulnerabilities.
- **Findings are individual markdown files** — one per finding in `memory/findings/{candidates,confirmed,rejected}/`. Filename: `YYYY-MM-DD-type-description.md`.

## Context Recovery Protocol

On session start or after context compaction:
1. Read `memory/hunt_state/status.md` — current target, hypothesis, agent
2. Read `memory/hunt_state/ledger.md` (last 20 entries) — what's been found
3. Read `memory/hunt_state/dead_ends.md` (last 10 entries) — what NOT to retry
4. Read `memory/hunt_state/worklog.md` (last 5 entries) — recent activity
5. Scan `memory/hunt_state/analyzed_paths.jsonl` — what's already covered
6. Resume from recovered state or pivot

## Build Order (Phase 1)

1. Directory structure + persistent memory files (skeleton with headers)
2. Attack surface mapper (`scripts/parse_gitlab_routes.py`)
3. Scanner wrappers (Semgrep, Brakeman) — test on small GitLab subset
4. Heuristic triage + escalation router
5. Knowledge pack (methodology.md, sources_sinks.md, research_terms.md)
6. Skill file (`agents/skills/taint_hunter.md`)
7. Validation tools (deterministic confirmer + adversarial reviewer)
8. Evaluation baseline (metrics.py + ground truth data)
9. Integration test — full pipeline against one GitLab controller

## Coordinator Logic (Phase 1)

1. On session start: run context recovery protocol
2. If no current work: check escalation queue for pending detections
3. If queue empty: run scanners against next priority area from attack surface map, triage output, populate queue
4. Process detections one at a time through full pipeline
5. After each finding or dead end: update all memory files
6. Periodically: update status.md with current state

## Scanner Output Format

JSONL (not SARIF for Phase 1). Each line:
```json
{"file": "...", "line": 0, "rule": "...", "severity": "...", "message": "...", "snippet": "..."}
```
Filter out: `spec/`, `test/`, `vendor/`, `db/migrate/`.

## Escalation Rules

SQLi/XSS/command injection/SSRF detections → `taint-hunter`. Auth/IDOR → `auth-hunter` (Phase 2). Variant matches → `variant-hunter` (Phase 3). See `config/escalation_rules.yaml`.

## Language & Tools

- **Python** for all scripts and tooling
- **Semgrep** and **Brakeman** required for Phase 1; CodeQL optional (Phase 2+)
- **Target**: GitLab CE Ruby on Rails monolith
