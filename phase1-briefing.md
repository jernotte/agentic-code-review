# GitLab Security Research Harness — Phase 1

Read `gitlab-security-harness-overview-v2.md` first. It contains the full architecture, interface definitions, and design rationale. This document tells you what to build for Phase 1 and why the constraints exist.

---

## What you are building

An autonomous taint analysis agent that reviews GitLab's Ruby on Rails source code for injection vulnerabilities (SQLi, XSS, command injection, SSRF). The agent operates through a pipeline: deterministic scanners flag suspicious locations → heuristic triage filters noise → the agent traces data flow and reasons about exploitability → the agent tries to disprove its own finding → deterministic tools re-confirm → a second LLM call challenges the finding.

This is Phase 1 of a multi-phase system. The goal is a working end-to-end pipeline that establishes baseline metrics, not a polished product. Later phases add more agents, knowledge retrieval, DSPy optimization, and full orchestration. Every component you build should sit behind a clear interface so implementations can be swapped in Phase 2 without rewriting the system.

---

## Environment discovery

Before building anything, you need to understand the environment. Do this first:

- Find the GitLab source clone. Check common locations. Note the path, the version/branch, and the directory structure (particularly `config/routes.rb`, `app/controllers/`, `app/finders/`, `app/services/`, `app/models/`, `app/policies/`, `lib/api/`).
- Check what tools are available: `semgrep --version`, `brakeman --version`, `codeql --version`. If any are missing, install them. Semgrep and Brakeman are required for Phase 1. CodeQL is optional (Phase 2+).
- Check the Ruby version and Rails version in the GitLab source (`Gemfile`, `.ruby-version`).
- Note the working directory structure and where to place the harness.

---

## Design constraints and why they exist

These are non-negotiable. Each has a specific reason from the research that led to this design.

**Markdown + JSONL only. No standalone JSON files.**
State files, knowledge packs, findings, and hunt logs use markdown. Structured records use JSONL (one JSON object per line). JSON files can't be appended to without parsing the whole file, can't be tailed, can't be grepped effectively, and a single syntax error breaks the whole file. This follows the trace37 pattern — a production system that survived 15+ context compactions in a single autonomous hunt using this exact format.

**A detection is not a finding.**
Semgrep flagging `html_safe` is a detection, not a finding. The agent confirming that user-controlled input reaches that `html_safe` call through an unprotected taint path is a candidate finding. The agent attempting to disprove its own finding and failing is a validated finding. This distinction is the primary mechanism for controlling false positives. Semgrep alone produces 88% false positives for some vuln classes. The multi-stage pipeline is how production systems (XBOW, Claude Code Security) get false positive rates below 10%.

**Self-disproval is built into the agent, not a separate step.**
Before reporting any finding, the agent must attempt to disprove it: "Is there a sanitizer I missed? Is this code path actually reachable? Does a `before_action` prevent this? Does Strong Parameters constrain this input?" This is Claude Code Security's approach — their self-verification loop where the agent tries to break its own findings is the most effective hallucination mitigation in production. Build this into the skill file's guardrails section, not as a separate post-processing step.

**Methodology-only knowledge packs.**
The knowledge pack for the taint hunter contains: how to hunt (methodology), what Rails sources/sinks/sanitizers exist (framework patterns), and domain terminology to focus attention (research terms). It does NOT contain specific examples of bugs other people found. Specific examples anchor the agent to known patterns and can reduce its ability to find novel vulnerabilities. Whether adding additional knowledge levels helps or hurts is tested in Phase 2. Phase 1 establishes the methodology-only baseline.

**Leave context window space for reasoning.**
The knowledge pack, skill file, and code context should not consume the entire context window. The agent needs space for its own reasoning — tracing data flow, exploring hypotheses, reading related code. Don't dump everything in at once. Load the skill file and knowledge pack, then let the agent use tools to pull code as needed.

**Findings are one markdown file each.**
Each candidate finding is a separate markdown file in `memory/findings/candidates/`. Each confirmed finding is a separate file in `memory/findings/confirmed/`. Each rejected finding is in `memory/findings/rejected/`. This makes findings human-reviewable, git-trackable, and individually addressable. The filename should include a timestamp and short description: `2026-03-11-sqli-projects-finder.md`.

---

## What Phase 1 produces

### 1. Persistent memory layer

The directory structure under `memory/` as specified in the overview doc. All write operations are append-only where possible (ledger, dead ends, worklog, analyzed paths). Status file is the one exception — it's overwritten to reflect current state.

Files to create and maintain:

`memory/hunt_state/status.md` — Current state. Overwritten on each update.
```markdown
# Hunt Status
- **Target:** GitLab CE vXX.X
- **Current area:** app/finders/
- **Current hypothesis:** Checking ProjectsFinder for SQL injection via search param
- **Agent:** taint-hunter
- **Last updated:** 2026-03-11 14:30
```

`memory/hunt_state/ledger.md` — Append-only log of findings.
```markdown
# Hunt Ledger

## 2026-03-11 14:45
- **CANDIDATE** SQLi in ProjectsFinder#execute via params[:search]
  - File: app/finders/projects_finder.rb:142
  - Confidence: medium
  - Status: pending validation
```

`memory/hunt_state/dead_ends.md` — Append-only log of investigated paths that yielded nothing.
```markdown
# Dead Ends

## 2026-03-11 13:20
- **Path:** app/controllers/projects_controller.rb#index
- **Reason:** All params go through Strong Parameters, no string interpolation in queries
- **Time spent:** ~5 min
```

`memory/hunt_state/worklog.md` — Append-only timestamped activity log.
```markdown
# Worklog

2026-03-11 13:00 — Started hunt session. Loaded attack surface map.
2026-03-11 13:05 — Running Semgrep scan against app/finders/
2026-03-11 13:12 — Semgrep returned 14 detections. Triaging.
2026-03-11 13:15 — 6 detections passed triage. Starting analysis of ProjectsFinder.
```

`memory/hunt_state/analyzed_paths.jsonl` — Append-only record of what's been analyzed.
```
{"file": "app/finders/projects_finder.rb", "type": "taint-sqli", "ts": "2026-03-11T13:45:00", "result": "candidate"}
{"file": "app/finders/issues_finder.rb", "type": "taint-sqli", "ts": "2026-03-11T14:10:00", "result": "clean"}
```

### 2. Context recovery protocol

When the agent starts a new session or recovers from context compaction, it must:

1. Read `memory/hunt_state/status.md` → know current target and hypothesis
2. Read `memory/hunt_state/ledger.md` (last 20 entries) → know what's been found
3. Read `memory/hunt_state/dead_ends.md` (last 10 entries) → know what NOT to retry
4. Read `memory/hunt_state/worklog.md` (last 5 entries) → know recent activity
5. Scan `memory/hunt_state/analyzed_paths.jsonl` → know what's covered
6. Resume or pivot based on recovered state

This protocol should be documented in the CLAUDE.md / skill file so the agent knows how to recover. This is not optional infrastructure — it's what makes autonomous operation possible across context compactions.

### 3. Attack surface mapper

A Python script (`scripts/parse_gitlab_routes.py`) that:
- Parses GitLab's `config/routes.rb` (and any route files it references)
- Maps routes to controllers and actions
- Identifies `before_action` filters on each controller (especially authentication/authorization)
- Identifies which actions handle user input (params)
- Outputs `memory/targets/gitlab/attack_surface.md` (human-readable prioritized list) and `memory/targets/gitlab/routes_map.jsonl` (structured data)

Priority ranking should weight: API endpoints over UI pages, endpoints without auth filters higher, endpoints that handle file uploads or process user content, finders/services that construct database queries.

This doesn't need to be perfect. It needs to produce a reasonable prioritized list that the agent can work through systematically.

### 4. Deterministic scanner wrappers

Python scripts in `tools/scanners/` that run Semgrep and Brakeman against specified targets and produce normalized output.

`tools/scanners/semgrep_runner.py`:
- Takes a target path or list of files
- Runs Semgrep with relevant rulesets: `p/ruby`, `p/rails`, and any brakeman-ported rules available in the Semgrep registry (`ruby.rails.security.brakeman.*`)
- Outputs detections as JSONL (not SARIF — keep it simple for Phase 1). Each line: `{"file": "...", "line": N, "rule": "...", "severity": "...", "message": "...", "snippet": "..."}`
- Filters out test files (`spec/`, `test/`), vendored code (`vendor/`), migrations (`db/migrate/`)

`tools/scanners/brakeman_runner.py`:
- Runs Brakeman against the GitLab source
- Parses the JSON output into the same JSONL format
- Note: Brakeman scans the full Rails app — it may take several minutes on GitLab's codebase

### 5. Heuristic triage and escalation router

`tools/triage/heuristic_filter.py`:
- Reads scanner JSONL output
- Deduplicates by file + line + rule category
- Filters known false positive patterns (common in large Rails apps)
- Outputs filtered JSONL

`tools/triage/escalation_router.py`:
- Reads filtered JSONL
- Matches each detection against escalation rules (see `config/escalation_rules.yaml` in overview doc)
- For Phase 1: all injection-related detections route to taint-hunter
- Outputs escalation queue as JSONL: `{"detection": {...}, "agent": "taint-hunter", "vuln_class": "sqli", "priority": N}`

### 6. Taint hunter skill file

The core skill file at `agents/skills/taint_hunter.md`. This is the CLAUDE.md for the hunting agent. Structure it with these sections (following the Crash Override five-component framework):

**Persona** — Senior Rails security researcher specializing in injection vulnerabilities.

**Context** — Target is GitLab CE (Ruby on Rails monolith). Key architectural details: ActiveRecord ORM, Grape API framework for REST APIs, GraphQL layer, DeclarativePolicy for authorization, Strong Parameters. Key directories: `app/controllers/`, `app/finders/`, `app/services/`, `app/models/`, `lib/api/`, `app/graphql/`.

**Related Research Terms** — Organize by sub-class:
- SQLi: `ActiveRecord, string interpolation, where, find_by_sql, sanitize_sql, Arel, pluck, order, group, having, joins, connection.execute, params, permit, require`
- XSS: `html_safe, raw, content_tag, render inline, ERB, Haml, sanitize, SafeBuffer, ActionView`
- Command injection: `system, exec, backtick, Open3, IO.popen, Kernel.open, spawn, %x`
- SSRF: `Net::HTTP, open-uri, URI.open, Faraday, HTTParty, RestClient, Typhoeus`

**Methodology** — Step-by-step hunting process:
1. Check the escalation queue for routed detections
2. For each detection, read the flagged code and surrounding context
3. Identify the user-controlled source (where does tainted data enter?)
4. Follow the data through the call chain (controller → service/finder → model)
5. Check for sanitizers at each step (Strong Parameters, type casting, allowlists, `sanitize()`)
6. If tainted data reaches a dangerous sink without sanitization, draft a finding
7. Before reporting: attempt self-disproval (see Guardrails)
8. Write finding to `memory/findings/candidates/` as markdown
9. Update ledger, worklog, and analyzed paths
10. Move to the next detection or select a new target from the attack surface map

**Output Format** — Each finding as a markdown file with:
```
# [Title: one-line summary]

## Location
- File: [path]:[line_range]
- Route: [HTTP method + path that reaches this code]
- Function: [method name]

## Taint Path
- **Source:** [where tainted data enters, e.g., params[:search]]
- **Path:** [source → through what methods/files → sink]
- **Sink:** [dangerous operation, e.g., where("name LIKE '#{search}'")]

## Reasoning
[Step-by-step explanation of why this is exploitable]

## Self-Disproval Attempt
[What the agent checked to try to disprove the finding and why it still holds]
- Checked for sanitizer: [result]
- Checked before_actions: [result]
- Checked Strong Parameters: [result]
- Checked if path is reachable: [result]

## Confidence
[high/medium/low] — [justification]

## Suggested Fix
[How to remediate, e.g., use parameterized query]

## Scanner Evidence
- Semgrep rule: [rule ID that flagged this]
- Brakeman check: [check name if applicable]
```

**Guardrails:**
- Do NOT speculate about vulnerabilities you cannot trace through the code
- Cite the specific file and line for every claim in your taint path
- If you cannot complete the taint path from source to sink, mark confidence as LOW and explain the gap
- Before reporting ANY finding, attempt to disprove it:
  - Search for sanitizers between source and sink
  - Check if `before_action` filters prevent untrusted access
  - Check if Strong Parameters (`permit`) constrain the input
  - Check if the code path is actually reachable (not dead code)
  - If you find evidence that breaks the taint path, do NOT report the finding — log it as a dead end instead
- After self-disproval, write the finding only if you cannot break it
- Update persistent memory files after every finding, dead end, or significant action

**Context Recovery:**
[Include the full context recovery protocol here — the 6-step sequence from the overview doc. The agent must know how to recover from compaction.]

### 7. Knowledge pack for taint analysis

Markdown files in `knowledge/packs/taint/`:

`methodology.md` — The hunting methodology (can largely be extracted from the skill file's methodology section, but this is the reference document that stays stable even if the skill file is later optimized by DSPy).

`sources_sinks.md` — Rails source/sink/sanitizer catalog. Organize by vuln sub-class (SQLi, XSS, command injection, SSRF). For each: list the dangerous APIs, the common safe alternatives, and the Rails-specific patterns. This is framework reference material, not examples of bugs.

`research_terms.md` — Domain terminology organized by sub-class. Same content as the Related Research Terms section in the skill file, but as a standalone reference.

### 8. Validation layer

`tools/validation/deterministic_confirmer.py`:
- Takes a candidate finding (markdown file)
- Extracts the source, sink, and file location
- Runs a targeted Semgrep scan with taint mode to verify the claimed taint path
- Outputs: confirmed / unconfirmed / inconclusive with reason

`tools/validation/adversarial_reviewer.py`:
- Takes a candidate finding (markdown file)
- Sends the finding + relevant code to a second LLM call with the prompt: "You are a skeptical security reviewer. Your job is to find flaws in this vulnerability report. Challenge every claim. Look for sanitizers, authorization checks, or other defenses the analyst may have missed. If the finding is invalid, explain why."
- Outputs: the reviewer's assessment

### 9. Simple coordinator

For Phase 1, the coordinator is instructions in the CLAUDE.md, not a Python orchestrator. The agent self-manages by following the skill file's methodology: read the escalation queue, process detections, update memory, move to the next target. The attack surface map and scanner output provide the work queue.

The coordinator logic that needs to be in the CLAUDE.md:
1. On session start: run context recovery protocol
2. If no current work: check escalation queue for pending detections
3. If escalation queue is empty: run scanners against the next priority area from the attack surface map, triage the output, populate the queue
4. Process detections one at a time through the full pipeline
5. After each finding or dead end: update all memory files
6. Periodically: update status.md with current state (so recovery works)

### 10. Evaluation baseline

`evaluation/metrics.py`:
- Reads confirmed findings and rejected findings
- Counts true positives, false positives, false negatives (against known GitLab CVEs if available)
- Tracks context tokens used per finding (from metadata)
- Outputs a summary report

`evaluation/ground_truth/gitlab_known_vulns.jsonl`:
- Known GitLab CVEs that can be used to verify findings
- Populate with a handful of public GitLab security advisories that include file/component information
- This is what lets you measure whether the agent is finding real things

---

## Build order

1. **Directory structure + persistent memory files** — create the skeleton. Empty files with headers.
2. **Attack surface mapper** — produces the target list that drives everything.
3. **Scanner wrappers** — Semgrep and Brakeman. Test against a small portion of GitLab.
4. **Heuristic triage + escalation router** — filter scanner output, produce queue.
5. **Knowledge pack** — methodology.md, sources_sinks.md, research_terms.md.
6. **Skill file** — the taint_hunter.md with full Crash Override structure.
7. **Validation tools** — deterministic confirmer + adversarial reviewer.
8. **Evaluation baseline** — metrics script + ground truth data.
9. **Integration test** — run the full pipeline against one GitLab controller. Scanner → triage → agent → self-disproval → validation. Verify findings are written to memory. Verify context recovery works after simulated compaction.

---

## What success looks like for Phase 1

- The pipeline runs end-to-end: scanners produce detections, triage filters them, the agent analyzes flagged code, self-disproval runs, validation confirms or rejects.
- Findings are markdown files with complete taint paths, reasoning, and self-disproval evidence.
- Persistent memory works: the agent can recover from context compaction and resume without repeating work.
- Baseline metrics exist: we know the TP rate, FP rate, token usage, and time per analysis.
- We can compare: agent findings vs. scanner-only findings to measure the LLM's marginal contribution.
- The system has identified at least some code areas worth investigating, even if the findings need human validation.

## What success does NOT look like

- A system that finds 50 "vulnerabilities" that are all false positives.
- An agent that dumps scanner output without tracing taint paths.
- A knowledge pack full of specific vulnerability examples (that's Phase 2 testing).
- Over-engineered infrastructure (vector databases, embeddings, DSPy) that belongs in later phases.
- A system that can't recover from context loss.
