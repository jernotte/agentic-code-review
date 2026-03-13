# GitLab Security Research Harness — Architecture Overview (v2)

## Purpose

An autonomous bug bounty system that performs code review against the GitLab open-source codebase (Ruby on Rails) to identify high-quality security vulnerabilities. The system uses specialized AI agents backed by curated knowledge, persistent memory, and deterministic tooling to match or exceed top-tier human bug bounty hunters.

## Design Principles

**Test, don't commit.** Every major component sits behind a defined interface. Implementations behind interfaces are swappable. We don't know what works best for code access, knowledge retrieval, or prompt structure — so we build to test alternatives cheaply.

**Simple first, optimize later.** Phase 1 uses flat files, markdown, and JSONL. Vector databases, embeddings, and DSPy optimization come in later phases, informed by real data about what agents actually need.

**Persistent memory is infrastructure, not a feature.** From day one, agents survive context compaction, track what's been analyzed, accumulate findings, and never repeat dead-end work. Markdown for state and knowledge (human-readable, editable, linkable). JSONL for structured records (append-only, greppable, streamable). No standalone JSON files.

**A detection is not a finding.** Borrowed from trace37's proven pipeline: broad deterministic scanning produces detections. Heuristic evaluation filters noise. LLM analysis of confirmed signals produces candidate findings. Adversarial self-disproval validates candidates. Only validated candidates become findings. This multi-stage pipeline is the primary mechanism for controlling false positives.

**Start with methodology-only knowledge, test additions.** trace37's system finds real bugs using skill files that encode *how to hunt* — not databases of *what others found*. That's our proven baseline. Whether adding root cause knowledge, specific examples, or retrieved patterns improves or degrades agent performance is an empirical question we test in Phase 2, not an assumption we bake in.

**Hybrid deterministic-plus-LLM is the winning formula.** Validated independently by XBOW, Semgrep, AISLE, and multiple academic teams: deterministic tools for detection + LLM reasoning for contextual validation + adversarial verification. Neither alone achieves acceptable accuracy.

**Coordinator from day one.** The orchestration layer — reading hunt state, selecting targets, dispatching specialists, handling failures — is not a Phase 4 feature. A simple coordinator runs from the first agent session, even if dispatch is initially manual.

---

## Core Pipeline

This is the central processing flow. Every analysis run follows this sequence, regardless of which agent or vulnerability class is being targeted.

```
┌──────────────────────────────────────────────────────────────────┐
│ 1. ATTACK SURFACE MAPPING                                        │
│    Parse routes.rb → controllers → before_actions → auth filters │
│    Prioritize by: trust boundary crossings, recent changes,      │
│    high-value functionality (auth, file handling, deserialization)│
│    Output: prioritized target list (markdown)                    │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│ 2. BROAD DETERMINISTIC SCAN                                      │
│    Semgrep (p/ruby, brakeman rules, taint mode)                  │
│    Brakeman (33 check categories)                                │
│    CodeQL (security-extended suite, 47+ Ruby queries)            │
│    Output: detections — flagged locations with rule IDs (SARIF)  │
│    These are DETECTIONS, not findings.                           │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│ 3. HEURISTIC TRIAGE                                              │
│    Filter known noise (test files, vendored code, migrations)    │
│    Deduplicate by location + rule type                           │
│    Route to appropriate specialist agent based on detection type  │
│    Escalation rules map detection categories to agent skills:    │
│      SQL interpolation flag    → taint-hunter                    │
│      Missing auth check        → auth-hunter                     │
│      html_safe/raw usage       → taint-hunter (XSS mode)        │
│      Unsafe deserialization    → taint-hunter (deser mode)       │
│      Known CVE pattern match   → variant-hunter                  │
│    Output: escalation queue (JSONL)                              │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│ 4. SPECIALIST AGENT ANALYSIS                                     │
│    Agent receives:                                               │
│      - Code context (via Code Access Interface)                  │
│      - Knowledge pack for its mode (via Knowledge Interface)     │
│      - Detection details from step 2                             │
│      - Hunt state from persistent memory                         │
│    Agent reasons about the code: traces data flow, checks auth   │
│    logic, evaluates exploitability                               │
│    Output: candidate finding with reasoning chain (JSONL)        │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│ 5. SELF-DISPROVAL + VALIDATION                                   │
│    Agent attempts to disprove its own finding before reporting:   │
│      "Can I find a sanitizer I missed?"                          │
│      "Is this code path actually reachable?"                     │
│      "Does a before_action prevent this?"                        │
│    Then deterministic re-confirmation:                           │
│      Semgrep verifies taint path still holds                     │
│      Brakeman cross-checks finding category                     │
│    Then adversarial LLM review:                                  │
│      Second LLM call challenges the finding's validity           │
│    Output: validated finding or rejection (JSONL)                │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│ 6. DYNAMIC CONFIRMATION (when available)                         │
│    Generate PoC against running GitLab test instance              │
│    SQLi: craft request, check error-based/time-based response    │
│    IDOR: attempt access as different user                        │
│    XSS: inject payload, confirm execution                        │
│    Output: confirmed finding with PoC evidence                   │
└──────────────────────┬───────────────────────────────────────────┘
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│ 7. HUMAN-IN-THE-LOOP REVIEW + REPORTING                         │
│    AI discovers, human validates and ships.                      │
│    Structured report: CVSS, CWE, PoC, remediation guidance       │
│    Format matches HackerOne/GitLab submission requirements        │
└──────────────────────────────────────────────────────────────────┘
```

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      COORDINATOR                            │
│  Reads hunt state → maps attack surface → runs broad scans  │
│  Triages detections → dispatches specialists → tracks results│
│  Handles failures, dedup, context recovery                  │
└─────────┬──────────┬──────────┬──────────┬─────────────────┘
          │          │          │          │
          ▼          ▼          ▼          ▼
   ┌──────────┐┌──────────┐┌──────────┐┌──────────┐
   │  TAINT   ││  AUTH/   ││ VARIANT  ││  CONFIG/ │
   │  HUNTER  ││  IDOR    ││  HUNTER  ││   DEPS   │
   │          ││  HUNTER  ││          ││  HUNTER  │
   └────┬─────┘└────┬─────┘└────┬─────┘└────┬─────┘
        │           │           │           │
        └───────────┴─────┬─────┴───────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  SHARED INTERFACE LAYER                      │
│                                                             │
│  ┌─────────────┐ ┌─────────────┐ ┌────────────────────┐    │
│  │ Code Access  │ │ Knowledge   │ │ Deterministic Tools │    │
│  │ [SWAPPABLE]  │ │ Retrieval   │ │ (Semgrep, CodeQL,   │    │
│  │             │ │ [SWAPPABLE] │ │  Brakeman, Git)     │    │
│  └─────────────┘ └─────────────┘ └────────────────────┘    │
│                                                             │
│  Implementations tested behind each interface:              │
│  Code Access:       Knowledge:         Tools:               │
│  • Raw file read    • Flat markdown     • Semgrep CLI       │
│  • AST-chunked      • BM25 search       • CodeQL queries    │
│  • Semgrep-guided   • Dense retrieval    • Brakeman          │
│  • CodeQL DB query  • Hybrid RAG         • Git log/diff      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   PERSISTENT MEMORY                         │
│  All markdown + JSONL. Human-readable. Git-trackable.       │
│                                                             │
│  hunt_state/              findings/        knowledge/       │
│  ├── ledger.md            ├── confirmed/   ├── packs/       │
│  ├── status.md            │   └── *.md     │   ├── taint/   │
│  ├── dead_ends.md         ├── candidates/  │   ├── auth/    │
│  ├── worklog.md           │   └── *.md     │   ├── variant/ │
│  └── analyzed_paths.jsonl └── rejected/    │   └── config/  │
│                               └── *.md     └── corpus/      │
│  targets/gitlab/                               └── *.jsonl  │
│  ├── attack_surface.md                                      │
│  ├── routes_map.jsonl                                       │
│  └── tech_profile.md                                        │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   VALIDATION LAYER                           │
│                                                             │
│  Self-disproval  →  Deterministic  →  Adversarial  →  Dynamic│
│  (agent tries to    (Semgrep/         (second LLM    (PoC vs │
│   break its own     Brakeman          challenges     live     │
│   finding)          re-confirm)       finding)       GitLab) │
└─────────────────────────────────────────────────────────────┘
```

---

## Interface Definitions

These are the contracts between components. Implementations change; interfaces don't.

### Code Access Interface

The principle from Snyk's CodeReduce research: **program analysis should drive context selection, not text similarity.** The interface returns minimal relevant code, not entire files.

```
Input:  target_spec (file path, function name, route, or detection from scanner)
Output: CodeContext {
    primary_code: str          # The code under analysis
    related_code: list[str]    # Supporting context (callers, callees, configs)
    metadata: {
        file_path: str
        line_range: (int, int)
        framework_context: str  # "Rails controller", "ActiveRecord model", etc.
        auth_filters: list[str] # before_actions that apply to this code path
        route: str              # The HTTP route that reaches this code
    }
}
```

Phase 1: Raw file read + grep for related files.
Phase 2 alternatives: AST-chunked via tree-sitter, Semgrep-guided (run Semgrep first, use flagged locations to pull minimal context), CodeQL database queries for cross-procedural context.

### Knowledge Retrieval Interface

Phase 1 baseline follows trace37's proven pattern: methodology-only knowledge packs. Phase 2 tests whether adding additional knowledge levels (root causes, specific examples, retrieval from corpus) improves or degrades performance.

```
Input:  vuln_class: str  # "sqli", "xss", "idor", etc.
        query: str       # Optional, for retrieval-based implementations

Output: KnowledgeContext {
    methodology: str           # How to hunt this vuln class (skill file content)
    research_terms: list[str]  # Domain terminology anchors for attention focusing
    framework_patterns: dict   # Rails-specific sources/sinks/anti-patterns
    supplemental: list[str]    # Additional context (empty in Phase 1, tested in Phase 2)
}
```

Phase 1: Load the agent's markdown knowledge pack directly (methodology.md + research_terms.md + sources_sinks.md). No retrieval, no mode logic.
Phase 2 experiments: Add root cause descriptions — does it help? Add retrieved specific examples — does it help or hurt? Test BM25 vs. dense retrieval vs. none. Test mode-dependent injection (hunting gets different knowledge than variant analysis).

### Persistent Memory Interface

```
# Write operations (append-only where possible)
log_finding(finding: dict) → None           # Append to candidates.jsonl
log_dead_end(path: str, reason: str) → None # Append to dead_ends.md
update_status(target: str, hypothesis: str, agent: str) → None  # Overwrite status.md
append_worklog(entry: str) → None           # Append timestamped line to worklog.md
mark_path_analyzed(file_path: str, analysis_type: str) → None   # Append to analyzed_paths.jsonl

# Read operations (for context recovery after compaction)
get_hunt_state() → HuntState                # Parse status.md
get_analyzed_paths() → set[str]             # Parse analyzed_paths.jsonl
get_dead_ends(last_n: int) → list[dict]     # Tail dead_ends.md
get_recent_findings(last_n: int) → list[dict]  # Tail candidates + confirmed
get_worklog(last_n: int) → list[str]        # Tail worklog.md
```

All phases: Flat markdown + JSONL files on disk. No database. This is the trace37 Obsidian vault pattern adapted for code review.

---

## Skill File Structure

Each specialist agent is defined by a skill file (markdown) following the Crash Override five-component framework plus the "Related Research Terms" technique. These are the files that DSPy will later optimize.

```markdown
# Taint Hunter — Rails SQL Injection

## Persona
You are a senior application security researcher specializing in Ruby on Rails
injection vulnerabilities. You have deep expertise in ActiveRecord query patterns,
Rails parameter handling, and taint flow analysis.

## Context
Target: GitLab CE/EE (Ruby on Rails monolith)
Framework: Rails with ActiveRecord ORM, Grape API, GraphQL
Auth: DeclarativePolicy gem (Ability.allowed? checks)
Key paths: app/controllers/, app/finders/, app/services/, lib/api/

## Related Research Terms
ActiveRecord, string interpolation, where clause, find_by_sql, sanitize_sql,
Arel, pluck, order, group, having, joins, connection.execute, quoted_table_name,
params, cookies, request.env, Strong Parameters, permit, require

## Methodology
[Step-by-step hunting process — trace from source to sink]
1. Identify entry point (route → controller action)
2. Map user-controlled inputs (params, headers, cookies)
3. Follow data through controller → service/finder → model
4. Check for parameterized queries vs string interpolation at each sink
5. Verify no sanitizer intervenes along the path
6. Check if before_actions or Strong Parameters constrain the input

## Output Format
For each finding, produce a markdown document with:
- Title: One-line summary
- Location: file:line_range
- Source: Where tainted data enters
- Sink: Where it reaches a dangerous operation
- Taint path: Source → intermediate steps → sink
- Reasoning: Why this is exploitable (step by step)
- Self-disproval attempt: "I tried to find a sanitizer/guard and..."
- Confidence: high/medium/low with justification
- Suggested fix: Parameterized query or other remediation

## Guardrails
- Do NOT speculate about vulnerabilities you cannot trace through the code
- Cite the specific file and line for every claim
- If you cannot complete the taint path, mark confidence as LOW and explain the gap
- Attempt to disprove your finding before reporting it
```

Agent configs (YAML, following seclab-taskflow-agent's pattern) tie skills to knowledge packs and tools:

```yaml
# agents/configs/taint.yaml
name: taint-hunter
skill: skills/taint_hunter.md
knowledge_pack: knowledge/packs/taint/
tools:
  - semgrep
  - brakeman
  - codeql
  - git
escalation_sources:
  - "CheckSQL"
  - "CheckCrossSiteScripting"
  - "CheckExecute"
  - "CheckSend"
  - "taint-mode-*"
output_dir: memory/findings/candidates/
```

---

## Escalation Rules

Borrowed from trace37's deliberate routing pattern. Detections from the broad scan are routed to the correct specialist based on what kind of analysis they need. The routing is intentional — a DOM sink detection needs taint tracing first, not exploitation.

```yaml
# config/escalation_rules.yaml
rules:
  - detection: "CheckSQL|sql-injection|sqli"
    agent: taint-hunter
    mode: hunting
    vuln_class: sqli
    note: "Trace taint path from source to SQL sink"

  - detection: "CheckCrossSiteScripting|xss|html_safe|raw"
    agent: taint-hunter
    mode: hunting
    vuln_class: xss
    note: "Trace taint path to rendering sink — html_safe alone is not a finding"

  - detection: "CheckExecute|command-injection|system|exec"
    agent: taint-hunter
    mode: hunting
    vuln_class: command_injection

  - detection: "missing-authorization|idor|insecure-direct-object"
    agent: auth-hunter
    mode: hunting
    vuln_class: idor
    note: "Check DeclarativePolicy — Model.find(params[:id]) without Ability check"

  - detection: "known-cve-pattern|variant-match"
    agent: variant-hunter
    mode: variant
    vuln_class: from_seed
    note: "Seed with matching CVE, search for unfixed variants"

  - detection: "vulnerable-dependency|outdated-gem"
    agent: config-hunter
    mode: validation
    vuln_class: dependency
```

---

## Context Recovery Protocol

When an agent hits context compaction or a new session starts, it follows this recovery sequence. This is identical to trace37's proven pattern that survived 15+ compactions in a single hunt.

```
1. Read memory/hunt_state/status.md
   → Current target, current hypothesis, which agent was running

2. Read memory/hunt_state/ledger.md (last 20 entries)
   → What has been found so far

3. Read memory/hunt_state/dead_ends.md (last 10 entries)
   → What NOT to try again

4. Read memory/hunt_state/worklog.md (last 5 entries)
   → What was being done immediately before compaction

5. Scan memory/hunt_state/analyzed_paths.jsonl
   → Which code paths are already covered

6. Resume from recovered state or pivot if prior approach was failing
```

---

## Persistent Memory Structure

Markdown for knowledge and state. JSONL for streaming/append-only structured records. No standalone JSON files. Human-readable and git-trackable.

```
harness/
├── memory/
│   ├── hunt_state/
│   │   ├── ledger.md              # Append-only: what has been found
│   │   ├── status.md              # Overwritten: current target, hypothesis, agent
│   │   ├── dead_ends.md           # Append-only: paths that yielded nothing
│   │   ├── worklog.md             # Append-only: timestamped activity log
│   │   └── analyzed_paths.jsonl   # Append-only: {"file": "...", "type": "...", "ts": "..."}
│   │
│   ├── findings/
│   │   ├── confirmed/             # One markdown file per confirmed finding
│   │   ├── candidates/            # One markdown file per unvalidated candidate
│   │   └── rejected/              # One markdown file per rejected finding (FP training data)
│   │
│   └── targets/
│       └── gitlab/
│           ├── attack_surface.md  # Routes → controllers → auth filters
│           ├── routes_map.jsonl   # {"route": "...", "controller": "...", "auth": [...]}
│           └── tech_profile.md    # Framework version, key gems, arch notes
│
├── knowledge/
│   ├── packs/                         # Phase 1: methodology-only baseline
│   │   ├── taint/
│   │   │   ├── methodology.md         # How to hunt injection vulns in Rails
│   │   │   ├── sources_sinks.md       # Rails source/sink/sanitizer catalog
│   │   │   └── research_terms.md      # Domain terminology per sub-class
│   │   ├── auth/
│   │   │   ├── methodology.md
│   │   │   ├── gitlab_policies.md     # DeclarativePolicy patterns
│   │   │   └── research_terms.md
│   │   ├── variant/
│   │   │   ├── methodology.md         # Big Sleep / Trail of Bits workflow
│   │   │   └── research_terms.md
│   │   └── config/
│   │       ├── methodology.md
│   │       ├── rails_checklist.md     # Security config expectations
│   │       └── research_terms.md
│   │
│   ├── supplemental/                  # Phase 2: tested additions
│   │   ├── root_causes/              # Vul-RAG Level 2 — does adding this help?
│   │   │   ├── injection.md
│   │   │   └── auth_bypass.md
│   │   └── examples/                 # Level 1 — does adding this help or hurt?
│   │       └── seed_cves.jsonl
│   │
│   └── corpus/                        # Phase 2: built for retrieval testing
│       ├── hackerone_gitlab.jsonl      # Normalized H1 findings
│       ├── ruby_advisories.jsonl      # Normalized gem advisories
│       ├── gitlab_cves.jsonl          # GitLab security releases
│       └── rails_patterns.jsonl       # General Rails vuln patterns
│
├── tools/
│   ├── code_access/                   # Code Access Interface implementations
│   │   ├── __init__.py                # Interface definition
│   │   ├── raw_reader.py              # Phase 1: simple file reading
│   │   ├── ast_chunker.py             # Phase 2: tree-sitter based
│   │   └── semgrep_guided.py          # Phase 2: Semgrep-flagged locations
│   │
│   ├── knowledge_retrieval/           # Knowledge Retrieval Interface implementations
│   │   ├── __init__.py                # Interface definition + mode logic
│   │   ├── flat_loader.py             # Phase 1: load markdown packs directly
│   │   ├── bm25_retriever.py          # Phase 2: keyword search over corpus
│   │   └── dense_retriever.py         # Phase 2: FAISS + embeddings
│   │
│   ├── scanners/                      # Deterministic tool wrappers
│   │   ├── semgrep_runner.py          # Run scans, output SARIF
│   │   ├── brakeman_runner.py         # Run scans, output SARIF
│   │   └── codeql_runner.py           # Run queries, output SARIF
│   │
│   ├── triage/
│   │   ├── heuristic_filter.py        # Noise filtering, dedup
│   │   └── escalation_router.py       # Map detections to agents via rules
│   │
│   └── validation/
│       ├── deterministic_confirmer.py  # Semgrep/Brakeman re-check
│       ├── adversarial_reviewer.py     # Second LLM challenges finding
│       └── dynamic_tester.py           # Phase 4: PoC against live GitLab
│
├── agents/
│   ├── skills/                        # Skill files (markdown, Crash Override format)
│   │   ├── taint_hunter.md            # Phase 1
│   │   ├── auth_hunter.md             # Phase 2
│   │   ├── variant_hunter.md          # Phase 3
│   │   └── config_hunter.md           # Phase 4
│   │
│   ├── configs/                       # YAML agent configs (seclab-taskflow pattern)
│   │   ├── taint.yaml
│   │   ├── auth.yaml
│   │   ├── variant.yaml
│   │   └── config.yaml
│   │
│   ├── dspy_modules/                  # Phase 3: DSPy optimizable signatures
│   │   ├── taint_analyzer.py
│   │   ├── auth_analyzer.py
│   │   └── variant_analyzer.py
│   │
│   └── coordinator.py                 # Phase 1: simple, grows over phases
│
├── evaluation/
│   ├── ground_truth/                  # Known GitLab CVEs for testing
│   │   └── gitlab_known_vulns.jsonl   # CVEs with file, line, type, severity
│   │
│   ├── metrics.py                     # TP/FP/FN counting, token usage tracking
│   └── compare.py                     # A/B testing between implementations
│
├── scripts/
│   ├── parse_gitlab_routes.py         # Phase 1: attack surface mapping
│   ├── ingest_hackerone.py            # Phase 2: normalize H1 findings to JSONL
│   ├── ingest_ruby_advisory.py        # Phase 2: normalize gem advisories to JSONL
│   ├── build_embeddings.py            # Phase 2: embed corpus into FAISS
│   └── run_dspy_optimization.py       # Phase 3: optimize skill file content
│
└── config/
    ├── harness.yaml                   # Global config (paths, model choices)
    ├── escalation_rules.yaml          # Detection → agent routing
    └── experiments/                   # A/B test configs
        ├── code_access_test.yaml
        ├── retrieval_test.yaml
        └── prompt_test.yaml
```

---

## Phased Build Plan

### Phase 1 — Single Agent End-to-End + Coordinator Skeleton

**Goal:** Taint analysis agent that can analyze GitLab code for injection vulnerabilities through the full pipeline (scan → triage → analyze → self-disprove → validate). Persistent memory operational. Coordinator functional enough to manage a single-agent session. Establish baseline metrics.

**Why taint analysis first (not variant analysis):** The research identifies variant analysis as highest-leverage for autonomous agents. However, variant analysis requires seed CVEs with structured root cause analysis (Phase 2 knowledge corpus) and Semgrep/CodeQL rule generation from patches. Taint analysis has deterministic validation tools available immediately (Semgrep taint mode, Brakeman), known GitLab CVEs for ground truth, and the clearest signal for testing whether knowledge retrieval adds value later.

**Components built:**

Persistent memory layer — full interface, markdown + JSONL implementation. Ledger, status, dead ends, worklog, analyzed paths. Context recovery protocol. This is permanent infrastructure.

Coordinator (simple) — reads attack surface map, dispatches taint-hunter to prioritized targets, tracks what's been analyzed, handles session resumption after compaction. In Phase 1 this is a CLAUDE.md that instructs the agent how to self-manage; it becomes a Python orchestrator in later phases.

Attack surface mapper — `parse_gitlab_routes.py` produces a prioritized target list by parsing `config/routes.rb`, mapping routes to controllers, identifying `before_action` filters. Output: `attack_surface.md` + `routes_map.jsonl`.

Deterministic scanner integration — Semgrep and Brakeman wrappers that produce SARIF output. Run against prioritized targets before agent dispatch. These produce detections, not findings.

Heuristic triage + escalation router — filters noise from scanner output (test files, vendored code, known false patterns), deduplicates, routes to taint-hunter via escalation rules.

Taint hunter skill file — structured per Crash Override framework: persona, context, related research terms, methodology, output format, guardrails. Includes self-disproval instructions.

Knowledge pack v1 for taint analysis — methodology-only baseline following trace37's proven pattern. Markdown files: `methodology.md` (how to hunt), `sources_sinks.md` (Rails source/sink/sanitizer catalog), `research_terms.md` (domain terminology anchors). No root cause descriptions, no specific examples, no retrieval — loaded into context at agent start. This establishes the baseline that Phase 2 tests against.

Validation layer — self-disproval (built into skill file instructions), deterministic re-confirmation (Semgrep re-check of agent's claimed taint path), adversarial LLM review (second call challenges finding).

Agent execution — Claude Code with skill file as CLAUDE.md, knowledge pack accessible in working directory, persistent memory files in working directory. Agent reads escalation queue, picks up routed detections, analyzes them through the full pipeline.

**Baseline metrics:**
- Findings produced (count, severity distribution)
- True positive rate (verified against known GitLab CVEs)
- False positive rate
- Context tokens used per finding
- Time per analysis run
- Comparison: agent findings vs. Semgrep-only vs. Brakeman-only

**Experiments in Phase 1:**
- Semgrep-flagged locations vs. agent choosing its own targets → which finds more?
- Full knowledge pack vs. methodology only (no source/sink catalog) → does the catalog help?
- With vs. without related research terms → measurable difference?
- Self-disproval enabled vs. disabled → does it reduce false positives without killing true positives?

---

### Phase 2 — Knowledge Corpus + Second Agent + Code Access Testing

**Goal:** Build the curated knowledge corpus. Add auth/IDOR agent to prove multi-agent routing works. Test alternative code access implementations. Test whether knowledge retrieval improves findings.

**Depends on:** Phase 1 baseline metrics. Understanding of what knowledge the agent actually needed during Phase 1 hunts.

**Components built:**

Knowledge corpus construction — Python scripts normalize HackerOne GitLab disclosures, Ruby Advisory DB entries, and GitLab security advisories into JSONL. AI-assisted cleaning step normalizes inconsistent formats. Each record follows Vul-RAG's multi-dimensional structure: functional semantics, root cause category, fix pattern. Monthly cron cycle for refresh.

Knowledge retrieval — testable implementations behind the same interface: (a) BM25 keyword search using `rank_bm25`, (b) dense retrieval using Voyage Code-3 embeddings in local FAISS index. Also test *what* gets retrieved: methodology-only (Phase 1 baseline) vs. methodology + root causes vs. methodology + specific examples.

Supplemental knowledge — build the `knowledge/supplemental/` materials: root cause descriptions per vuln class, specific example findings. These are not loaded by default — they're tested as additions to the Phase 1 baseline to measure whether they help or hurt.

Auth/IDOR hunter — skill file, config, knowledge pack. DeclarativePolicy methodology. Research terms for authorization bypass. Escalation rules route missing-auth detections to this agent.

AST-based code access — tree-sitter parsing of Ruby into function-level chunks with metadata. Test against Phase 1's raw file reading.

Coordinator enhancement — now manages two agent types, routes detections to the correct specialist via escalation rules, handles agent failures.

**Experiments in Phase 2:**
- Methodology-only (Phase 1) vs. methodology + root causes → does Level 2 knowledge help?
- Methodology-only vs. methodology + specific examples → does Level 1 knowledge help or hurt creativity?
- BM25 retrieval vs. dense retrieval vs. flat file loading → which retrieval method works?
- AST-chunked context vs. raw file reading → token efficiency and finding quality
- Taint agent vs. auth agent on known auth bypass CVEs → does specialization matter?

---

### Phase 3 — DSPy Optimization + Variant Analysis

**Goal:** Systematically optimize skill file content using DSPy against accumulated findings. Add variant analysis agent. Introduce feedback loop.

**Depends on:** 20-30+ confirmed findings per agent type from Phases 1-2. Knowledge corpus from Phase 2.

**Components built:**

DSPy training data — transform confirmed findings into `dspy.Example` objects. Rejected findings become negative signal. HackerOne GitLab findings supplement.

DSPy signatures per agent — each agent's skill file mapped to an optimizable signature. Optimization targets the instructions and few-shot examples, not the static research terms or persona.

Variant analysis agent — seeded with known GitLab CVEs. Uses Autogrep-style rule generation from patches. Unlike hunting agents, variant analysis inherently requires specific examples as input — that's the definition of the task (find more of *this* pattern). Trail of Bits 5-step workflow. Phase 2 knowledge level testing results inform how much additional context beyond the seed CVE the agent receives.

Feedback loop — confirmed findings added to corpus and DSPy training set. Monthly re-optimization with growing dataset.

**Experiments in Phase 3:**
- Hand-crafted skills vs. DSPy-optimized → which produces better findings?
- BootstrapFewShot vs. MIPROv2 → cost/quality tradeoff
- Cross-model prompt evolution (MulVul technique) vs. DSPy → which wins?
- Variant agent with 1 seed CVE vs. 5 → anchoring vs. coverage

---

### Phase 4 — Full Orchestration + Dynamic Validation

**Goal:** Automated multi-agent orchestration. Dynamic PoC validation against live GitLab. Submission-ready reports.

**Depends on:** Optimized prompts, proven retrieval approach, working multi-agent routing.

**Components built:**

Full coordinator — Python orchestrator running as long-lived process (tmux). Reads attack surface, checks persistent memory, dispatches agents, handles stalls and compaction recovery.

Config/dependency agent — bundler-audit + Rails config checklist. Mostly deterministic.

Dynamic validation — PoC generation and execution against running GitLab test instance.

Report generation — CVSS, CWE, PoC, remediation. HackerOne format.

Knowledge graph (only if Phase 2-3 testing shows flat retrieval is insufficient) — Neo4j with CVE → CWE → CAPEC traversal.

---

## What Gets Tested at Each Interface

| Interface | Phase 1 (Baseline) | Phase 2 (Alternatives) | Phase 3 (Optimized) |
|-----------|-------------------|----------------------|-------------------|
| Code Access | Raw file read | + AST-chunked, + Semgrep-guided | Best from Phase 2 |
| Knowledge | Methodology-only markdown packs | + root causes, + specific examples, + retrieval | + DSPy-selected |
| Agent Prompts | Hand-crafted skill files | Per-agent skill files | + DSPy-optimized |
| Knowledge Level | Methodology only (trace37 baseline) | + root causes? + examples? Mode-dependent? | Best from Phase 2 |
| Validation | Self-disproval + Semgrep + adversarial LLM | + Brakeman cross-check | + Dynamic PoC |
| Context Recovery | Flat markdown + JSONL | Same (proven pattern) | Same |

---

## Key Decision Log

| Decision | Choice | Rationale | Source |
|----------|--------|-----------|--------|
| Runtime | Claude Code with skills | Proven by trace37/RAPTOR. Aligns with existing workflow. | trace37 articles |
| Language | Python | DSPy, Semgrep scripting, ML tooling, tree-sitter. | User preference |
| Memory format | Markdown + JSONL only | trace37 pattern. Human-readable. Append-friendly. No JSON files. | trace37 articles |
| Pipeline model | Detection → triage → analysis → self-disproval → validation | trace37's "detection is not a finding" + Claude Code Security's self-verification | Both research docs |
| Validation | Self-disproval from Phase 1 | Claude Code Security's most sophisticated hallucination mitigation | System design doc |
| First agent | Taint (not variant) | Deterministic tools for validation exist now. Variant needs corpus first. | System design doc |
| Knowledge baseline | Methodology-only packs (trace37 pattern) | Proven by trace37. Whether adding root causes or examples helps is tested in Phase 2, not assumed. | trace37 articles + conversation |
| Skill structure | Crash Override 5-component + research terms | Proven framework + proven attention-focusing technique | RAG knowledge doc |
| Agent configs | YAML (seclab-taskflow pattern) | Testable, version-controlled, DSPy-optimizable | RAG knowledge doc |
| Escalation routing | YAML rules mapping detections to agents | trace37's deliberate routing pattern | trace37 articles |
| Knowledge corpus | Vul-RAG multi-dimensional (Phase 2 build) | 16-24% improvement in research, but needs testing against our methodology-only baseline | RAG knowledge doc |
| DSPy timing | Phase 3 (after 20-30 findings) | Needs training data; premature without ground truth | DSPy research |
| Coordinator timing | Phase 1 (simple, grows) | trace37 has coordinator from minute one | trace37 articles |

---

## Open Questions (Resolved Per Phase)

**Phase 1:**
- What's the optimal context budget split? (code vs. knowledge vs. reasoning space)
- How much of the GitLab codebase can one agent meaningfully cover in a session?
- Does Semgrep pre-filtering help or constrain the agent?
- How effective is self-disproval at reducing FP without killing TP?

**Phase 2:**
- Does adding root cause descriptions improve findings over methodology-only baseline?
- Does adding specific examples help, hurt, or make no difference for hunting agents?
- If examples help variant analysis but hurt hunting — should knowledge injection be mode-dependent?
- BM25 vs. dense vs. hybrid — which retrieval works for security knowledge?
- How many HackerOne findings needed for meaningful retrieval?
- Does AST-chunking measurably improve token efficiency?

**Phase 3:**
- How many training examples per agent for DSPy improvement?
- Cross-model prompt evolution vs. DSPy MIPROv2 — which wins?
- Can the metric function itself be a DSPy module?

**Phase 4:**
- Acceptable false positive rate for fully automated dispatch?
- Multi-step vulnerabilities spanning multiple agents?
- Cost per finding at steady state?
