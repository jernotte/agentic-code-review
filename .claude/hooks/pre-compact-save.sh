#!/usr/bin/env bash
# PreCompact hook — snapshot dev state before context compaction.
# Always exits 0.

RECOVERY_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/recovery"
mkdir -p "$RECOVERY_DIR"

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

{
    echo "# Recovery State"
    echo ""
    echo "**Saved at:** $TS"
    echo ""

    # Recently modified files from activity log
    LOG_FILE="${CLAUDE_PROJECT_DIR:-.}/.claude/logs/activity.jsonl"
    if [[ -f "$LOG_FILE" ]]; then
        echo "## Recently Modified Files"
        echo ""
        tail -20 "$LOG_FILE" | python3 -c "
import sys, json
seen = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        entry = json.loads(line)
        f = entry.get('file','')
        if f and f not in seen:
            seen.append(f)
            print(f'- {f} ({entry.get(\"tool\",\"?\")}, {entry.get(\"ts\",\"?\")})')
    except json.JSONDecodeError:
        pass
" 2>/dev/null
        echo ""
    fi

    # Git status
    echo "## Git Status"
    echo ""
    echo '```'
    git status --short 2>/dev/null || echo "(not a git repo)"
    echo '```'
    echo ""

    # Git diff summary
    echo "## Git Diff Summary"
    echo ""
    echo '```'
    git diff --stat 2>/dev/null || echo "(no changes)"
    echo '```'

} > "$RECOVERY_DIR/last_state.md"

exit 0
