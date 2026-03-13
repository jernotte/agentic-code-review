#!/usr/bin/env bash
# SessionStart hook — inject recovery context on session start/resume/compact.
# Outputs additionalContext JSON if recovery state exists. Always exits 0.

RECOVERY_FILE="${CLAUDE_PROJECT_DIR:-.}/.claude/recovery/last_state.md"

if [[ -f "$RECOVERY_FILE" ]]; then
    CONTENT=$(cat "$RECOVERY_FILE")
    python3 -c "
import json, sys

content = sys.stdin.read()
output = {
    'hookSpecificOutput': {
        'additionalContext': content
    }
}
print(json.dumps(output))
" <<< "$CONTENT"
fi

exit 0
