#!/usr/bin/env bash
# PostToolUse hook for Edit|Write (async) — append-only JSONL activity log.
# Always exits 0.

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_name','unknown'))" 2>/dev/null || echo "unknown")
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))" 2>/dev/null || echo "")

if [[ -z "$FILE_PATH" ]]; then
    exit 0
fi

LOG_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/logs"
mkdir -p "$LOG_DIR"

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SESSION_ID="${CLAUDE_SESSION_ID:-unknown}"

# Use python for safe JSON serialization
python3 -c "
import json, sys
entry = {
    'ts': '$TS',
    'tool': '$TOOL_NAME',
    'file': '$FILE_PATH',
    'session': '$SESSION_ID'
}
print(json.dumps(entry))
" >> "$LOG_DIR/activity.jsonl" 2>/dev/null

exit 0
