#!/usr/bin/env bash
# PreToolUse hook for Bash — validate staged files before git commit.
# Exit 2 if staged files fail validation. Exit 0 if not a commit or all checks pass.

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('command',''))" 2>/dev/null)

if [[ -z "$CMD" ]]; then
    exit 0
fi

# Only act on git commit commands
if ! echo "$CMD" | grep -qE '(^|[;&|]\s*)git\s+commit'; then
    exit 0
fi

ERRORS=""

# Get staged files
STAGED_FILES=$(git diff --cached --name-only 2>/dev/null || true)

if [[ -z "$STAGED_FILES" ]]; then
    exit 0
fi

while IFS= read -r f; do
    # Skip if file doesn't exist (deleted files)
    if [[ ! -f "$f" ]]; then
        continue
    fi

    EXT="${f##*.}"

    case "$EXT" in
        py)
            if ! python3 -m py_compile "$f" 2>/dev/null; then
                ERRORS="${ERRORS}STAGED FILE SYNTAX ERROR: $f failed Python compilation\n"
            fi
            ;;
        yaml|yml)
            if ! python3 -c "import yaml; yaml.safe_load(open('$f'))" 2>/dev/null; then
                ERRORS="${ERRORS}STAGED FILE SYNTAX ERROR: $f is not valid YAML\n"
            fi
            ;;
    esac
done <<< "$STAGED_FILES"

if [[ -n "$ERRORS" ]]; then
    echo -e "COMMIT BLOCKED — staged files have errors:\n$ERRORS" >&2
    exit 2
fi

exit 0
