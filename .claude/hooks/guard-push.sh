#!/usr/bin/env bash
# PreToolUse hook for Bash — block destructive git operations and rm -rf.
# Exit 2 with explanation on blocked command. Exit 0 otherwise.

set -euo pipefail

INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('command',''))" 2>/dev/null)

if [[ -z "$CMD" ]]; then
    exit 0
fi

# Check for git push (any variant)
if echo "$CMD" | grep -qE '(^|[;&|]\s*)git\s+push(\s|$)'; then
    echo "BLOCKED: git push is not allowed. User pushes manually." >&2
    exit 2
fi

# Check for git reset --hard
if echo "$CMD" | grep -qE '(^|[;&|]\s*)git\s+reset\s+--hard'; then
    echo "BLOCKED: git reset --hard is destructive and not allowed." >&2
    exit 2
fi

# Check for broad git checkout restores (git checkout . or git checkout -- .)
if echo "$CMD" | grep -qE '(^|[;&|]\s*)git\s+checkout\s+(--\s+)?\.(\s|$)'; then
    echo "BLOCKED: broad git checkout restore is destructive and not allowed." >&2
    exit 2
fi

# Check for broad git restore (git restore .)
if echo "$CMD" | grep -qE '(^|[;&|]\s*)git\s+restore\s+\.(\s|$)'; then
    echo "BLOCKED: broad git restore is destructive and not allowed." >&2
    exit 2
fi

# Check for git clean -f
if echo "$CMD" | grep -qE '(^|[;&|]\s*)git\s+clean\s+.*-f'; then
    echo "BLOCKED: git clean -f is destructive and not allowed." >&2
    exit 2
fi

# Check for rm -rf on project directories
if echo "$CMD" | grep -qE '(^|[;&|]\s*)rm\s+.*-r.*f|rm\s+.*-f.*r'; then
    echo "BLOCKED: rm -rf is not allowed on project directories." >&2
    exit 2
fi

exit 0
