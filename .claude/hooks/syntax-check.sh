#!/usr/bin/env bash
# PostToolUse hook for Edit|Write — validate file syntax after modification.
# Exit 2 on failure (stderr fed back to Claude). Exit 0 on success or non-checked type.

set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))" 2>/dev/null)

if [[ -z "$FILE_PATH" || ! -f "$FILE_PATH" ]]; then
    exit 0
fi

EXT="${FILE_PATH##*.}"

case "$EXT" in
    py)
        if ! python3 -m py_compile "$FILE_PATH" 2>&1; then
            echo "SYNTAX ERROR: $FILE_PATH failed Python compilation" >&2
            exit 2
        fi
        ;;
    yaml|yml)
        if ! python3 -c "import yaml; yaml.safe_load(open('$FILE_PATH'))" 2>&1; then
            echo "SYNTAX ERROR: $FILE_PATH is not valid YAML" >&2
            exit 2
        fi
        ;;
    json)
        if ! python3 -m json.tool "$FILE_PATH" > /dev/null 2>&1; then
            echo "SYNTAX ERROR: $FILE_PATH is not valid JSON" >&2
            exit 2
        fi
        ;;
    sh)
        if ! bash -n "$FILE_PATH" 2>&1; then
            echo "SYNTAX ERROR: $FILE_PATH has bash syntax errors" >&2
            exit 2
        fi
        ;;
    *)
        # Not a checked file type
        ;;
esac

exit 0
