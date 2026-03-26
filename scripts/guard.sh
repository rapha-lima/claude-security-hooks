#!/bin/bash
# guard.sh - PreToolUse hook for Claude Code
# Blocks dangerous Bash commands, prevents secret file access via Bash bypass,
# blocks writes to sensitive files, and logs all tool calls for auditing.
#
# Exit codes:
#   0 = allow (or deny via JSON output)
#   2 = block with stderr message

set -euo pipefail

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')
CWD=$(echo "$INPUT" | jq -r '.cwd // ""')
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# --- Audit log ---
LOG_DIR="$HOME/.claude/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/audit-$(date '+%Y-%m-%d').log"

deny() {
  local reason="$1"
  echo "[$TIMESTAMP] [$SESSION_ID] BLOCKED: $reason" >> "$LOG_FILE"
  jq -n --arg reason "$reason" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: $reason
    }
  }'
  exit 0
}

# ===========================
# BASH COMMAND INSPECTION
# ===========================
if [ "$TOOL_NAME" = "Bash" ]; then
  COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // ""')
  echo "[$TIMESTAMP] [$SESSION_ID] Bash: $COMMAND (cwd: $CWD)" >> "$LOG_FILE"

  # --- Secret file access via Bash (bypass of Read deny rules) ---
  if echo "$COMMAND" | grep -qiE '(cat|less|more|head|tail|sed|awk|grep|bat|strings|xxd|od|hexdump|base64)\s+.*\.(env|pem|key|p12|pfx|jks)'; then
    deny "Reading secret files via Bash is blocked. Use the Read tool on non-sensitive files instead."
  fi

  # --- Data exfiltration ---
  if echo "$COMMAND" | grep -qiE '(curl|wget|nc|ncat|socat)\s+.*(-d|--data|--upload|POST)'; then
    deny "Potential data exfiltration detected. Outbound data transfer is blocked."
  fi

  # --- Encoding secrets for exfiltration ---
  if echo "$COMMAND" | grep -qiE 'base64.*\.(env|pem|key|credentials|secret)'; then
    deny "Encoding secret files is blocked."
  fi

  # --- Process killing ---
  if echo "$COMMAND" | grep -qiE '(kill\s+-9\s+|killall\s+|pkill\s+)'; then
    deny "Process killing is blocked. Specify which process needs to stop."
  fi

  # --- Disk-level destructive operations ---
  if echo "$COMMAND" | grep -qiE '(mkfs|fdisk|dd\s+if=|shred|wipefs)'; then
    deny "Disk-level destructive operations are blocked."
  fi

  # --- Network listeners (reverse/bind shells) ---
  if echo "$COMMAND" | grep -qiE '(nc\s+-l|ncat\s+-l|socat\s+TCP-LISTEN|python.*socket.*listen)'; then
    deny "Opening network listeners is blocked."
  fi

  # --- Cron/at manipulation ---
  if echo "$COMMAND" | grep -qiE '(crontab\s+-[re]|\bat\s+-[fmqv])'; then
    deny "Cron/at job manipulation is blocked."
  fi

  # --- History tampering ---
  if echo "$COMMAND" | grep -qiE '(history\s+-c|history\s+-w|HISTFILE=|unset\s+HISTFILE)'; then
    deny "Shell history manipulation is blocked."
  fi

  # --- Pre-commit secrets scan ---
  if echo "$COMMAND" | grep -qE '^\s*git\s+commit\b'; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    SCAN_SCRIPT="$SCRIPT_DIR/pre-commit-scan.sh"
    if [ -x "$SCAN_SCRIPT" ]; then
      SCAN_RESULT=$(cd "$CWD" && "$SCAN_SCRIPT" 2>/dev/null) || true
      if [ -n "$SCAN_RESULT" ]; then
        deny "SECRETS FOUND in staged files — commit blocked. $SCAN_RESULT Remove the secrets and unstage sensitive files before committing."
      fi
    fi
  fi

# ===========================
# WRITE/EDIT FILE INSPECTION
# ===========================
elif [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "Edit" ]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
  echo "[$TIMESTAMP] [$SESSION_ID] $TOOL_NAME: $FILE_PATH (cwd: $CWD)" >> "$LOG_FILE"

  # Block writes to sensitive config/secret files
  if echo "$FILE_PATH" | grep -qiE '\.(env|env\..+|pem|key|p12|pfx|jks|npmrc|pypirc|netrc|git-credentials)$'; then
    deny "Writing to sensitive file '$(basename "$FILE_PATH")' is blocked."
  fi

  if echo "$FILE_PATH" | grep -qiE '(credentials\.json|service-account.*\.json)$'; then
    deny "Writing to credentials file '$(basename "$FILE_PATH")' is blocked."
  fi

# ===========================
# OTHER TOOLS (log only)
# ===========================
else
  echo "[$TIMESTAMP] [$SESSION_ID] $TOOL_NAME (cwd: $CWD)" >> "$LOG_FILE"
fi

# Allow by default
exit 0
