#!/bin/bash
# secrets-scan.sh - PostToolUse hook for Claude Code
# Scans content written by Write/Edit tools for accidentally committed secrets.
# Warns Claude to remove them immediately.
#
# Detects: AWS keys, GitHub tokens, Slack tokens, private keys, JWTs,
# database connection strings, Stripe/SendGrid/Twilio keys, hardcoded passwords.

set -euo pipefail

INPUT=$(cat)

TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // ""')
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
SESSION_ID=$(echo "$INPUT" | jq -r '.session_id // "unknown"')

# Skip binary and lock files
if echo "$FILE_PATH" | grep -qiE '\.(lock|lockb|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp3|mp4|zip|tar|gz|bin|exe|dll|so|dylib)$'; then
  exit 0
fi

# Get the content that was written
CONTENT=""
if [ "$TOOL_NAME" = "Write" ]; then
  CONTENT=$(echo "$INPUT" | jq -r '.tool_input.content // ""')
elif [ "$TOOL_NAME" = "Edit" ]; then
  CONTENT=$(echo "$INPUT" | jq -r '.tool_input.new_string // ""')
fi

if [ -z "$CONTENT" ]; then
  exit 0
fi

# --- Secret pattern detection ---
FINDINGS=""

# AWS Access Key ID (AKIA...)
if echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}'; then
  FINDINGS="${FINDINGS}AWS Access Key ID detected. "
fi

# AWS Secret Access Key
if echo "$CONTENT" | grep -qiE '(aws_secret_access_key|secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}'; then
  FINDINGS="${FINDINGS}AWS Secret Access Key detected. "
fi

# Generic API keys/tokens (long strings assigned to key/token/secret vars)
if echo "$CONTENT" | grep -qiE '(api_key|apikey|api_secret|access_token|auth_token|secret_key|private_key)\s*[=:]\s*["'"'"'][A-Za-z0-9_/+=\-]{20,}["'"'"']'; then
  FINDINGS="${FINDINGS}Possible API key/token in variable assignment. "
fi

# GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
if echo "$CONTENT" | grep -qE 'gh[pousr]_[A-Za-z0-9_]{36,}'; then
  FINDINGS="${FINDINGS}GitHub token detected. "
fi

# Slack tokens (xoxb-, xoxa-, xoxp-, xoxr-, xoxs-)
if echo "$CONTENT" | grep -qE 'xox[baprs]-[0-9]+-[A-Za-z0-9]+'; then
  FINDINGS="${FINDINGS}Slack token detected. "
fi

# Private key blocks
if echo "$CONTENT" | grep -qE -- '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'; then
  FINDINGS="${FINDINGS}Private key block detected. "
fi

# JWT tokens (3 base64url segments)
if echo "$CONTENT" | grep -qE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'; then
  FINDINGS="${FINDINGS}JWT token detected. "
fi

# Database connection strings with embedded passwords
if echo "$CONTENT" | grep -qiE '(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@'; then
  FINDINGS="${FINDINGS}Database connection string with password detected. "
fi

# Stripe keys (live and test)
if echo "$CONTENT" | grep -qE '(sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{20,}'; then
  FINDINGS="${FINDINGS}Stripe key detected. "
fi

# SendGrid API keys
if echo "$CONTENT" | grep -qE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'; then
  FINDINGS="${FINDINGS}SendGrid API key detected. "
fi

# Twilio API keys
if echo "$CONTENT" | grep -qE 'SK[0-9a-fA-F]{32}'; then
  FINDINGS="${FINDINGS}Possible Twilio API key detected. "
fi

# Hardcoded passwords
if echo "$CONTENT" | grep -qiE '(password|passwd|pwd)\s*[=:]\s*["'"'"'][^"'"'"']{8,}["'"'"']'; then
  FINDINGS="${FINDINGS}Hardcoded password detected. "
fi

# Google OAuth client secrets
if echo "$CONTENT" | grep -qE 'GOCSPX-[A-Za-z0-9_-]{28}'; then
  FINDINGS="${FINDINGS}Google OAuth client secret detected. "
fi

# Anthropic API keys
if echo "$CONTENT" | grep -qE 'sk-ant-[A-Za-z0-9_-]{20,}'; then
  FINDINGS="${FINDINGS}Anthropic API key detected. "
fi

# OpenAI API keys
if echo "$CONTENT" | grep -qE 'sk-[A-Za-z0-9]{20,}'; then
  FINDINGS="${FINDINGS}OpenAI API key detected. "
fi

# --- Report findings ---
if [ -n "$FINDINGS" ]; then
  LOG_DIR="$HOME/.claude/logs"
  mkdir -p "$LOG_DIR"
  echo "[$TIMESTAMP] [$SESSION_ID] SECRETS WARNING in $FILE_PATH: $FINDINGS" >> "$LOG_DIR/audit-$(date '+%Y-%m-%d').log"

  jq -n --arg findings "$FINDINGS" --arg file "$FILE_PATH" '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      additionalContext: ("WARNING: Potential secrets detected in " + $file + ": " + $findings + "You MUST remove these secrets immediately. Replace with environment variables or placeholder values.")
    }
  }'
  exit 0
fi

exit 0
