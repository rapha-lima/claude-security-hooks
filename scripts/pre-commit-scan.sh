#!/bin/bash
# pre-commit-scan.sh - Scans all staged files for secrets before git commit.
# Called by guard.sh when it detects a git commit command.
# Exit 0 = clean, Exit 1 = secrets found (returns findings on stdout)

set -euo pipefail

# Get list of staged files (only added/modified, not deleted)
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

FINDINGS=""

while IFS= read -r FILE; do
  # Skip binary and documentation files (docs often contain example patterns)
  if echo "$FILE" | grep -qiE '\.(lock|lockb|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp3|mp4|zip|tar|gz|bin|exe|dll|so|dylib|md|mdx|rst|txt)$'; then
    continue
  fi

  # Skip files that don't exist (submodules, symlinks)
  if [ ! -f "$FILE" ]; then
    continue
  fi

  CONTENT=$(git show ":$FILE" 2>/dev/null || true)
  if [ -z "$CONTENT" ]; then
    continue
  fi

  # AWS Access Key ID
  if echo "$CONTENT" | grep -qE 'AKIA[0-9A-Z]{16}'; then
    FINDINGS="${FINDINGS}[$FILE] AWS Access Key ID. "
  fi

  # AWS Secret Access Key
  if echo "$CONTENT" | grep -qiE '(aws_secret_access_key|secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}'; then
    FINDINGS="${FINDINGS}[$FILE] AWS Secret Access Key. "
  fi

  # Generic API keys/tokens
  if echo "$CONTENT" | grep -qiE '(api_key|apikey|api_secret|access_token|auth_token|secret_key|private_key)\s*[=:]\s*["'"'"'][A-Za-z0-9_/+=\-]{20,}["'"'"']'; then
    FINDINGS="${FINDINGS}[$FILE] API key/token in variable assignment. "
  fi

  # GitHub tokens
  if echo "$CONTENT" | grep -qE 'gh[pousr]_[A-Za-z0-9_]{36,}'; then
    FINDINGS="${FINDINGS}[$FILE] GitHub token. "
  fi

  # Slack tokens
  if echo "$CONTENT" | grep -qE 'xox[baprs]-[0-9]+-[A-Za-z0-9]+'; then
    FINDINGS="${FINDINGS}[$FILE] Slack token. "
  fi

  # Private key blocks
  if echo "$CONTENT" | grep -qE -- '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'; then
    FINDINGS="${FINDINGS}[$FILE] Private key. "
  fi

  # JWT tokens
  if echo "$CONTENT" | grep -qE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'; then
    FINDINGS="${FINDINGS}[$FILE] JWT token. "
  fi

  # Database connection strings with passwords
  if echo "$CONTENT" | grep -qiE '(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@'; then
    FINDINGS="${FINDINGS}[$FILE] Database connection string with password. "
  fi

  # Stripe keys
  if echo "$CONTENT" | grep -qE '(sk_live|pk_live|sk_test|pk_test)_[A-Za-z0-9]{20,}'; then
    FINDINGS="${FINDINGS}[$FILE] Stripe key. "
  fi

  # SendGrid keys
  if echo "$CONTENT" | grep -qE 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'; then
    FINDINGS="${FINDINGS}[$FILE] SendGrid API key. "
  fi

  # Anthropic API keys
  if echo "$CONTENT" | grep -qE 'sk-ant-[A-Za-z0-9_-]{20,}'; then
    FINDINGS="${FINDINGS}[$FILE] Anthropic API key. "
  fi

  # OpenAI API keys
  if echo "$CONTENT" | grep -qE 'sk-[A-Za-z0-9]{20,}'; then
    FINDINGS="${FINDINGS}[$FILE] OpenAI API key. "
  fi

  # Google OAuth client secrets
  if echo "$CONTENT" | grep -qE 'GOCSPX-[A-Za-z0-9_-]{28}'; then
    FINDINGS="${FINDINGS}[$FILE] Google OAuth secret. "
  fi

  # Hardcoded passwords
  if echo "$CONTENT" | grep -qiE '(password|passwd|pwd)\s*[=:]\s*["'"'"'][^"'"'"']{8,}["'"'"']'; then
    FINDINGS="${FINDINGS}[$FILE] Hardcoded password. "
  fi

  # .env file content patterns (KEY=value with sensitive names)
  if echo "$CONTENT" | grep -qiE '^(DATABASE_URL|SECRET_KEY|API_KEY|AUTH_TOKEN|PRIVATE_KEY)\s*=\s*.{8,}'; then
    FINDINGS="${FINDINGS}[$FILE] Sensitive env variable assignment. "
  fi

done <<< "$STAGED_FILES"

if [ -n "$FINDINGS" ]; then
  echo "$FINDINGS"
  exit 1
fi

exit 0
