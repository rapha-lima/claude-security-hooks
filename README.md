# claude-security-hooks

Security hooks for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that block dangerous commands, prevent secret leaks, and provide audit logging for every tool call.

## What it does

### Guard (PreToolUse)

Inspects every Bash command, Write, and Edit before execution:

| Protection | What it blocks |
|---|---|
| Secret file bypass | `cat .env`, `head .pem`, `tail .key` via Bash (bypasses Read deny rules) |
| Data exfiltration | `curl --data`, `wget --upload`, outbound `nc` |
| Secret encoding | `base64 .env`, `base64 .credentials` |
| Process killing | `kill -9`, `killall`, `pkill` |
| Disk destruction | `mkfs`, `dd if=`, `shred`, `wipefs` |
| Network listeners | `nc -l`, `socat TCP-LISTEN` (reverse/bind shells) |
| Cron manipulation | `crontab -e`, `at -f` |
| History tampering | `history -c`, `unset HISTFILE` |
| Sensitive file writes | Blocks Write/Edit to `.env`, `.pem`, `.key`, `.npmrc`, etc. |

### Secrets Scanner (PostToolUse)

Scans content after every Write/Edit for accidentally hardcoded secrets:

| Detection | Pattern |
|---|---|
| AWS Keys | `AKIA...` + secret key assignments |
| GitHub tokens | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| Slack tokens | `xox[baprs]-...` |
| Private keys | `-----BEGIN PRIVATE KEY-----` |
| JWT tokens | `eyJ...eyJ...` |
| DB connection strings | `postgres://user:pass@host` |
| Stripe keys | `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` |
| SendGrid keys | `SG.xxx.xxx` |
| Twilio keys | `SK` + 32 hex chars |
| Hardcoded passwords | `password = "..."` |
| Google OAuth | `GOCSPX-...` |
| Anthropic API keys | `sk-ant-...` |
| OpenAI API keys | `sk-...` |

### Audit Logging

Every tool call is logged to `~/.claude/logs/audit-YYYY-MM-DD.log` with:
- Timestamp
- Session ID
- Tool name and arguments
- Blocked actions with reasons

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- `jq` (JSON processor) - install with `brew install jq` on macOS or `apt install jq` on Linux

## Installation

### As a plugin (recommended)

```bash
# Add marketplace
/plugin marketplace add raphalima/claude-security-hooks

# Install
/plugin install claude-security-hooks@claude-security-hooks
```

### Manual installation

1. Clone this repo:
```bash
git clone https://github.com/raphalima/claude-security-hooks.git ~/.claude/plugins/claude-security-hooks
```

2. Make scripts executable:
```bash
chmod +x ~/.claude/plugins/claude-security-hooks/scripts/*.sh
```

3. Add the hooks to your `~/.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/plugins/claude-security-hooks/scripts/guard.sh"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/plugins/claude-security-hooks/scripts/secrets-scan.sh"
          }
        ]
      }
    ]
  }
}
```

## Recommended deny rules

Add these to your `~/.claude/settings.json` for defense in depth (static rules + dynamic hooks):

```json
{
  "permissions": {
    "deny": [
      "Bash(sudo *)",
      "Bash(rm -rf *)",
      "Bash(rm -r *)",
      "Bash(chmod 777 *)",
      "Bash(curl * | *)",
      "Bash(wget * | *)",
      "Bash(git push --force *)",
      "Bash(git push * --force *)",
      "Bash(git reset --hard *)",
      "Bash(git clean *)",
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Read(**/.aws/credentials)",
      "Read(**/.ssh/**)",
      "Read(**/.npmrc)",
      "Read(**/.pypirc)",
      "Read(**/.netrc)",
      "Read(**/.git-credentials)",
      "Read(**/.docker/config.json)",
      "Read(**/credentials.json)",
      "Read(**/service-account*.json)",
      "Read(**/*.pem)",
      "Read(**/*.key)",
      "Read(**/.kube/config)",
      "Read(**/.terraform/*.tfstate)"
    ]
  }
}
```

Also remove `Bash(cat *)`, `Bash(head *)`, and `Bash(tail *)` from your allow rules if present -- they bypass Read deny rules. Claude Code has a dedicated `Read` tool that doesn't need these.

## How it works

```
User prompt
    |
    v
Claude decides to use a tool
    |
    v
PreToolUse hook (guard.sh)
    |-- Bash? --> inspect command for dangerous patterns
    |-- Write/Edit? --> check if target is a sensitive file
    |-- Other? --> log only
    |
    v (if allowed)
Tool executes
    |
    v
PostToolUse hook (secrets-scan.sh)
    |-- Write/Edit? --> scan content for secret patterns
    |-- Secret found? --> warn Claude to remove it
    |
    v
Claude continues
```

## Customization

### Adding new blocked patterns

Edit `scripts/guard.sh` and add a new check:

```bash
if echo "$COMMAND" | grep -qiE 'your-pattern-here'; then
  deny "Your reason here."
fi
```

### Adding new secret detectors

Edit `scripts/secrets-scan.sh` and add a new pattern:

```bash
if echo "$CONTENT" | grep -qE 'your-regex-here'; then
  FINDINGS="${FINDINGS}Your description. "
fi
```

### Changing log location

Edit the `LOG_DIR` variable in `scripts/guard.sh`:

```bash
LOG_DIR="/your/custom/path"
```

## License

MIT
