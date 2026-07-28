#!/usr/bin/env bash
# ============================================================
# check_secrets.sh
# Enforces the push boundary before anything leaves the machine.
# Run it manually, or wire it as a git pre commit hook:
#   ln -s ../../scripts/check_secrets.sh .git/hooks/pre-commit
#
# It fails (exit 1) if a staged file looks like a secret or if a
# file that must never be committed slipped into the staged set.
# ============================================================
set -euo pipefail

fail=0

# Files that must never be staged, matched by name pattern.
forbidden_patterns=(
  '\.env$'
  '\.env\..*'
  '.*\.pem$'
  '.*\.key$'
  '.*\.sqlite3?$'
  '.*\.db$'
  'secrets\.json$'
  'credentials\.json$'
  'service_account.*\.json$'
)

# Content patterns that indicate a leaked secret inside a staged file.
content_patterns=(
  'sk-ant-[a-zA-Z0-9]'
  'AKIA[0-9A-Z]{16}'
  'ghp_[a-zA-Z0-9]{20,}'
  '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  'password[[:space:]]*=[[:space:]]*[^[:space:]]'
)

staged=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

# In CI there is no staged set. Fall back to every tracked file so the same
# script gates both a local commit and a pushed branch.
if [ -z "$staged" ]; then
  staged=$(git ls-files 2>/dev/null || true)
  if [ -z "$staged" ]; then
    echo "no files to check"
    exit 0
  fi
  echo "no staged files, scanning all tracked files"
fi

while IFS= read -r file; do
  [ -z "$file" ] && continue

  # The env template is the one intentional exception: it holds no values.
  if [ "$file" = ".env.example" ]; then
    continue
  fi

  for pat in "${forbidden_patterns[@]}"; do
    if echo "$file" | grep -Eq -- "$pat"; then
      echo "BLOCKED: $file matches a forbidden name pattern and must not be committed"
      fail=1
    fi
  done

  if [ -f "$file" ]; then
    for pat in "${content_patterns[@]}"; do
      if grep -Eq -- "$pat" "$file"; then
        echo "BLOCKED: $file contains what looks like a secret"
        fail=1
      fi
    done
  fi
done <<< "$staged"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "Commit blocked. Move secrets into .env (git ignored) and try again."
  exit 1
fi

echo "secret scan clean"
exit 0
