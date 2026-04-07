#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/alex/linux-stable}"
REMOTE_NAME="${REMOTE_NAME:-alex}"
PUSH_REF="${PUSH_REF:-HEAD}"
COMMIT_PREFIX="${COMMIT_PREFIX:-auto-sync}"
LOG_PREFIX="${LOG_PREFIX:-[auto_git_sync]}"

cd "$REPO_DIR"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "$LOG_PREFIX not a git repo: $REPO_DIR" >&2
  exit 1
fi

if git rev-parse --verify HEAD >/dev/null 2>&1; then
  :
else
  echo "$LOG_PREFIX no commits yet; refusing to auto-commit" >&2
  exit 1
fi

if ! git config user.name >/dev/null || ! git config user.email >/dev/null; then
  echo "$LOG_PREFIX missing git user.name/user.email; set them before enabling auto sync" >&2
  exit 1
fi

if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  echo "$LOG_PREFIX remote not found: $REMOTE_NAME" >&2
  exit 1
fi

LOCK_PATH="${LOCK_PATH:-$REPO_DIR/.git/auto_git_sync.lock}"
exec 9>"$LOCK_PATH"
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || exit 0
fi

git add -A

if git diff --cached --quiet; then
  exit 0
fi

branch="$(git rev-parse --abbrev-ref HEAD || echo detached)"
ts="$(date -Is)"
host="$(hostname -s 2>/dev/null || echo unknown-host)"
msg="${COMMIT_PREFIX}: ${host} ${branch} ${ts}"

git commit -m "$msg"
git push -u "$REMOTE_NAME" "$PUSH_REF"
