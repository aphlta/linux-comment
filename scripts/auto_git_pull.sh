#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-/home/alex/linux-stable}"
REMOTE_NAME="${REMOTE_NAME:-alex}"
LOG_PREFIX="${LOG_PREFIX:-[auto_git_pull]}"

cd "$REPO_DIR"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "$LOG_PREFIX not a git repo: $REPO_DIR" >&2
  exit 1
fi

if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
  echo "$LOG_PREFIX remote not found: $REMOTE_NAME" >&2
  exit 1
fi

# Ensure we don't collide with auto_git_sync.sh
LOCK_PATH="${LOCK_PATH:-$REPO_DIR/.git/auto_git_sync.lock}"
exec 9>"$LOCK_PATH"
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { echo "$LOG_PREFIX Another git sync/pull is running. Exiting."; exit 0; }
fi

branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
if [ "$branch" = "detached" ]; then
  echo "$LOG_PREFIX Detached HEAD, refusing to auto-pull." >&2
  exit 1
fi

echo "$LOG_PREFIX Checking for local changes..."
has_changes=0
if ! git diff --quiet || ! git diff --cached --quiet; then
  has_changes=1
  echo "$LOG_PREFIX Stashing local changes..."
  git stash push -m "auto-pull-stash-$(date -Is)" >/dev/null
fi

echo "$LOG_PREFIX Fetching and pulling (rebase) from $REMOTE_NAME/$branch..."
if ! git pull --rebase "$REMOTE_NAME" "$branch"; then
  echo "$LOG_PREFIX Conflict or error during pull! Aborting rebase." >&2
  git rebase --abort || true
fi

if [ "$has_changes" -eq 1 ]; then
  echo "$LOG_PREFIX Restoring stashed changes..."
  if ! git stash pop >/dev/null; then
    echo "$LOG_PREFIX Warning: Conflict restoring stash. Please resolve manually." >&2
  fi
fi

echo "$LOG_PREFIX Pull complete."
