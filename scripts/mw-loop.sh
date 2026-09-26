#!/usr/bin/env bash
# Runs the MESHWARDEN queue one task per fresh Claude Code session until the
# queue is DONE, a task writes BLOCKED, or an iteration makes no commit.
# Usage: bash scripts/mw-loop.sh            (defaults: 12 iterations)
#        MW_MAX_ITERS=3 bash scripts/mw-loop.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

dir=.claude/loop
max="${MW_MAX_ITERS:-12}"
mkdir -p "$dir/runs"

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree is dirty. Commit or stash before starting the loop." >&2
  exit 1
fi

echo RUNNING > "$dir/STATUS"
echo 0 > "$dir/.stop_blocks"

prompt='Read CLAUDE.md, then follow .claude/loop/PROCEDURE.md exactly for ONE task. Stop after committing it (or after writing BLOCKED/DONE).'

for i in $(seq 1 "$max"); do
  before=$(git rev-parse HEAD)
  stamp=$(date +%Y%m%d-%H%M%S)
  echo "== iteration $i/$max at $stamp (HEAD $before) =="

  claude -p "$prompt" \
    --permission-mode acceptEdits \
    --output-format stream-json --verbose \
    > "$dir/runs/iter-$stamp.json" 2> "$dir/runs/iter-$stamp.err" || true

  status=$(head -n1 "$dir/STATUS")
  after=$(git rev-parse HEAD)
  echo "   status=$status  head=$after"
  git log --oneline -1

  case "$status" in
    DONE)    echo "Queue complete."; break ;;
    BLOCKED) echo "Blocked. Read $dir/BLOCKED.md."; break ;;
  esac

  if [ "$before" = "$after" ]; then
    echo BLOCKED > "$dir/STATUS"
    printf '\n## No progress\nIteration %s ended without a commit. See runs/iter-%s.*\n' "$i" "$stamp" >> "$dir/BLOCKED.md"
    echo "No commit this iteration. Stopping so it can't spin." ; break
  fi
done

echo
echo "Final status: $(head -n1 "$dir/STATUS")"
echo "Commits since start are local only. Review, then push yourself."
