#!/usr/bin/env bash
# Stop hook: while the loop is RUNNING, an iteration can't end with a red gate
# or uncommitted work. Capped so it can never spin forever.
set -u
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
dir=ops/loop
status=$(head -n1 "$dir/STATUS" 2>/dev/null || echo IDLE)
[ "$status" = "RUNNING" ] || exit 0

count_file="$dir/.stop_blocks"
n=$(cat "$count_file" 2>/dev/null || echo 0)
max="${MW_MAX_STOP_BLOCKS:-6}"

if [ "$n" -ge "$max" ]; then
  echo BLOCKED > "$dir/STATUS"
  printf '\n## Stop hook cap\nGave up after %s forced continuations. Check the last run log.\n' "$n" >> "$dir/BLOCKED.md"
  echo 0 > "$count_file"
  exit 0
fi

if ! out=$(bash xtask/gate.sh 2>&1); then
  echo $((n + 1)) > "$count_file"
  {
    echo "The gate is red, so this iteration can't end yet. Fix it within the task's scope."
    echo "If the fix is out of scope, follow PROCEDURE.md section 6 (write BLOCKED, restore the tree)."
    echo "--- last 60 lines of xtask/gate.sh ---"
    echo "$out" | tail -n 60
  } >&2
  exit 2
fi

if [ -n "$(git status --porcelain)" ]; then
  echo $((n + 1)) > "$count_file"
  {
    echo "Gate is green but the tree has uncommitted changes:"
    git status --porcelain | head -n 30
    echo "Finish PROCEDURE.md step 5 (review, then commit), or restore the changes and write BLOCKED."
  } >&2
  exit 2
fi

echo 0 > "$count_file"
exit 0
