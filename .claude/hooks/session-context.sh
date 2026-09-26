#!/usr/bin/env bash
# SessionStart: tell Claude where the loop stands. Plain stdout becomes context.
cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
status=$(head -n1 .claude/loop/STATUS 2>/dev/null || echo IDLE)
next=$(grep -m1 -E '^- \[ \] ' .claude/loop/QUEUE.md 2>/dev/null || echo "none")
echo "MESHWARDEN loop status is $status. Next unchecked queue task: $next. HEAD is $(git rev-parse --short HEAD 2>/dev/null)."
exit 0
