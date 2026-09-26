#!/usr/bin/env bash
# PreToolUse (Edit|Write|MultiEdit|NotebookEdit): role-based write guard.
# - fde-reviewer never writes.
# - Only test-author writes under crates/*/tests/.
# - test-author writes nowhere else.
set -u
input=$(cat)
path=$(jq -r '.tool_input.file_path // .tool_input.notebook_path // empty' <<<"$input")
agent=$(jq -r '.agent_type // "main"' <<<"$input")
root="${CLAUDE_PROJECT_DIR:-$(pwd)}"
rel="${path#"$root"/}"

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

[ "$agent" = "fde-reviewer" ] && deny "fde-reviewer is read-only. Report findings; the implementer makes changes."

case "$rel" in
  crates/*/tests/*) is_test=1 ;;
  *) is_test=0 ;;
esac

if [ "$is_test" = 1 ] && [ "$agent" != "test-author" ]; then
  deny "Only the test-author subagent writes under crates/*/tests/. If a test looks wrong, send it back to test-author with the ADR text that shows it."
fi
if [ "$agent" = "test-author" ] && [ "$is_test" = 0 ]; then
  deny "test-author writes only under crates/*/tests/. List any src helpers you need in your reply instead."
fi
exit 0
