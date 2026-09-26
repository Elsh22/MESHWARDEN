---
name: mw-next
description: Run one iteration of the MESHWARDEN autonomous queue (next unchecked task in .claude/loop/QUEUE.md) by following .claude/loop/PROCEDURE.md.
disable-model-invocation: true
---

Set `.claude/loop/STATUS` to RUNNING if it is IDLE, then follow
`.claude/loop/PROCEDURE.md` exactly for one task. Stop after the commit.
