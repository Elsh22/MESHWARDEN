---
name: mw-next
description: Run one iteration of the MESHWARDEN autonomous queue (next unchecked task in ops/loop/QUEUE.md) by following ops/loop/PROCEDURE.md.
disable-model-invocation: true
---

Set `ops/loop/STATUS` to RUNNING if it is IDLE, then follow
`ops/loop/PROCEDURE.md` exactly for one task. Stop after the commit.
