# Loop procedure (one task per iteration)

You are running one iteration of the MESHWARDEN autonomous queue. Do exactly
one task, commit it, write its report, and stop. The outer script starts a fresh
session for the next task.

## 0. Orient
1. Read `ops/loop/STATUS`. If it is not `RUNNING`, stop immediately.
2. Read `ops/loop/QUEUE.md`, including "Decisions in force" and
   "Maintainer-only". Pick the FIRST task whose box is `- [ ]`.
   If none remain, write `DONE` to STATUS and stop.
3. If any task listed in its `Needs:` is unchecked, write `BLOCKED` to STATUS,
   explain in `ops/loop/BLOCKED.md`, and stop.
4. Run `git status --porcelain`. If the tree is dirty from a previous run, do
   not build on it. Write BLOCKED with the dirty file list and stop.
5. Read every ADR section, spec, and file the task cites. Read CLAUDE.md rules.

## 1. Plan
Write a short plan to `ops/loop/runs/<TASK-ID>.md` under a "Plan" heading:
files to touch, ADR sections relied on, the tests you expect, and every
assumption. If the ADR is silent or contradictory on something the task needs,
that is a STOP condition (section 6), not a judgement call.

## 2. Tests first
If the task has a "Tests:" block, delegate to the `test-author` subagent in the
foreground. Give it: the task ID, the ADR sections, the obligations to cover,
and the public API it may compile against. It writes only under
crates/*/tests/. A hook enforces this.

You may not edit test files. If you think a test is wrong, don't work around
it. Send it back to test-author with the exact ADR text that shows it's wrong,
and record the exchange in the run report. Never weaken an assertion to get green.

## 3. Implement
Make the smallest change that satisfies the task and the tests. Stay inside the
task's Scope list. Cite ADR sections in doc comments for security-relevant code.

## 4. Gate
Run `bash xtask/gate.sh` until it passes. If a failure is outside the task's
scope (a pre-existing break), STOP (section 6). Don't fix unrelated code.

## 5. Review, then commit
1. Stage your changes with `git add` (never `git add -A` on paths outside Scope).
2. Invoke `fde-reviewer` in the foreground with: task ID, the task's full text
   from QUEUE.md, and the list of changed files. It reads `git diff --cached`
   itself and reruns the evidence.
3. On `VERDICT: FAIL`, fix the findings (tests go back through test-author),
   re-run the gate, and review again. After 3 FAIL rounds, STOP.
4. On `VERDICT: PASS`:
   - Tick the task box in QUEUE.md and append ` (commit: see log)`.
   - Finish the run report (format below) and paste the reviewer's verdict in.
   - Stage QUEUE.md and the run report with the task changes.
   - Commit with the task's commit message, using `git commit -F <file>`.
5. Stop. Don't start the next task.

## 6. STOP conditions (write BLOCKED, explain, stop)
Write `BLOCKED` to STATUS and append a section to BLOCKED.md with the task ID,
what you found, exact quotes or file:line, and the question for the maintainer.
Leave the tree clean (`git restore` your uncommitted edits) unless keeping them
is the point of the question, in which case list them.
- The ADR or spec is silent, ambiguous, or contradicts the code on something
  the task needs.
- The task would require editing a protected path (docs/adr, docs/spec,
  .claude config, .cursor, deny.toml, rust-toolchain.toml, CLAUDE.md).
- Anything in "Maintainer-only" in QUEUE.md.
- A pre-existing failure outside scope, or the gate stays red.
- Three reviewer FAIL rounds.
- A test from test-author and the implementation disagree and the ADR doesn't
  settle which is right.

## Run report format (ops/loop/runs/<TASK-ID>.md)
1. Plan (from step 1).
2. What changed, per file, one or two lines each.
3. ADR obligations covered -> test names (exact fn names).
4. Evidence: gate summary lines, and any structural check output.
5. Reviewer verdict and findings, with how each was resolved.
6. Choices made that the ADR didn't dictate, each flagged for maintainer review.
7. Unresolved for maintainer.
