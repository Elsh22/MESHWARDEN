# MESHWARDEN

Zero-trust, offline-capable distributed compute mesh PoC for DDIL environments.
Pure Rust, static musl binaries, no C dependencies. Autonomous weaponization is
an explicit non-goal (docs/01-prd.md).

## Sources of truth
- Decisions live in exactly one ADR under docs/adr/. ADR-017 is normative for
  all authentication work. Read the sections your task cites; don't skim the
  whole 1200 lines every time.
- Schemas live in docs/spec/ only (algorithm-registry.md, wire-registry.md).
- docs/07-roadmap.md sequences work and tracks testing-obligation coverage.
- .cursor/rules/*.mdc are binding here too: crypto-boundary, docs-discipline,
  naming, mermaid. Read them before touching the areas they cover.

## Invariants (never break, never "temporarily" relax)
- Crypto agility boundary: only mw-crypto imports primitive crypto crates.
- AlgId tagging on every crypto-bearing field. No fixed-size arrays in wire or
  spec types; use mw-proto BoundedBytes/BoundedVec with exact-length checks.
- No ambient clock in library code. `now`, nonces, and channel binding are inputs.
- Bounds are enforced before allocation, and where the information to name the
  violation exists.
- mw-session::machine is pure: no I/O, clock, timer, entropy, or private key type.
- Frozen golden vectors (certificate_signing_bytes, AuthTranscriptV1) never change.
- Crate edges follow ADR-017 "Crate ownership" exactly.

## Evidence rules (these are the review checklist)
1. A test checks what the code SHOULD do per the ADR, not what it currently does.
2. Negative tests assert the exact error variant and fields. Never bare is_err().
3. Canonical encodings are proven with byte-literal fixtures, not Rust round trips.
4. Bound tests cover the exact edge: at bound passes, bound + 1 fails.
5. Green tests are not sufficient if they only confirm existing behavior.
6. A security claim in a doc or comment must name the test that proves it.

## Build gate
`bash xtask/gate.sh` must pass before any commit. It runs fmt check, the full
workspace build and tests, the static musl build, the crypto-boundary check, and
the ADR-017 structural checks. Crate-local test runs never count as the gate.

## Writing style for docs
Plain, direct prose. No em dashes in new text. Cite ADR sections instead of
restating them. Don't invent FR/NFR/SEC/THR/RSK/TST/DEM IDs.

## Autonomous loop
If `ops/loop/STATUS` says RUNNING, follow `ops/loop/PROCEDURE.md`.
Roles: the main thread implements; the `test-author` subagent writes every file
under crates/*/tests/; the `fde-reviewer` subagent reviews every task before
commit. Never launch subagents in the background.
