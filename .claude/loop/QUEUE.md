# MESHWARDEN autonomous queue

Base: b65b39f (repair slice) plus the harness commit. ADR-017 Revision 6.

## Decisions in force (maintainer-confirmed)
- Slice numbering: bounded decode = 1/1b, certificates = 2a/2b, auth wire
  messages = 3, mw-session::machine = 4, mw-session::driver = 5.
- Certificate decode and validation errors are mapped to session errors by the
  machine (Slice 4). ADR-017 "Division of responsibility" says the machine
  performs certificate validation, so MalformedCertificate, LimitExceeded from
  certificate bounds, PeerCertificateNotValidAt, IssuerKeyMismatch, and
  SubjectKeyMismatch are machine-level. Framing-level errors (MalformedMessage,
  UnknownMessageType, cumulative pre-auth bytes) stay with the driver (Slice 5).
- The machine takes `policy_max_session_duration` as an input. No default value
  is chosen in Slice 4.

## Maintainer-only (always STOP, never decide)
- Any edit to docs/adr/** or docs/spec/** (ADR revisions, amendments, rows).
- Any bound constant value, wire format, message code, or golden vector change.
- New dependency edges not listed in ADR-017 "Crate ownership", and any new
  third-party crate.
- Hello's position relative to AUTH_INIT.
- Anything post-quantum.
- Starting Slice 5 (driver).

---

- [ ] T0 Housekeeping
  Needs: none
  Cite: repair slice report items 1, 2, 6; ADR-017 Testing obligations (Structural)
  Scope: crates/mw-transport/src/devcert.rs (formatting only),
         xtask/check-no-fixed-crypto-arrays.sh (new), docs/07-roadmap.md
  Do:
  - rustfmt devcert.rs. `git diff -w -- crates/mw-transport/src/devcert.rs`
    must be empty (whitespace-only change). Paste that in the report.
  - New script xtask/check-no-fixed-crypto-arrays.sh: fails if any
    `[u8; N]` array type appears in crates/mw-proto/src. It must support a
    `--self-test` flag that writes a temp file containing a fixed array, runs
    the check against it, and exits non-zero unless the check caught it. The
    gate already calls this script if it exists. Evidence = self-test output.
  - Roadmap: fix the stale "Current position" section (write "as of <hash>"
    for the base commit). Flip the "No fixed-size crypto array" coverage row
    from Gap to Covered, evidence = the script. Leave the exporter row as Gap
    (T8 closes it).
  Commit: chore: format devcert, add fixed-array structural check, refresh roadmap position

- [ ] T1 Slice 4a: scaffold mw-session
  Needs: T0
  Cite: ADR-017 Crate ownership, Why a new crate, Division of responsibility
  Scope: crates/mw-session/** (new), Cargo.toml (members only), Cargo.lock,
         xtask/check-machine-purity.sh (new)
  Do:
  - New crate crates/mw-session, added to workspace members. Dependencies are
    exactly the edges ADR-017 allows (mw-crypto, mw-identity, mw-proto) plus
    thiserror from the workspace. No tokio, no rustls, no mw-trust, no
    mw-transport yet (the driver adds those in Slice 5).
  - `pub mod machine;` with module docs citing ADR-017 by section. Nothing else.
  - xtask/check-machine-purity.sh: fails if crates/mw-session/src/machine*
    mentions std::time, SystemTime, Instant, tokio, std::net, std::fs,
    thread::sleep, rand, OsRng, getrandom, or any private-key type exported by
    mw-crypto or mw-identity (find the real type names by reading those crates;
    list them in the script with a comment). `--self-test` like T0's script.
  Evidence: gate passes; both self-tests; `cargo tree -p mw-session --depth 1`.
  Commit: feat(session): scaffold mw-session with machine purity check

- [ ] T2 Slice 4b: machine API and error taxonomy
  Needs: T1
  Cite: ADR-017 Division of responsibility (AuthOutcome, capability accessor
        discipline), Authentication flow, Transition points, Failure behavior,
        Session validity and expiry, Testing obligations (Negative table names)
  Scope: crates/mw-session/src/**, crates/mw-session/tests/** (test-author)
  Do:
  - Public types for a sans-I/O AuthMachine for both roles: inputs (start with
    local cert bytes, channel binding, nonce, now, policy_max_session_duration;
    inbound message bytes or decoded messages), outputs (outbound message,
    a SignRequest carrying the transcript signing bytes, AuthOutcome, or error).
    The machine never receives key material; signing comes back as an input.
  - AuthOutcome with the three accessors ADR-017 mandates: complete raw-code
    accessor, has_capability(AlgId), and a lossy accessor whose name says so.
  - One error enum whose variants use the ADR-017 Negative-table names for
    machine-level rows (see Decisions in force). Each variant's doc cites the row.
  - No stub methods with todo!() or placeholder bodies. Each method lands in
    the task that implements and tests it (T3/T4).
  Tests (test-author): compile-level API tests only. Lossy accessor omits an
  unknown code while the raw accessor includes it; has_capability is correct
  for a known code alongside an unknown one. Build AuthOutcome through whatever
  constructor the API exposes to tests (a `#[doc(hidden)]` test constructor is
  acceptable; flag it in the report).
  Commit: feat(session): AuthMachine API, AuthOutcome accessors, error taxonomy

- [ ] T3 Slice 4c: client path
  Needs: T2
  Cite: ADR-017 Authentication flow, Transition points, AuthTranscriptV1,
        Exact-length validation, v1 signature-list rules, Certificate
        validation ordering, Algorithm handling / v1 validation rules
  Scope: crates/mw-session/src/**, crates/mw-session/tests/** (test-author)
  Do: client builds AUTH_INIT; consumes AUTH_RESPONSE (decode server cert via
  mw-identity, validate in the ADR's order at supplied now, check node id vs
  subject, build AuthTranscriptV1 with role Server, verify the server proof);
  emits SignRequest for its own role; on signature returns AUTH_CONFIRM and an
  AuthOutcome with session_valid_until per ADR-017 Session validity.
  Tests (test-author), all at machine level with real certificates built via
  mw-identity test helpers: happy path; each machine-level Negative row that
  the client can hit (empty/two signatures, duplicate alg codes, unknown alg
  code, signature alg != auth_algorithm, signature alg != cert key alg, node id
  unparseable, node id != subject, cert not valid at now, wrong-but-valid
  issuer key -> IssuerKeyMismatch not BadSignature, subject mismatch, tampered
  proof, 65 capabilities, oversized cert, non-canonical cert encoding,
  exact-length 31/33). Each asserts the exact variant.
  Commit: feat(session): client authentication path

- [ ] T4 Slice 4d: server path
  Needs: T3
  Cite: same as T3
  Scope: crates/mw-session/src/**, crates/mw-session/tests/** (test-author)
  Do: server consumes AUTH_INIT, builds AUTH_RESPONSE (SignRequest for role
  Server), consumes AUTH_CONFIRM, verifies the client proof, returns AuthOutcome.
  Server transitions only after AUTH_CONFIRM validates (ADR-017 Transition points).
  Tests (test-author): server-side mirrors of every T3 negative row, plus a
  full client<->server run with both machines in memory producing matching
  peer NodeIds and capability sets.
  Commit: feat(session): server authentication path

- [ ] T5 Slice 4e: adversarial matrix
  Needs: T4
  Cite: ADR-017 Testing obligations (Negative), Security invariants
  Scope: crates/mw-session/tests/** (test-author), crates/mw-session/src/**
         (only if a test exposes a real defect)
  Tests (test-author), in-memory machines only:
  - Reflection: replay a peer's proof back to it -> rejected on role.
  - Cross-session replay: proof from a run with binding A fed to a run with
    binding B -> rejected on channel_binding.
  - MITM relay: two sessions with different bindings, relay proofs across ->
    rejected.
  - Role confusion; unknown-key-share (substitute one identity).
  - Out-of-order messages; nonce reuse -> ProtocolViolation.
  For each rejection, assert the exact variant AND prove the rejection comes
  from the named field: build a control case that differs only in that field
  and passes.
  If a test fails, the implementer fixes src. The run report lists every
  defect found this way.
  Commit: test(session): adversarial authentication matrix

- [ ] T6 Slice 4f: expiry and structural closure
  Needs: T5
  Cite: ADR-017 Session validity and expiry, Enforcement without an ambient
        clock, Testing obligations (Structural)
  Scope: crates/mw-session/**
  Do/Tests: session_valid_until is the min of the three ADR terms (a test per
  term being the minimum); an operation with now >= session_valid_until ->
  SessionExpired (test at exactly equal). Confirm the purity script covers the
  final machine code and that no private-key type is reachable from AuthMachine.
  Commit: feat(session): session expiry and structural checks

- [ ] T7 Slice 4 close-out
  Needs: T6
  Cite: docs-discipline.mdc; roadmap "Testing obligation coverage"
  Scope: docs/07-roadmap.md, .claude/loop/runs/SLICE-4-REPORT.md
  Do: update every coverage row Slice 4 touched (Planned/Partial -> Covered
  with exact test names, or leave Partial with the reason). Add the Slice 4
  row to Completed work. Update Current position. Write SLICE-4-REPORT.md: a
  maintainer-facing summary of T1-T6 (commits, obligations covered, defects
  found, every flagged choice, open questions).
  Commit: docs(roadmap): close Slice 4

- [ ] T8 Transport: channel-binding exporter
  Needs: T7
  Cite: ADR-017 Channel binding, Status of the exporter value, Crate ownership
        (mw-transport row), Testing obligations (Positive: exporter row)
  Scope: crates/mw-transport/src/**, crates/mw-transport/tests/** (test-author)
  Do: an API on the Unauthenticated<S> TLS stream that returns the channel
  binding via rustls export_keying_material with mw_proto::EXPORTER_LABEL_V1,
  context None, exactly 32 bytes. Redacted Debug. mw-transport still must not
  declare mw-crypto or mw-identity. Return type: use an mw-proto bounded type
  or a transport newtype with an exact-length check; no fixed-size array.
  Flag the choice in the report.
  Tests (test-author): over tokio::io::duplex with the dev cert: 32 bytes;
  client and server values equal within one session; values differ across two
  sessions; calling twice in one session returns the same value.
  Roadmap: flip the exporter coverage row to Covered with test names.
  Commit: feat(transport): TLS exporter channel binding per ADR-017

- [ ] T9 Decision memo, then stop
  Needs: T8
  Scope: .claude/loop/runs/DECISION-MEMO.md only
  Do: write a memo for the maintainer covering, with ADR quotes and
  consequences, but NO recommendation presented as decided:
  1. Hello placement relative to AUTH_INIT: options, effect on the 16384-byte
     pre-auth budget, driver behavior, wire behavior, what ADR-017 Rev 7 would
     need to say for each.
  2. Items waiting for Rev 7: a Hello MAX_HELLO_ALGS + 1 obligation row; the
     machine-owns-certificate-errors decision; the exporter return type chosen
     in T8; any flagged choices from SLICE-4-REPORT.md.
  3. Slice 5 prerequisites checklist.
  Then write BLOCKED to STATUS with "Maintainer decision required before
  Slice 5" in BLOCKED.md.
  Commit: docs(loop): decision memo for Slice 5 prerequisites
