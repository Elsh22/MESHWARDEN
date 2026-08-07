# ADR-016: rustls CryptoProvider is rustls-rustcrypto (PoC)

Status: Accepted
Date: 2026-08-07
Phase: Phase 6 (prototype build — decided ahead of `mw-transport`)

## Context

`mw-transport` uses rustls for TLS 1.3 mutual authentication between mesh nodes.
rustls does not implement cryptography itself; it delegates to a
`CryptoProvider`. The choice of provider collides directly with ADR-003
(all-Rust) and ADR-006 (pure-Rust, static-musl for the PoC): rustls's two
built-in providers are both C-backed.

- The default provider, `aws-lc-rs`, requires a C toolchain (cmake/cc) and has
  documented build fragility on musl and older architectures.
- The alternative built-in, `ring`, is C/assembly, also requires `cc`, and has
  the same musl friction; teams have abandoned rustls for OpenSSL over exactly
  this build pain.

Either built-in defeats the pure-Rust/static-musl gate that is the PoC's central
claim: that MESHWARDEN runs on heterogeneous aging commodity hardware from a
single statically linked pure-Rust artifact per architecture.

## Decision

For the PoC, use **`rustls-rustcrypto`** — the pure-Rust rustls `CryptoProvider`
built on the RustCrypto primitives — with `rustls` set to
`default-features = false` to drop the `aws-lc-rs` dependency. Its experimental,
incomplete, non-FIPS status is accepted as a documented residual risk scoped to
the PoC and demo, not to production.

## Alternatives considered

- **`aws-lc-rs` (rustls default)** — most complete, FIPS-140-3 capable via a
  feature flag, best performance. Rejected for the PoC because the C build
  requirement and musl/old-architecture fragility break the pure-Rust/static-
  musl gate. It is the leading candidate *if and when* the gate is relaxed or a
  FIPS driver appears (see triggers).
- **`ring`** — mature, widely used, but C/asm with a `cc` requirement and the
  same musl friction. No advantage over aws-lc-rs for our constraints and less
  of a compliance story; rejected.
- **OpenSSL provider (`rustls-openssl`)** — heaviest system dependency, furthest
  from a self-contained static artifact; rejected.

`rustls-rustcrypto` wins on gate alignment: it is pure Rust and therefore
compiles wherever Rust targets, links cleanly into a static-musl binary with no
C toolchain, and reuses the RustCrypto family (`ed25519-dalek`, `x25519-dalek`,
`sha2`) that `mw-crypto` already depends on — one cryptographic ecosystem across
the whole fabric.

## Consequences

- The demo runs as a pure-Rust, statically linked musl artifact on aging
  hardware — the thesis is demonstrable rather than asserted.
- The provider is upstream-labelled experimental and "not for production": it
  implements only a subset of TLS suites (stated as sufficient for ~70% of
  usage), is neither formally verified nor FIPS-certified, and is generally
  slower than ring/aws-lc-rs. This must be recorded as an accepted residual risk
  (RSK) in the threat model and stated plainly in the Phase 8 proposal — the PoC
  proves the architecture, not a production-hardened TLS stack.
- Cipher-suite selection is constrained to what the provider implements;
  `mw-transport` must pin to suites it actually supports.
- Provider throughput on target hardware is unknown until measured; it belongs
  in the `lab/bench` matrix alongside the signature/hash numbers.

## Coupled decisions

- **ADR-003 (all-Rust) and ADR-006 (pure-Rust static-musl PoC).** This is the
  transport-layer realization of that gate. If the gate is relaxed for
  production, this decision flips — most likely to `aws-lc-rs`, which also opens
  the FIPS path.
- **ADR-005 (crypto posture — CNSA 2.0 reachable by policy flip).** FIPS/CNSA
  compliance lives with `aws-lc-rs` + its `fips` feature, so a compliance driver
  couples the provider choice to the crypto posture, not just to the build gate.

## Revisit triggers

- Production-hardening phase begins — reassess against `aws-lc-rs`.
- A FIPS or CNSA 2.0 compliance requirement becomes a real driver — move to
  `aws-lc-rs` with the `fips` feature.
- `rustls-rustcrypto` reaches an audited, production-declared state.
- A TLS suite required by the transport design is not implemented by the
  provider.
- Benchmarks on target (2010–2018 x86-64, low RAM) show provider performance is
  unacceptable for the workload.

## Traceability

SEC secure transport / mutual auth (SEC-01), NFR old-hardware fit and degraded-
link operation, HW pure-Rust static-musl on aging x86-64. Introduces a residual
risk (RSK — provider maturity: experimental, non-FIPS, subset of suites) to be
registered in `docs/03-threat-model.md`. Relates to ADR-003, ADR-005, ADR-006.