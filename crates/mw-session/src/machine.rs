//! Pure authentication state machine, `AuthMachine` (ADR-017 "Division of
//! responsibility", `mw-session::machine`). This module is a scaffold; the
//! machine lands in later Slice 4 tasks.
//!
//! Per ADR-017, the machine will consume validated inputs and events and
//! produce authentication outputs or a verified `AuthOutcome`. It will
//! perform certificate validation, transcript construction, and signature
//! verification with public keys only. To sign, it will emit a request; it
//! must never hold or receive private key material (ADR-017 Security
//! invariants, INV-14).
//!
//! It must not own or consume the TLS stream or construct
//! `AuthenticatedSession<S>`. It must perform no I/O, read no clock, run no
//! timer, and draw no entropy. The current time, the channel binding, and
//! nonces are inputs supplied by the driver.
//!
//! `xtask/check-machine-purity.sh`, run by `xtask/gate.sh`, enforces the
//! textual part of these rules on every `machine` source file.
