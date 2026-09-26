//! MESHWARDEN session authentication (ADR-017).
//!
//! This crate exists for dependency direction and composition reuse
//! (ADR-017 "Why a new crate"). It composes `mw-crypto`, `mw-identity`, and
//! `mw-proto` and must never depend on `mw-trust` (ADR-017 "Crate
//! ownership"). The "mw-session structure (ADR-017)" step of
//! `xtask/gate.sh` enforces that edge with `cargo tree`.
//!
//! [`machine`] is the pure authentication core. The async `driver` that owns
//! the TLS stream lands in Slice 5. Only `machine` is sans-I/O; the crate as a
//! whole is not (ADR-017 "Division of responsibility").

pub mod machine;
