//! MESHWARDEN transport — slice 1: TLS 1.3 plumbing over the pure-Rust
//! rustls provider (ADR-016), with `mw-proto` framing on top (ADR-015).
//!
//! # What this slice is — and is not
//!
//! This slice establishes a **confidential but NOT mutually authenticated**
//! channel. The client accepts whatever certificate the server presents
//! ([`verify::AcceptAnyServerCert`]) and the server certificate is a
//! throwaway ([`devcert`]) with no relation to any mesh identity. How a peer
//! is bound to a `NodeId`/`NodeCertificate` is a security-architecture
//! decision that lands in slice 2 once ADR-017 is settled. **Nothing may
//! make trust decisions on a slice-1 channel.** To make that structural
//! rather than prose, every stream produced by [`channel::connect`] /
//! [`channel::accept`] is wrapped in the [`channel::Unauthenticated`]
//! marker type.
//!
//! Also deferred to slice 2 / ADR-017: mutual client authentication, channel
//! binding (exported keying material), real TCP sockets, session/replay
//! handling. This crate declares no direct dependency on `mw-crypto` or
//! `mw-identity` (`mw-crypto` is still reachable transitively through
//! `mw-proto`, which carries `AlgId` — an ADR-007-sanctioned edge).

pub mod channel;
pub mod devcert;
pub mod verify;

pub use channel::{FramedChannel, Unauthenticated, accept, client_config, connect, server_config};

/// Installs `rustls-rustcrypto` as the process-default rustls
/// [`CryptoProvider`](rustls::crypto::CryptoProvider) (ADR-016). No built-in
/// (C-backed) provider is compiled into the dependency graph.
///
/// Idempotent: ignoring the install result is deliberate — `Err` only means
/// a default provider is already installed, and in a MESHWARDEN process that
/// is this same provider from an earlier call; nothing else installs one.
pub fn install_default_provider() {
    let _ = rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider());
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The TLS handshake did not complete.
    #[error("TLS handshake failed")]
    Handshake(#[source] std::io::Error),
    /// TLS configuration was rejected by rustls (e.g. bad certificate/key).
    #[error("TLS configuration error")]
    Tls(#[from] rustls::Error),
    /// I/O on the established channel failed (includes a peer closing the
    /// stream mid-frame, surfaced as `UnexpectedEof`).
    #[error("channel I/O failed")]
    Io(#[from] std::io::Error),
    /// Frame or payload codec error surfaced from `mw-proto`.
    #[error("frame codec error")]
    Frame(#[from] mw_proto::Error),
    /// Slice-1 throwaway certificate generation failed ([`devcert`]).
    #[error("throwaway certificate generation failed: {0}")]
    DevCert(String),
}

pub type Result<T> = core::result::Result<T, Error>;
