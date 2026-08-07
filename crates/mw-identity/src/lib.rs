//! MESHWARDEN node identity: [`NodeId`] derivation, the node [`Keystore`],
//! and the identity-bound capability certificate [`NodeCertificate`]
//! (ADR-008, ADR-009, ADR-015).
//!
//! Depends on `mw-crypto` and no other `mw-*` crate. X.509/DER, enrollment
//! (`mw-ca`), rustls integration (`mw-transport`), and revocation are out of
//! scope here.
//!
//! No ambient clock: every temporal check takes `now` (unix seconds) as a
//! parameter; `SystemTime::now()` is never called in this crate.

pub mod cert;
pub mod keystore;
pub mod node_id;

pub use cert::{CertificateFields, MAX_CERT_LIFETIME_SECS, NodeCertificate};
pub use keystore::Keystore;
pub use node_id::NodeId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `now` precedes the certificate's `valid_from`.
    #[error("certificate not yet valid: valid_from {valid_from}, checked at {now}")]
    NotYetValid { valid_from: u64, now: u64 },
    /// `now` is at or past the certificate's `valid_until` (exclusive bound).
    #[error("certificate expired: valid_until {valid_until}, checked at {now}")]
    Expired { valid_until: u64, now: u64 },
    /// The signature does not verify over the canonical form.
    #[error("certificate signature verification failed")]
    BadSignature(#[source] mw_crypto::Error),
    /// ADR-009: the validity window is longer than
    /// [`MAX_CERT_LIFETIME_SECS`], or inverted (`valid_until < valid_from`).
    #[error(
        "certificate validity window {valid_from}..{valid_until} exceeds \
         maximum lifetime {max}s or is inverted",
        max = MAX_CERT_LIFETIME_SECS
    )]
    LifetimeExceedsMaximum { valid_from: u64, valid_until: u64 },
    /// Input does not parse as `mw:node:<base32-sha256-prefix>`.
    #[error("malformed node id: {0:?}")]
    MalformedNodeId(String),
    /// Signing the canonical form failed.
    #[error("signing the canonical certificate form failed")]
    Signing(#[source] mw_crypto::Error),
    /// Canonical-form encoding failed (postcard, ADR-015).
    #[error("canonical form encoding failed")]
    Codec(#[from] postcard::Error),
}

pub type Result<T> = core::result::Result<T, Error>;
