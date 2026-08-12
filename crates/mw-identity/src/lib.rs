//! MESHWARDEN node identity: [`NodeId`] derivation, the node [`Keystore`],
//! and the identity-bound capability certificate [`NodeCertificate`]
//! (ADR-008, ADR-009, ADR-015).
//!
//! Depends on `mw-crypto` and `mw-proto` (bound constants; ADR-017 Amendment 3).
//! X.509/DER, enrollment (`mw-ca`), rustls integration (`mw-transport`), and
//! revocation are out of scope here.
//!
//! No ambient clock: every temporal check takes `now` (unix seconds) as a
//! parameter; `SystemTime::now()` is never called in this crate.

pub mod cert;
pub mod keystore;
pub mod node_id;

pub use cert::{CertificateFields, MAX_CERT_LIFETIME_SECS, NodeCertificate};
pub use keystore::Keystore;
pub use node_id::NodeId;

/// Wire-field identity for encode-time bound violations on a complete
/// certificate (`NodeCertificate::to_wire_bytes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateWireField {
    /// `public_key` length against [`mw_proto::MAX_PUBLIC_KEY_BYTES`].
    PublicKey,
    /// `signature` byte length against [`mw_proto::MAX_SIGNATURE_BYTES`].
    Signature,
}

impl core::fmt::Display for CertificateWireField {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PublicKey => "public_key",
            Self::Signature => "signature",
        })
    }
}

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
    /// The certificate's `subject` is not the [`NodeId`] derived from its own
    /// `public_key` — the name and the key material disagree.
    #[error("certificate subject does not match its public key")]
    SubjectKeyMismatch,
    /// The certificate's `issuer` is not the [`NodeId`] derived from the
    /// verifying key the caller supplied — a valid signature from the wrong
    /// key would otherwise pass.
    #[error("certificate issuer does not match the supplied issuer public key")]
    IssuerKeyMismatch,
    /// ADR-009 / ADR-017: the validity window is longer than
    /// [`MAX_CERT_LIFETIME_SECS`], inverted (`valid_until < valid_from`), or
    /// zero-length (`valid_until == valid_from`).
    #[error(
        "certificate validity window {valid_from}..{valid_until} exceeds \
         maximum lifetime {max}s, is inverted, or is zero-length",
        max = MAX_CERT_LIFETIME_SECS
    )]
    LifetimeExceedsMaximum { valid_from: u64, valid_until: u64 },
    /// ADR-017: more than [`mw_proto::MAX_CERT_CAPABILITIES`] capability codes.
    #[error("certificate has {count} capabilities; maximum is {max}")]
    TooManyCapabilities { count: usize, max: usize },
    /// A variable-length certificate wire field exceeds its bound.
    ///
    /// Raised by encode-time field checks in
    /// [`NodeCertificate::to_wire_bytes`] before any DTO construction or
    /// postcard encoding, so the failing field is named.
    #[error("certificate wire field {field} is {len} bytes; maximum is {max}")]
    FieldBoundExceeded {
        field: CertificateWireField,
        len: usize,
        max: usize,
    },
    /// Subject `public_key` is not a well-formed Ed25519 public key.
    ///
    /// Implicit algorithm assumption: ADR-017 §*Legacy: `NodeCertificate.public_key`
    /// is untagged*.
    #[error("certificate subject public key is not a well-formed Ed25519 key")]
    MalformedSubjectPublicKey(#[source] mw_crypto::Error),
    /// Input does not parse as `mw:node:<base32-sha256-prefix>`.
    ///
    /// Embeds the caller-supplied input string; callers should be deliberate
    /// about what reaches logs.
    #[error("malformed node id: {0:?}")]
    MalformedNodeId(String),
    /// Signing the canonical form failed.
    #[error("signing the canonical certificate form failed")]
    Signing(#[source] mw_crypto::Error),
    /// Canonical-form or wire-form encoding failed (postcard, ADR-015).
    #[error("canonical form encoding failed")]
    Codec(#[from] postcard::Error),
    /// Structural, bound, or trailing-byte failure while decoding certificate
    /// wire bytes (`mw_proto::decode_exact`).
    ///
    /// **Known limitation:** `mw_proto::Error::BoundExceeded` does not name
    /// which field exceeded its bound, so a decode-time bound failure cannot
    /// say whether it was the public key, the signature, or the capability
    /// list. Changing `mw-proto`'s error shape is out of scope here.
    #[error(transparent)]
    Wire(#[from] mw_proto::Error),
    /// Input (or encoded output) exceeds [`mw_proto::MAX_CERTIFICATE_WIRE_BYTES`].
    #[error("certificate wire encoding is {len} bytes; maximum is {max}")]
    WireTooLarge { len: usize, max: usize },
    /// Decoded certificate re-encodes to different bytes than the input
    /// (ADR-017 §Normative parsing rules rule 2).
    #[error("certificate wire encoding is not canonical")]
    NonCanonicalEncoding,
    /// Signature algorithm registry code is not known to this build.
    #[error(transparent)]
    UnknownAlgorithm(#[from] mw_crypto::UnknownAlgorithmCode),
}

pub type Result<T> = core::result::Result<T, Error>;
