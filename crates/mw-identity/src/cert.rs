//! Identity-bound capability certificate.
//!
//! ADR-008: a node's capabilities are only ever asserted inside this signed,
//! identity-bound certificate — never loose in a handshake. ADR-015: the
//! signed canonical form is postcard.

use mw_crypto::ed25519::PublicKey;
use mw_crypto::{AlgId, Signature, Signer, Verifier as _};
use serde::Serialize;

use crate::{Error, NodeId, Result};

/// Maximum certificate lifetime in seconds: 8 hours.
///
/// ADR-009: hours-scale lifetimes stand in for revocation in the PoC — a
/// compromised certificate ages out instead of being revoked, so revocation
/// stays out of scope. This is coupled to the Ed25519 hot-path decision
/// (ADR-005): short lifetimes mean every node re-signs and re-verifies
/// certificates every few hours, which is only tenable because Ed25519 is
/// cheap on aging hardware. A heavier signature scheme (e.g. the reserved
/// post-quantum `AlgId`s) would force longer lifetimes and re-open the
/// revocation question.
pub const MAX_CERT_LIFETIME_SECS: u64 = 8 * 60 * 60;

/// Everything a [`NodeCertificate`] carries except the signature; the input
/// to [`NodeCertificate::sign`].
#[derive(Debug, Clone)]
pub struct CertificateFields {
    pub subject: NodeId,
    /// Raw Ed25519 public key bytes of the subject.
    pub public_key: Vec<u8>,
    pub capabilities: Vec<AlgId>,
    /// Unix seconds, inclusive.
    pub valid_from: u64,
    /// Unix seconds, exclusive.
    pub valid_until: u64,
    pub issuer: NodeId,
}

/// The identity-bound capability advertisement (ADR-008).
///
/// The signature covers the postcard-serialized canonical form of every
/// other field, so tampering with any of them — including a single
/// capability entry — invalidates the certificate.
#[derive(Debug, Clone)]
pub struct NodeCertificate {
    pub subject: NodeId,
    /// Raw Ed25519 public key bytes of the subject.
    pub public_key: Vec<u8>,
    pub capabilities: Vec<AlgId>,
    /// Unix seconds, inclusive.
    pub valid_from: u64,
    /// Unix seconds, exclusive.
    pub valid_until: u64,
    pub issuer: NodeId,
    pub signature: Signature,
}

/// Canonical signing form (ADR-015): every field except the signature, in
/// declaration order, postcard-serialized. `AlgId` is carried as its registry
/// `u16` code (docs/spec/algorithm-registry.md). Any change to this struct's
/// field set, order, or types invalidates every previously issued signature.
#[derive(Serialize)]
struct CanonicalForm<'a> {
    subject: &'a NodeId,
    public_key: &'a [u8],
    capabilities: Vec<u16>,
    valid_from: u64,
    valid_until: u64,
    issuer: &'a NodeId,
}

fn canonical_bytes(
    subject: &NodeId,
    public_key: &[u8],
    capabilities: &[AlgId],
    valid_from: u64,
    valid_until: u64,
    issuer: &NodeId,
) -> Result<Vec<u8>> {
    let form = CanonicalForm {
        subject,
        public_key,
        capabilities: capabilities.iter().map(|&alg| alg as u16).collect(),
        valid_from,
        valid_until,
        issuer,
    };
    Ok(postcard::to_allocvec(&form)?)
}

/// ADR-009: the lifetime bound is enforced at construction so an over-long
/// certificate can never be issued, rather than caught at verification.
/// Inverted windows (`valid_until < valid_from`) are rejected on the same
/// path.
fn check_lifetime(valid_from: u64, valid_until: u64) -> Result<()> {
    match valid_until.checked_sub(valid_from) {
        Some(lifetime) if lifetime <= MAX_CERT_LIFETIME_SECS => Ok(()),
        _ => Err(Error::LifetimeExceedsMaximum {
            valid_from,
            valid_until,
        }),
    }
}

impl NodeCertificate {
    /// Signs `fields` with the issuer's key, producing a certificate.
    ///
    /// Enforces [`MAX_CERT_LIFETIME_SECS`] before signing (ADR-009). The
    /// signature is over the postcard canonical form (ADR-015).
    pub fn sign(fields: CertificateFields, issuer: &impl Signer) -> Result<Self> {
        check_lifetime(fields.valid_from, fields.valid_until)?;
        let msg = canonical_bytes(
            &fields.subject,
            &fields.public_key,
            &fields.capabilities,
            fields.valid_from,
            fields.valid_until,
            &fields.issuer,
        )?;
        let signature = issuer.sign(&msg).map_err(Error::Signing)?;
        Ok(Self {
            subject: fields.subject,
            public_key: fields.public_key,
            capabilities: fields.capabilities,
            valid_from: fields.valid_from,
            valid_until: fields.valid_until,
            issuer: fields.issuer,
            signature,
        })
    }

    /// Verifies the signature over the canonical form against the issuer's
    /// public key, then checks `valid_from <= now < valid_until`.
    ///
    /// `now` (unix seconds) is injected by the caller — this crate never
    /// reads an ambient clock, so validity is testable at any instant.
    pub fn verify(&self, issuer_public_key: &PublicKey, now: u64) -> Result<()> {
        let msg = canonical_bytes(
            &self.subject,
            &self.public_key,
            &self.capabilities,
            self.valid_from,
            self.valid_until,
            &self.issuer,
        )?;
        issuer_public_key
            .verify(&msg, &self.signature)
            .map_err(Error::BadSignature)?;
        if now < self.valid_from {
            return Err(Error::NotYetValid {
                valid_from: self.valid_from,
                now,
            });
        }
        if now >= self.valid_until {
            return Err(Error::Expired {
                valid_until: self.valid_until,
                now,
            });
        }
        Ok(())
    }
}
