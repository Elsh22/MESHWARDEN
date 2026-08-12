//! Identity-bound capability certificate.
//!
//! ADR-008: a node's capabilities are only ever asserted inside this signed,
//! identity-bound certificate — never loose in a handshake. ADR-015: the
//! signed canonical form is postcard. ADR-017: the complete certificate also
//! has a public wire encoding (`to_wire_bytes` / `from_wire_bytes`).

use core::convert::TryFrom;

use mw_crypto::ed25519::PublicKey;
use mw_crypto::{AlgId, Signature, Signer, Verifier as _};
use mw_proto::{
    BoundedBytes, BoundedVec, MAX_CERT_CAPABILITIES, MAX_CERTIFICATE_WIRE_BYTES,
    MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES, decode_exact,
};
use serde::{Deserialize, Serialize};

use crate::{CertificateWireField, Error, NodeId, Result};

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
    /// Raw subject public-key bytes.
    ///
    /// Untagged: there is no algorithm field on the certificate. In v1 these
    /// are interpreted as Ed25519 (ADR-017 §*Legacy: `NodeCertificate.public_key`
    /// is untagged*). Adding a `public_key_algorithm` field is a separate
    /// coupled decision requiring its own ADR.
    pub public_key: Vec<u8>,
    /// Capability registry codes (raw `u16`; ADR-017 Amendment 1).
    pub capabilities: Vec<u16>,
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
    /// Raw subject public-key bytes.
    ///
    /// Untagged: there is no algorithm field on the certificate. In v1 these
    /// are interpreted as Ed25519 (ADR-017 §*Legacy: `NodeCertificate.public_key`
    /// is untagged*). Adding a `public_key_algorithm` field is a separate
    /// coupled decision requiring its own ADR.
    pub public_key: Vec<u8>,
    /// Capability registry codes (raw `u16`; ADR-017 Amendment 1).
    pub capabilities: Vec<u16>,
    /// Unix seconds, inclusive.
    pub valid_from: u64,
    /// Unix seconds, exclusive.
    pub valid_until: u64,
    pub issuer: NodeId,
    pub signature: Signature,
}

/// Canonical signing form (ADR-015): every field except the signature, in
/// declaration order, postcard-serialized. Capabilities are raw registry
/// `u16` codes (docs/spec/algorithm-registry.md; ADR-017 Amendment 1). Any
/// change to this struct's field set, order, or types invalidates every
/// previously issued signature.
#[derive(Serialize)]
struct CanonicalForm<'a> {
    subject: &'a NodeId,
    public_key: &'a [u8],
    capabilities: Vec<u16>,
    valid_from: u64,
    valid_until: u64,
    issuer: &'a NodeId,
}

/// Complete certificate wire DTO (ADR-017 §*Certificate representations*).
///
/// Field order: every [`CanonicalForm`] field in that struct's exact
/// declaration order, then `signature_algorithm` and `signature`. Private;
/// constructed only by [`NodeCertificate::to_wire_bytes`] /
/// [`NodeCertificate::from_wire_bytes`].
///
/// `signature_algorithm` is a plain `u16` so unknown codes surface as a typed
/// identity error after decode, not as postcard's payload-free
/// `SerdeDeCustom`. Capability codes stay raw `u16` (Amendment 1 descriptive
/// side) and are never resolved here.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateWire {
    subject: NodeId,
    public_key: BoundedBytes<MAX_PUBLIC_KEY_BYTES>,
    capabilities: BoundedVec<u16, MAX_CERT_CAPABILITIES>,
    valid_from: u64,
    valid_until: u64,
    issuer: NodeId,
    signature_algorithm: u16,
    signature: BoundedBytes<MAX_SIGNATURE_BYTES>,
}

fn canonical_bytes(
    subject: &NodeId,
    public_key: &[u8],
    capabilities: &[u16],
    valid_from: u64,
    valid_until: u64,
    issuer: &NodeId,
) -> Result<Vec<u8>> {
    let form = CanonicalForm {
        subject,
        public_key,
        capabilities: capabilities.to_vec(),
        valid_from,
        valid_until,
        issuer,
    };
    Ok(postcard::to_allocvec(&form)?)
}

/// ADR-009 / ADR-017: the lifetime bound and window shape are enforced at
/// construction (`sign`) and re-enforced at verification (`verify`).
///
/// Construction-time enforcement was sufficient only while `sign` was the
/// sole way a certificate could exist; once certificates arrive from the
/// wire, an issuer with a valid key could otherwise mint a certificate
/// outliving the short-lifetime scheme that stands in for revocation
/// (coupled to RSK-017-4). Inverted windows (`valid_until < valid_from`) and
/// zero-length windows (`valid_until == valid_from`) are rejected on the
/// same path.
fn check_lifetime(valid_from: u64, valid_until: u64) -> Result<()> {
    match valid_until.checked_sub(valid_from) {
        Some(lifetime) if lifetime > 0 && lifetime <= MAX_CERT_LIFETIME_SECS => Ok(()),
        _ => Err(Error::LifetimeExceedsMaximum {
            valid_from,
            valid_until,
        }),
    }
}

fn check_capability_count(capabilities: &[u16]) -> Result<()> {
    let count = capabilities.len();
    if count > MAX_CERT_CAPABILITIES {
        return Err(Error::TooManyCapabilities {
            count,
            max: MAX_CERT_CAPABILITIES,
        });
    }
    Ok(())
}

fn check_wire_field_len(field: CertificateWireField, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(Error::FieldBoundExceeded { field, len, max });
    }
    Ok(())
}

/// Validates that `public_key` is a well-formed Ed25519 public key.
///
/// Implicit algorithm assumption (ADR-017 §*Legacy: `NodeCertificate.public_key`
/// is untagged*): the certificate carries no algorithm tag on `public_key`, so
/// treating it as Ed25519 holds only while Ed25519 is the sole implemented
/// signature algorithm. Adding a `public_key_algorithm` field is a separate
/// coupled decision requiring its own ADR — never invent it here.
fn check_subject_public_key(public_key: &[u8]) -> Result<()> {
    PublicKey::from_bytes(public_key).map_err(Error::MalformedSubjectPublicKey)?;
    Ok(())
}

impl NodeCertificate {
    /// Complete, authoritative capability set as raw registry codes.
    pub fn capability_codes(&self) -> &[u16] {
        &self.capabilities
    }

    /// Complete and correct for both positive and negative queries.
    ///
    /// Compares `alg.as_u16()` against the stored raw codes — does not resolve
    /// stored codes to [`AlgId`] first, so an unresolvable code in the set
    /// cannot silently change the answer.
    pub fn has_capability(&self, alg: AlgId) -> bool {
        let code = alg.as_u16();
        self.capabilities.contains(&code)
    }

    /// LOSSY: yields only codes this build can resolve to an [`AlgId`].
    ///
    /// This is **not** the complete capability set. Unknown or otherwise
    /// unresolvable registry codes present on the certificate are omitted.
    /// Callers that need the authoritative set must use
    /// [`capability_codes`](Self::capability_codes) or
    /// [`has_capability`](Self::has_capability).
    pub fn known_capabilities(&self) -> impl Iterator<Item = AlgId> + '_ {
        self.capabilities
            .iter()
            .copied()
            .filter_map(|code| AlgId::from_u16(code).ok())
    }

    /// Signs `fields` with the issuer's key, producing a certificate.
    ///
    /// Validation order (ADR-017 §*Certificate validation ordering*):
    /// capability count → subject key well-formedness → subject/key
    /// consistency → validity window → sign.
    ///
    /// Enforces [`MAX_CERT_LIFETIME_SECS`] and the window shape at
    /// construction (ADR-009), and [`MAX_CERT_CAPABILITIES`] (ADR-017). The
    /// signature is over the postcard canonical form (ADR-015).
    pub fn sign(fields: CertificateFields, issuer: &impl Signer) -> Result<Self> {
        check_capability_count(&fields.capabilities)?;
        check_subject_public_key(&fields.public_key)?;
        // Subject/issuer NodeId comparisons here and in `verify` operate on
        // public data (identities derived from public keys), so a
        // non-constant-time `!=` leaks nothing.
        if fields.subject != NodeId::from_public_key_bytes(&fields.public_key) {
            return Err(Error::SubjectKeyMismatch);
        }
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
    /// Validation order (ADR-017 §*Certificate validation ordering*):
    /// capability count → subject key well-formedness → subject mismatch →
    /// issuer mismatch → signature → validity-window re-check →
    /// not-yet-valid → expired.
    ///
    /// The lifetime cap and window shape are re-enforced here, not only in
    /// [`sign`](Self::sign): once certificates arrive from the wire, an
    /// issuer with a valid key could otherwise mint a certificate outliving
    /// the short-lifetime scheme that stands in for revocation (RSK-017-4).
    /// Wire decoding (slice 2b) stays concerned with bytes, counts, and
    /// canonicality only — this is the one semantic enforcement point for
    /// wire-arrived certificates.
    ///
    /// `now` (unix seconds) is injected by the caller — this crate never
    /// reads an ambient clock, so validity is testable at any instant.
    pub fn verify(&self, issuer_public_key: &PublicKey, now: u64) -> Result<()> {
        check_capability_count(&self.capabilities)?;
        check_subject_public_key(&self.public_key)?;
        if self.subject != NodeId::from_public_key_bytes(&self.public_key) {
            return Err(Error::SubjectKeyMismatch);
        }
        if self.issuer != NodeId::from_public_key_bytes(&issuer_public_key.to_bytes()) {
            return Err(Error::IssuerKeyMismatch);
        }
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
        check_lifetime(self.valid_from, self.valid_until)?;
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

    /// Encodes the complete certificate for the wire (ADR-017
    /// §*Certificate representations*).
    ///
    /// Check order:
    /// 1. field bounds (capability count, public-key length, signature length)
    ///    — each names the failing field; no DTO construction or encoding yet;
    /// 2. construct the private wire DTO;
    /// 3. postcard-encode once;
    /// 4. total-size check against [`MAX_CERTIFICATE_WIRE_BYTES`] →
    ///    [`Error::WireTooLarge`].
    ///
    /// Step 4 is defense-in-depth: with every field individually in bounds the
    /// worst-case encoding is ~674 bytes against 2048, so `WireTooLarge` is
    /// unreachable on the success path today. The guard remains for a future
    /// field, a raised field bound, or a lowered total bound.
    ///
    /// Capability count reuses [`Error::TooManyCapabilities`] from
    /// [`sign`](Self::sign) / [`verify`](Self::verify).
    ///
    /// Does **not** validate the certificate: encoding is not verification.
    pub fn to_wire_bytes(&self) -> Result<Vec<u8>> {
        check_capability_count(&self.capabilities)?;
        check_wire_field_len(
            CertificateWireField::PublicKey,
            self.public_key.len(),
            MAX_PUBLIC_KEY_BYTES,
        )?;
        check_wire_field_len(
            CertificateWireField::Signature,
            self.signature.bytes.len(),
            MAX_SIGNATURE_BYTES,
        )?;
        // Step-1 bounds match the DTO type parameters, so the validating
        // constructors below cannot fail for a bound reason.
        let dto = Self::wire_dto_from_fields(self)?;
        let bytes = postcard::to_allocvec(&dto)?;
        if bytes.len() > MAX_CERTIFICATE_WIRE_BYTES {
            return Err(Error::WireTooLarge {
                len: bytes.len(),
                max: MAX_CERTIFICATE_WIRE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes a complete certificate from wire bytes (ADR-017
    /// §*Certificate representations*).
    ///
    /// Normative check order (bytes-level before semantic, cheapest first):
    /// 1. input length against [`MAX_CERTIFICATE_WIRE_BYTES`] →
    ///    [`Error::WireTooLarge`] (no parse attempt);
    /// 2. bounded decode with whole-input consumption via
    ///    [`mw_proto::decode_exact`];
    /// 3. canonical re-encoding comparison → [`Error::NonCanonicalEncoding`];
    /// 4. signature-algorithm resolution via [`AlgId::try_from`] →
    ///    [`Error::UnknownAlgorithm`].
    ///
    /// Capability codes are **not** resolved — they remain raw `u16`.
    ///
    /// Decoding performs **no** signature verification, identity-consistency
    /// check, temporal check, or subject-key well-formedness check. A
    /// decoded certificate with a garbage signature must be rejected by
    /// [`verify`](Self::verify), not here.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CERTIFICATE_WIRE_BYTES {
            return Err(Error::WireTooLarge {
                len: bytes.len(),
                max: MAX_CERTIFICATE_WIRE_BYTES,
            });
        }
        let dto: CertificateWire = decode_exact(bytes)?;
        let reencoded = postcard::to_allocvec(&dto)?;
        if reencoded.as_slice() != bytes {
            return Err(Error::NonCanonicalEncoding);
        }
        let alg = AlgId::try_from(dto.signature_algorithm)?;
        Ok(Self {
            subject: dto.subject,
            public_key: dto.public_key.into_inner(),
            capabilities: dto.capabilities.into_inner(),
            valid_from: dto.valid_from,
            valid_until: dto.valid_until,
            issuer: dto.issuer,
            signature: Signature {
                alg,
                bytes: dto.signature.into_inner(),
            },
        })
    }

    /// Builds the wire DTO after field bounds have already been checked.
    ///
    /// Maps any residual `BoundExceeded` from the validating constructors to
    /// the named encode-time variants. That path is unreachable when the
    /// step-1 checks and the DTO type parameters agree; a failure here would
    /// mean those bounds have drifted.
    fn wire_dto_from_fields(cert: &Self) -> Result<CertificateWire> {
        let public_key = BoundedBytes::from_slice(&cert.public_key).map_err(|e| match e {
            mw_proto::Error::BoundExceeded { declared, max } => Error::FieldBoundExceeded {
                field: CertificateWireField::PublicKey,
                len: declared,
                max,
            },
            other => Error::Wire(other),
        })?;
        let capabilities = BoundedVec::new(cert.capabilities.clone()).map_err(|e| match e {
            mw_proto::Error::BoundExceeded { declared, max } => Error::TooManyCapabilities {
                count: declared,
                max,
            },
            other => Error::Wire(other),
        })?;
        let signature = BoundedBytes::from_slice(&cert.signature.bytes).map_err(|e| match e {
            mw_proto::Error::BoundExceeded { declared, max } => Error::FieldBoundExceeded {
                field: CertificateWireField::Signature,
                len: declared,
                max,
            },
            other => Error::Wire(other),
        })?;
        Ok(CertificateWire {
            subject: cert.subject,
            public_key,
            capabilities,
            valid_from: cert.valid_from,
            valid_until: cert.valid_until,
            issuer: cert.issuer,
            signature_algorithm: cert.signature.alg.as_u16(),
            signature,
        })
    }
}
