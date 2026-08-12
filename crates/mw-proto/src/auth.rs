//! Authentication wire messages and signing transcript (ADR-017).
//!
//! Certificates are opaque [`BoundedBytes`] — never parsed or interpreted
//! here. `mw-proto` must not depend on `mw-identity`. Signature-list arity,
//! `auth_version`, node-id parsing, and subject matching are `mw-session`
//! concerns; decoding performs none of them.

use serde::{Deserialize, Serialize};

use crate::{
    BoundedBytes, BoundedVec, Error, MAX_AUTH_CONFIRM_BYTES, MAX_AUTH_INIT_BYTES,
    MAX_AUTH_RESPONSE_BYTES, MAX_AUTH_TRANSCRIPT_BYTES, MAX_CERTIFICATE_WIRE_BYTES,
    MAX_PROOF_SIGNATURES, MAX_SIGNATURE_BYTES, Result, alg_from_u16, decode_exact,
};

/// Domain separation constant for [`AuthTranscriptV1`] (16 bytes including
/// the trailing NUL).
pub const AUTH_TRANSCRIPT_DOMAIN_V1: &[u8] = b"MESHWARDEN-AUTH\0";

/// [`AuthTranscriptV1::role`] value for the client endpoint.
pub const AUTH_ROLE_CLIENT: u8 = 0x01;

/// [`AuthTranscriptV1::role`] value for the server endpoint.
pub const AUTH_ROLE_SERVER: u8 = 0x02;

/// TLS 1.3 exporter label for channel binding (ADR-017 §The TLS exporter
/// binding).
///
/// Context is **unconditionally `None`**. Output length is **exactly 32
/// bytes**. TLS 1.3 only. The label version (`-v1`) is inseparable from the
/// transcript version: an `AuthTranscriptV2` requires an `-v2` label, and
/// vice versa, so cross-version proofs fail closed.
///
/// The driver performs `export_keying_material`; this crate only names the
/// label.
pub const EXPORTER_LABEL_V1: &str = "EXPERIMENTAL-MESHWARDEN-AUTH-v1";

const _: () = assert!(AUTH_TRANSCRIPT_DOMAIN_V1.len() == 16);

/// One entry in an authentication proof signature list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSignature {
    /// Algorithm-registry wire code (resolved after decode).
    pub algorithm: u16,
    /// Variable-length, bounded signature bytes.
    pub signature: BoundedBytes<MAX_SIGNATURE_BYTES>,
}

/// Client → server authentication init (message code `0x0002`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthInit {
    pub auth_version: u16,
    pub client_nonce: BoundedBytes<32>,
    /// Opaque certificate wire octets — never parsed in this crate.
    pub client_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
}

/// Server → client authentication response (message code `0x0003`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub auth_version: u16,
    pub server_nonce: BoundedBytes<32>,
    /// Opaque certificate wire octets — never parsed in this crate.
    pub server_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
    pub signatures: BoundedVec<WireSignature, MAX_PROOF_SIGNATURES>,
}

/// Client → server authentication confirm (message code `0x0004`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfirm {
    pub signatures: BoundedVec<WireSignature, MAX_PROOF_SIGNATURES>,
}

/// Versioned authentication transcript. Signed by both endpoints.
///
/// Never transmitted; reconstructed independently by each side. Field order
/// is ADR-017-normative and must not change (a change breaks every deployed
/// signature — use `AuthTranscriptV2` + `-v2` label instead).
///
/// Node-id fields are length-checked only. Parsing as a `NodeId` and matching
/// the certificate subject is `mw-session`'s job; this crate must not depend
/// on `mw-identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthTranscriptV1 {
    pub domain: BoundedBytes<16>,
    pub auth_version: u16,
    pub auth_algorithm: u16,
    pub role: u8,
    pub channel_binding: BoundedBytes<32>,
    pub client_node_id: BoundedBytes<34>,
    pub server_node_id: BoundedBytes<34>,
    pub client_nonce: BoundedBytes<32>,
    pub server_nonce: BoundedBytes<32>,
    /// Exact octets observed on the wire, not a re-encoding.
    pub client_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
    pub server_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
}

fn resolve_signature_algorithms(signatures: &[WireSignature]) -> Result<()> {
    for sig in signatures {
        // Acted-upon Amendment 1: unknown algorithm codes are rejected.
        // Resolve through the registry — never a local match.
        let _ = alg_from_u16(sig.algorithm)?;
    }
    Ok(())
}

fn check_canonical(bytes: &[u8], reencoded: &[u8]) -> Result<()> {
    if reencoded != bytes {
        return Err(Error::NonCanonicalEncoding);
    }
    Ok(())
}

impl AuthInit {
    /// Encodes this message as postcard bytes.
    ///
    /// Check order: field bounds (exact nonce length) → encode → total vs
    /// [`MAX_AUTH_INIT_BYTES`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.client_nonce.require_exact_len(32)?;
        // Certificate length is already gated by BoundedBytes construction.
        let bytes = postcard::to_allocvec(self).map_err(|_| Error::EncodeFailed)?;
        if bytes.len() > MAX_AUTH_INIT_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_INIT_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes from postcard bytes.
    ///
    /// Check order: total length vs [`MAX_AUTH_INIT_BYTES`] →
    /// [`decode_exact`] → canonical re-encode. Performs **no** semantic
    /// validation (`auth_version`, certificate contents).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_AUTH_INIT_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_INIT_BYTES,
            });
        }
        let value: Self = decode_exact(bytes)?;
        let reencoded = postcard::to_allocvec(&value).map_err(|_| Error::EncodeFailed)?;
        check_canonical(bytes, &reencoded)?;
        Ok(value)
    }
}

impl AuthResponse {
    /// Encodes this message as postcard bytes.
    ///
    /// Check order: field bounds (exact nonce length, signature-byte bounds
    /// already in [`WireSignature`]) → encode → total vs
    /// [`MAX_AUTH_RESPONSE_BYTES`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.server_nonce.require_exact_len(32)?;
        // Signature bytes and list cardinality are already gated by
        // BoundedBytes / BoundedVec construction.
        let bytes = postcard::to_allocvec(self).map_err(|_| Error::EncodeFailed)?;
        if bytes.len() > MAX_AUTH_RESPONSE_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_RESPONSE_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes from postcard bytes.
    ///
    /// Check order: total length → [`decode_exact`] → canonical re-encode →
    /// resolve each [`WireSignature::algorithm`]. Does **not** check
    /// signature-list arity, `auth_version`, or certificates.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_AUTH_RESPONSE_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_RESPONSE_BYTES,
            });
        }
        let value: Self = decode_exact(bytes)?;
        let reencoded = postcard::to_allocvec(&value).map_err(|_| Error::EncodeFailed)?;
        check_canonical(bytes, &reencoded)?;
        resolve_signature_algorithms(value.signatures.as_slice())?;
        Ok(value)
    }
}

impl AuthConfirm {
    /// Encodes this message as postcard bytes.
    ///
    /// Check order: encode → total vs [`MAX_AUTH_CONFIRM_BYTES`]. Signature
    /// field bounds are carried by [`BoundedVec`] / [`BoundedBytes`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_allocvec(self).map_err(|_| Error::EncodeFailed)?;
        if bytes.len() > MAX_AUTH_CONFIRM_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_CONFIRM_BYTES,
            });
        }
        Ok(bytes)
    }

    /// Decodes from postcard bytes.
    ///
    /// Check order: total length → [`decode_exact`] → canonical re-encode →
    /// resolve each [`WireSignature::algorithm`]. Empty signature lists
    /// decode successfully; arity is slice 4's job.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_AUTH_CONFIRM_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_CONFIRM_BYTES,
            });
        }
        let value: Self = decode_exact(bytes)?;
        let reencoded = postcard::to_allocvec(&value).map_err(|_| Error::EncodeFailed)?;
        check_canonical(bytes, &reencoded)?;
        resolve_signature_algorithms(value.signatures.as_slice())?;
        Ok(value)
    }
}

impl AuthTranscriptV1 {
    /// Constructs a transcript, performing every exact-length check and the
    /// domain / role gates. An invalid transcript cannot be built.
    ///
    /// Node-id fields are length-only (see struct docs). Certificates are
    /// length-bounded only.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: Vec<u8>,
        auth_version: u16,
        auth_algorithm: u16,
        role: u8,
        channel_binding: Vec<u8>,
        client_node_id: Vec<u8>,
        server_node_id: Vec<u8>,
        client_nonce: Vec<u8>,
        server_nonce: Vec<u8>,
        client_certificate: Vec<u8>,
        server_certificate: Vec<u8>,
    ) -> Result<Self> {
        if role != AUTH_ROLE_CLIENT && role != AUTH_ROLE_SERVER {
            return Err(Error::InvalidAuthRole(role));
        }

        let domain = BoundedBytes::<16>::new(domain)?;
        domain.require_exact_len(16)?;
        if domain.as_slice() != AUTH_TRANSCRIPT_DOMAIN_V1 {
            // Wrong bytes at the correct length: not ExactLength. Treat as
            // malformed wire input for the domain gate.
            return Err(Error::MalformedWire);
        }

        let channel_binding = BoundedBytes::<32>::new(channel_binding)?;
        channel_binding.require_exact_len(32)?;

        // Length only — NodeId parse / subject match is mw-session.
        let client_node_id = BoundedBytes::<34>::new(client_node_id)?;
        client_node_id.require_exact_len(34)?;
        let server_node_id = BoundedBytes::<34>::new(server_node_id)?;
        server_node_id.require_exact_len(34)?;

        let client_nonce = BoundedBytes::<32>::new(client_nonce)?;
        client_nonce.require_exact_len(32)?;
        let server_nonce = BoundedBytes::<32>::new(server_nonce)?;
        server_nonce.require_exact_len(32)?;

        let client_certificate =
            BoundedBytes::<MAX_CERTIFICATE_WIRE_BYTES>::new(client_certificate)?;
        let server_certificate =
            BoundedBytes::<MAX_CERTIFICATE_WIRE_BYTES>::new(server_certificate)?;

        Ok(Self {
            domain,
            auth_version,
            auth_algorithm,
            role,
            channel_binding,
            client_node_id,
            server_node_id,
            client_nonce,
            server_nonce,
            client_certificate,
            server_certificate,
        })
    }

    /// Postcard encoding used as the signing input.
    ///
    /// There is intentionally **no decoder**: the transcript is never
    /// transmitted, and an unused decoder would be attack surface plus a
    /// second representation to keep canonical.
    pub fn to_signing_bytes(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_allocvec(self).map_err(|_| Error::EncodeFailed)?;
        if bytes.len() > MAX_AUTH_TRANSCRIPT_BYTES {
            return Err(Error::MessageTooLarge {
                len: bytes.len(),
                max: MAX_AUTH_TRANSCRIPT_BYTES,
            });
        }
        Ok(bytes)
    }
}
