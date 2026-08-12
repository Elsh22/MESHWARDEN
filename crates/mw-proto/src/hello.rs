//! Negotiation hello shape (capability advertisement).

use mw_crypto::AlgId;
use serde::{Deserialize, Serialize};

use crate::{BoundedVec, Error, MAX_HELLO_ALGS, Result, alg_from_u16, alg_to_u16, decode_exact};

/// Negotiation hello: the set of algorithms this node claims to support.
///
/// Capability advertisement is bound to attested identity and signed, **not**
/// asserted in-handshake (ADR-008). The cryptographic binding of this set to
/// a node identity lands in `mw-identity`; this type is only the wire shape.
///
/// Under ADR-017 Amendment 1, `supported_algs` is **descriptive / advisory**:
/// codes are raw registry `u16` values. Unknown codes are non-fatal at decode
/// (contrast [`crate::WireSignature::algorithm`], which is acted-upon and
/// rejects unknowns). Hello advertisement is never used for a security
/// decision by itself.
///
/// Payload codec is postcard (ADR-015); see [`Hello::to_bytes`] and
/// [`Hello::from_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Supported algorithm registry codes (raw `u16`).
    ///
    /// Bounded by [`MAX_HELLO_ALGS`] — an independent constant from
    /// [`crate::MAX_CERT_CAPABILITIES`] (descriptive advertisement vs
    /// attested capabilities; same anti-DoS cardinality).
    pub supported_algs: BoundedVec<u16, MAX_HELLO_ALGS>,
}

impl Hello {
    /// Constructs a hello from raw registry codes.
    pub fn new(codes: Vec<u16>) -> Result<Self> {
        Ok(Self {
            supported_algs: BoundedVec::new(codes)?,
        })
    }

    /// Constructs a hello from known [`AlgId`] values.
    pub fn from_algorithms(algs: &[AlgId]) -> Result<Self> {
        Self::new(algs.iter().copied().map(alg_to_u16).collect())
    }

    /// Complete and authoritative advertisement codes (raw registry `u16`).
    pub fn algorithm_codes(&self) -> &[u16] {
        self.supported_algs.as_slice()
    }

    /// LOSSY: yields only codes this build can resolve to an [`AlgId`].
    ///
    /// This is **not** the complete advertisement set. Unknown or otherwise
    /// unresolvable registry codes present on the wire are omitted. Callers
    /// that need the authoritative set must use
    /// [`algorithm_codes`](Self::algorithm_codes).
    pub fn known_algorithms(&self) -> impl Iterator<Item = AlgId> + '_ {
        self.supported_algs
            .as_slice()
            .iter()
            .copied()
            .filter_map(|code| alg_from_u16(code).ok())
    }

    /// Encodes this hello as postcard bytes (ADR-015).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::EncodeFailed)
    }

    /// Decodes a hello from postcard bytes (ADR-015).
    ///
    /// Strict decode (ADR-017 §Normative parsing rules rule 1): trailing
    /// bytes are [`Error::TrailingBytes`]. Bound violations are
    /// [`Error::BoundExceeded`]. Other decode failures are
    /// [`Error::MalformedWire`]. Unknown algorithm codes are **accepted**.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        decode_exact(bytes)
    }
}
