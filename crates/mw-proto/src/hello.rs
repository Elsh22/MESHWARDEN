//! Negotiation hello shape (capability set).

use mw_crypto::AlgId;
use serde::{Deserialize, Serialize};

use crate::{alg_from_u16, alg_to_u16, Error, Result};

/// Negotiation hello: the set of algorithms this node claims to support.
///
/// Capability advertisement is bound to attested identity and signed, **not**
/// asserted in-handshake (ADR-008). The cryptographic binding of this set to
/// a node identity lands in `mw-identity`; this type is only the wire shape.
///
/// Payload codec is postcard (ADR-015); see [`Hello::to_bytes`] and
/// [`Hello::from_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Supported algorithms. Serialized as registry `u16` wire codes.
    #[serde(serialize_with = "serialize_algs", deserialize_with = "deserialize_algs")]
    pub supported_algs: Vec<AlgId>,
}

impl Hello {
    /// Encodes this hello as postcard bytes (ADR-015).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::MalformedPayload)
    }

    /// Decodes a hello from postcard bytes (ADR-015).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).map_err(|_| Error::MalformedPayload)
    }
}

fn serialize_algs<S>(algs: &[AlgId], serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(algs.len()))?;
    for alg in algs {
        seq.serialize_element(&alg_to_u16(*alg))?;
    }
    seq.end()
}

fn deserialize_algs<'de, D>(deserializer: D) -> core::result::Result<Vec<AlgId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let codes: Vec<u16> = Vec::deserialize(deserializer)?;
    codes
        .into_iter()
        .map(|c| alg_from_u16(c).map_err(serde::de::Error::custom))
        .collect()
}
