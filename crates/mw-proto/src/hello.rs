//! Negotiation hello shape (capability set).

use mw_crypto::AlgId;
use serde::{Deserialize, Serialize};

use crate::{Error, Result, alg_from_u16, alg_to_u16};

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
    #[serde(
        serialize_with = "serialize_algs",
        deserialize_with = "deserialize_algs"
    )]
    pub supported_algs: Vec<AlgId>,
}

impl Hello {
    /// Encodes this hello as postcard bytes (ADR-015).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        postcard::to_allocvec(self).map_err(|_| Error::MalformedPayload)
    }

    /// Decodes a hello from postcard bytes (ADR-015).
    ///
    /// Strict decode (ADR-017 §Normative parsing rules rule 1): trailing
    /// bytes are rejected as [`Error::TrailingBytes`]. Other decode failures
    /// keep the historical [`Error::MalformedPayload`] shape; the
    /// error-taxonomy split (unknown-algorithm vs malformed-payload) is
    /// deferred to the auth-message slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        crate::decode_exact(bytes).map_err(|e| match e {
            Error::TrailingBytes { .. } => e,
            _ => Error::MalformedPayload,
        })
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

/// Decodes the algorithm sequence without preallocating from a size hint.
///
/// `Hello::from_bytes` decodes through [`crate::decode_exact`], whose opaque
/// flavor wrapper makes the declared element count visible to every visitor
/// (see the doctrine on `decode_exact`). Delegating to
/// `Vec::<u16>::deserialize` would let `serde`'s `Vec` visitor
/// `with_capacity` from that attacker-controlled declaration (capped at
/// ~1 MiB by `size_hint::cautious`). This visitor instead starts from
/// `Vec::new()` and pushes as elements decode, so growth comes only from
/// bytes actually present.
///
/// `Hello.supported_algs` has no normative maximum, and inventing one is
/// forbidden: push-until-input-exhausted is the correct behavior. Unknown
/// algorithm codes still map through [`alg_from_u16`]; the
/// `UnknownAlgorithm`-vs-`MalformedPayload` error-taxonomy split remains the
/// auth-message slice's job.
fn deserialize_algs<'de, D>(deserializer: D) -> core::result::Result<Vec<AlgId>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AlgSeqVisitor;

    impl<'de> serde::de::Visitor<'de> for AlgSeqVisitor {
        type Value = Vec<AlgId>;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("a sequence of u16 algorithm codes")
        }

        fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            // Deliberately ignores `seq.size_hint()`.
            let mut algs = Vec::new();
            while let Some(code) = seq.next_element::<u16>()? {
                algs.push(alg_from_u16(code).map_err(serde::de::Error::custom)?);
            }
            Ok(algs)
        }
    }

    deserializer.deserialize_seq(AlgSeqVisitor)
}
