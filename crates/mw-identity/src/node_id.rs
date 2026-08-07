//! Node identity: `mw:node:<base32-sha256-prefix>`, derived deterministically
//! from an Ed25519 public key (locked naming convention; ADR-008 binds
//! capability assertions to this identity).

use core::fmt;
use core::str::FromStr;

use data_encoding::BASE32_NOPAD;

use crate::Error;

/// URI-style scheme prefix of the textual form.
pub const NODE_ID_SCHEME: &str = "mw:node:";

/// Number of leading bytes of `sha256(public_key_bytes)` kept as the identity
/// prefix: 16 bytes (128 bits). Wide enough that accidental collision is
/// negligible at mesh scale, short enough to stay readable in logs and on
/// constrained links.
pub const NODE_ID_PREFIX_LEN: usize = 16;

/// Length of the base32 (RFC 4648, no padding) encoding of the 16-byte
/// prefix: ceil(16 * 8 / 5) = 26 characters.
pub const NODE_ID_ENCODED_LEN: usize = 26;

/// A node identity.
///
/// Displayed and parsed as `mw:node:<26 base32 chars>`. Serialized (postcard,
/// ADR-015) as that string, so the canonical certificate form embeds the
/// exact text a human sees in logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId {
    prefix: [u8; NODE_ID_PREFIX_LEN],
}

impl NodeId {
    /// Derives the identity from raw Ed25519 public key bytes.
    ///
    /// Deterministic: the same key bytes always yield the same [`NodeId`].
    pub fn from_public_key_bytes(public_key_bytes: &[u8]) -> Self {
        let digest = mw_crypto::sha256(public_key_bytes);
        let mut prefix = [0u8; NODE_ID_PREFIX_LEN];
        prefix.copy_from_slice(&digest.bytes[..NODE_ID_PREFIX_LEN]);
        Self { prefix }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{NODE_ID_SCHEME}{}", BASE32_NOPAD.encode(&self.prefix))
    }
}

impl FromStr for NodeId {
    type Err = Error;

    /// Parses and validates the textual form. Rejects a missing or wrong
    /// scheme, wrong encoded length (including padded input), and any
    /// character outside the RFC 4648 base32 alphabet.
    fn from_str(s: &str) -> Result<Self, Error> {
        let malformed = || Error::MalformedNodeId(s.to_owned());
        let encoded = s.strip_prefix(NODE_ID_SCHEME).ok_or_else(malformed)?;
        if encoded.len() != NODE_ID_ENCODED_LEN {
            return Err(malformed());
        }
        let decoded = BASE32_NOPAD
            .decode(encoded.as_bytes())
            .map_err(|_| malformed())?;
        let prefix = decoded.try_into().map_err(|_| malformed())?;
        Ok(Self { prefix })
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NodeIdVisitor;

        impl serde::de::Visitor<'_> for NodeIdVisitor {
            type Value = NodeId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an `mw:node:<base32-sha256-prefix>` string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<NodeId, E> {
                v.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NodeIdVisitor)
    }
}
