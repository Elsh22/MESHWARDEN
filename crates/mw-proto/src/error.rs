//! Wire-protocol errors.

/// Errors produced while decoding or validating wire types.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Algorithm code not in docs/spec/algorithm-registry.md (invariant 3).
    #[error("unknown algorithm code 0x{0:04X}")]
    UnknownAlgorithm(u16),

    /// Peer spoke a wire major version we do not implement.
    #[error("unsupported wire version v{0}")]
    UnsupportedWireVersion(u16),

    /// Frame header or body is truncated or otherwise malformed.
    #[error("malformed or truncated frame")]
    MalformedFrame,

    /// Declared payload length exceeds [`crate::MAX_PAYLOAD_LEN`].
    #[error("payload too large: {len} bytes exceeds limit {max}")]
    PayloadTooLarge { len: usize, max: usize },

    /// Payload bytes failed to decode under the payload codec (postcard,
    /// ADR-015).
    #[error("malformed payload")]
    MalformedPayload,
}

pub type Result<T> = core::result::Result<T, Error>;
