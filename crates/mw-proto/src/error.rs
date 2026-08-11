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

    /// A declared length or element count exceeded its bound.
    #[error("bound exceeded: declared {declared} exceeds maximum {max}")]
    BoundExceeded { declared: usize, max: usize },

    /// Input contained bytes after a complete value (ADR-017 strict decode).
    #[error("{remaining} trailing byte(s) after a complete value")]
    TrailingBytes { remaining: usize },

    /// A fixed-length field's length was within bound but not exact.
    #[error("exact length violation: expected {expected}, got {actual}")]
    ExactLength { expected: usize, actual: usize },

    /// Input was not well-formed under the payload codec, with no more
    /// specific cause available.
    #[error("malformed wire input")]
    MalformedWire,
}

pub type Result<T> = core::result::Result<T, Error>;
