//! Length-delimited frame envelope.

use serde::{Deserialize, Serialize};

use crate::{Error, Result, WireVersion};

/// Maximum accepted payload size (bytes). Larger declarations are rejected
/// with [`Error::PayloadTooLarge`] before allocation.
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Fixed header size: version `u16` + message type `u16` + length `u32`.
const HEADER_LEN: usize = 2 + 2 + 4;

/// Known message-type discriminators (SCREAMING_SNAKE on the wire, PascalCase
/// in Rust). The frame stores the raw `u16` so unknown types can still be
/// framed; interpretation is up to the caller.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    Hello = 0x0001,
}

impl MessageType {
    /// Wire discriminator value.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Length-delimited frame envelope.
///
/// Layout (all multi-byte integers big-endian / network byte order):
///
/// ```text
/// version_major: u16
/// message_type:  u16
/// payload_len:   u32
/// payload:       [u8; payload_len]
/// ```
///
/// No fixed-size crypto arrays (ADR-007). Crypto-bearing fields inside
/// payloads carry [`mw_crypto::AlgId`].
///
/// TODO: choose a concrete payload codec; `payload` remains opaque bytes here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frame {
    pub version: WireVersion,
    /// Message-type discriminator (`u16` on the wire).
    pub message_type: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Builds a frame for a known [`MessageType`].
    pub fn new(version: WireVersion, message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            version,
            message_type: message_type.as_u16(),
            payload,
        }
    }

    /// Encodes this frame to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !self.version.is_supported() {
            return Err(Error::UnsupportedWireVersion(self.version.major));
        }

        let len = self.payload.len();
        if len > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge {
                len,
                max: MAX_PAYLOAD_LEN,
            });
        }
        let len_u32 = u32::try_from(len).map_err(|_| Error::PayloadTooLarge {
            len,
            max: MAX_PAYLOAD_LEN,
        })?;

        let mut out = Vec::with_capacity(HEADER_LEN + len);
        out.extend_from_slice(&self.version.major.to_be_bytes());
        out.extend_from_slice(&self.message_type.to_be_bytes());
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Decodes a single complete frame from `bytes`.
    ///
    /// Rejects truncated/malformed input, unsupported wire majors, and
    /// oversized payloads without panicking.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::MalformedFrame);
        }

        let version = WireVersion {
            major: u16::from_be_bytes([bytes[0], bytes[1]]),
        };
        if !version.is_supported() {
            return Err(Error::UnsupportedWireVersion(version.major));
        }

        let message_type = u16::from_be_bytes([bytes[2], bytes[3]]);
        let payload_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;

        if payload_len > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge {
                len: payload_len,
                max: MAX_PAYLOAD_LEN,
            });
        }

        let total = HEADER_LEN + payload_len;
        if bytes.len() != total {
            return Err(Error::MalformedFrame);
        }

        Ok(Self {
            version,
            message_type,
            payload: bytes[HEADER_LEN..total].to_vec(),
        })
    }
}
