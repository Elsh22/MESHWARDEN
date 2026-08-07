//! MESHWARDEN wire types, framing, and versioning.
//!
//! Depends only on [`mw_crypto`] among `mw-*` crates. Crypto-bearing fields
//! carry [`mw_crypto::AlgId`]; no fixed-size crypto arrays (ADR-007).
//!
//! Payload codec is postcard (ADR-015). Framing is length-delimited with a
//! hand-rolled big-endian header and stays codec-agnostic; payload types
//! expose `to_bytes`/`from_bytes` backed by postcard.

mod alg;
mod error;
mod frame;
mod hello;
mod version;

pub use alg::{alg_from_u16, alg_to_u16};
pub use error::{Error, Result};
pub use frame::{Frame, MessageType, MAX_PAYLOAD_LEN};
pub use hello::Hello;
pub use version::WireVersion;
