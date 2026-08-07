//! MESHWARDEN wire types, framing, and versioning.
//!
//! Depends only on [`mw_crypto`] among `mw-*` crates. Crypto-bearing fields
//! carry [`mw_crypto::AlgId`]; no fixed-size crypto arrays (ADR-007).
//!
//! TODO: choose a concrete payload codec (e.g. CBOR, postcard). Framing is
//! length-delimited and codec-agnostic; `serde` derives are prepared for that
//! choice but no format crate is pulled in yet.

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
