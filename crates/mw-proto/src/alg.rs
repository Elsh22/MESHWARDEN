//! Wire `u16` ↔ [`AlgId`] mapping (docs/spec/algorithm-registry.md).

use mw_crypto::AlgId;

use crate::{Error, Result};

/// Maps a wire `u16` algorithm code to [`AlgId`].
///
/// These are free functions rather than `TryFrom<u16> for AlgId` /
/// `From<AlgId> for u16` because Rust's orphan rule forbids implementing a
/// foreign trait (`TryFrom` / `From`) on a foreign type (`AlgId` lives in
/// `mw-crypto`). Unknown codes return [`Error::UnknownAlgorithm`] — registry
/// invariant 3 (reject, never panic).
pub fn alg_from_u16(code: u16) -> Result<AlgId> {
    match code {
        0x0001 => Ok(AlgId::Ed25519),
        0x0002 => Ok(AlgId::X25519),
        0x0010 => Ok(AlgId::Sha256),
        0x0011 => Ok(AlgId::Sha384),
        0x0020 => Ok(AlgId::MlKem768),
        0x0030 => Ok(AlgId::MlDsa87),
        0x0031 => Ok(AlgId::SlhDsa128s),
        other => Err(Error::UnknownAlgorithm(other)),
    }
}

/// Maps [`AlgId`] to its registry wire code (`u16`, big-endian on the wire).
///
/// See [`alg_from_u16`] for why this is a free function rather than `From`.
pub fn alg_to_u16(alg: AlgId) -> u16 {
    alg as u16
}
