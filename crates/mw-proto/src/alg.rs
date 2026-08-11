//! Wire `u16` ↔ [`AlgId`] mapping (docs/spec/algorithm-registry.md).

use mw_crypto::AlgId;

use crate::{Error, Result};

/// Maps a wire `u16` algorithm code to [`AlgId`].
///
/// `TryFrom<u16> for AlgId` and `From<AlgId> for u16` exist in `mw-crypto`
/// (since commit `b9c8a2b`). These free functions survive as adapters that
/// map [`mw_crypto::UnknownAlgorithmCode`] into `mw_proto`'s [`Error`]:
/// unknown codes return [`Error::UnknownAlgorithm`] — registry invariant 3
/// (reject, never panic).
pub fn alg_from_u16(code: u16) -> Result<AlgId> {
    AlgId::from_u16(code).map_err(|e| Error::UnknownAlgorithm(e.code))
}

/// Maps [`AlgId`] to its registry wire code (`u16`, big-endian on the wire).
///
/// See [`alg_from_u16`] for why this is a free function rather than `From`.
pub fn alg_to_u16(alg: AlgId) -> u16 {
    alg.as_u16()
}
