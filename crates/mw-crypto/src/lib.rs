//! MESHWARDEN crypto boundary (ADR-007).
//!
//! This crate is the sole home for primitive crypto crates. Every other
//! crate routes crypto operations through the algorithm-tagged types and
//! traits defined here; none may import `ed25519-dalek`, `sha2`, etc.
//! directly. It depends on no other `mw-*` crate (dependency sink).

pub mod ed25519;

use sha2::Digest as _;

/// Wire-stable algorithm identifier. `u16` on the wire (SCREAMING_SNAKE
/// in the spec, PascalCase here). Reserved variants are defined so wire
/// codes are allocated, but operations on them return [`Error::UnsupportedAlg`].
#[non_exhaustive]
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgId {
    Ed25519 = 0x0001,
    /// Reserved (ADR-006): not implemented in the PoC.
    X25519 = 0x0002,
    Sha256 = 0x0010,
    /// Reserved: not implemented in the PoC.
    Sha384 = 0x0011,
    /// Reserved (ADR-006): benchmarking only, never on a security path.
    MlKem768 = 0x0020,
    /// Reserved: not implemented in the PoC.
    MlDsa87 = 0x0030,
    /// Reserved: not implemented in the PoC.
    SlhDsa128s = 0x0031,
}

impl core::fmt::Display for AlgId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            AlgId::Ed25519 => "ED25519",
            AlgId::X25519 => "X25519",
            AlgId::Sha256 => "SHA256",
            AlgId::Sha384 => "SHA384",
            AlgId::MlKem768 => "ML_KEM_768",
            AlgId::MlDsa87 => "ML_DSA_87",
            AlgId::SlhDsa128s => "SLH_DSA_128S",
        };
        f.write_str(name)
    }
}

/// Algorithm-tagged signature. Variable-length bytes by design (ADR-007):
/// never a fixed-size array in wire or spec types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub alg: AlgId,
    pub bytes: Vec<u8>,
}

/// Algorithm-tagged digest. Variable-length bytes by design (ADR-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    pub alg: AlgId,
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("algorithm {0} is reserved or not implemented")]
    UnsupportedAlg(AlgId),
    #[error("algorithm mismatch: verifier expects {expected}, signature carries {actual}")]
    AlgMismatch { expected: AlgId, actual: AlgId },
    #[error("malformed signature for {alg}: expected {expected_len} bytes, got {actual_len}")]
    MalformedSignature {
        alg: AlgId,
        expected_len: usize,
        actual_len: usize,
    },
    #[error("malformed {alg} public key")]
    MalformedKey { alg: AlgId },
    #[error("signature verification failed")]
    VerificationFailed,
}

pub type Result<T> = core::result::Result<T, Error>;

/// Produces an algorithm-tagged [`Signature`] over a message.
pub trait Signer {
    fn sign(&self, msg: &[u8]) -> Result<Signature>;
}

/// Verifies an algorithm-tagged [`Signature`] over a message.
///
/// Implementations MUST reject a signature whose `alg` does not match the
/// verifier's own algorithm with [`Error::AlgMismatch`] — this is the
/// agility-layer correctness property, not an edge case.
pub trait Verifier {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()>;
}

/// Incremental hasher. Only SHA-256 is implemented in the PoC; reserved
/// hash algorithms return [`Error::UnsupportedAlg`].
#[derive(Debug)]
pub struct Hasher {
    inner: sha2::Sha256,
}

impl Hasher {
    pub fn new(alg: AlgId) -> Result<Self> {
        match alg {
            AlgId::Sha256 => Ok(Self {
                inner: sha2::Sha256::new(),
            }),
            other => Err(Error::UnsupportedAlg(other)),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> Digest {
        Digest {
            alg: AlgId::Sha256,
            bytes: self.inner.finalize().to_vec(),
        }
    }
}


/// One-shot SHA-256 digest, tagged with [`AlgId::Sha256`].
pub fn sha256(data: &[u8]) -> Digest {
    let mut hasher = Hasher::new(AlgId::Sha256).expect("SHA-256 is always available");
    hasher.update(data);
    hasher.finalize()
}
