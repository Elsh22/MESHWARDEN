//! Ed25519 signing and verification, the one concrete signature algorithm
//! in the PoC (ADR-005).

use ed25519_dalek::{Signer as _, Verifier as _};
use rand_core::OsRng;

use crate::{AlgId, Error, Result, Signature, Signer, Verifier};

const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;
const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// Ed25519 keypair (holds secret material). Implements both [`Signer`] and
/// [`Verifier`]. Secret bytes are zeroized on drop via ed25519-dalek's
/// `zeroize` feature.
pub struct Keypair {
    signing_key: ed25519_dalek::SigningKey,
}

impl Keypair {
    /// Generates a fresh keypair from the OS entropy source.
    pub fn generate() -> Self {
        Self {
            signing_key: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    /// Raw public key bytes, e.g. for deriving the `mw:node:<...>` identity.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// The public half of this keypair as a standalone [`PublicKey`] — the
    /// verifier a peer reconstructs from bytes received over the wire.
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }
}

impl Signer for Keypair {
    fn sign(&self, msg: &[u8]) -> Result<Signature> {
        Ok(Signature {
            alg: AlgId::Ed25519,
            bytes: self.signing_key.sign(msg).to_vec(),
        })
    }
}

impl Verifier for Keypair {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        verify_ed25519(&self.signing_key.verifying_key(), msg, sig)
    }
}

/// Ed25519 public key with no secret material, reconstructed from a peer's
/// raw key bytes. Implements [`Verifier`]. This is the verification path used
/// in practice: you verify a peer's signature against *their* public key, not
/// by holding their [`Keypair`].
#[derive(Debug, Clone)]
pub struct PublicKey {
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl PublicKey {
    /// Reconstructs a public key from its raw bytes. Rejects wrong-length
    /// input and byte strings that are not valid Ed25519 points, without
    /// panicking.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw: &[u8; PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::MalformedKey { alg: AlgId::Ed25519 })?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(raw)
            .map_err(|_| Error::MalformedKey { alg: AlgId::Ed25519 })?;
        Ok(Self { verifying_key })
    }

    /// Raw public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }
}

impl Verifier for PublicKey {
    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        verify_ed25519(&self.verifying_key, msg, sig)
    }
}

/// Shared verification path for [`Keypair`] and [`PublicKey`]. Rejects an
/// algorithm-mismatched signature before inspecting any bytes (ADR-007).
fn verify_ed25519(
    verifying_key: &ed25519_dalek::VerifyingKey,
    msg: &[u8],
    sig: &Signature,
) -> Result<()> {
    if sig.alg != AlgId::Ed25519 {
        return Err(Error::AlgMismatch {
            expected: AlgId::Ed25519,
            actual: sig.alg,
        });
    }
    let raw: &[u8; SIGNATURE_LEN] =
        sig.bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedSignature {
                alg: AlgId::Ed25519,
                expected_len: SIGNATURE_LEN,
                actual_len: sig.bytes.len(),
            })?;
    verifying_key
        .verify(msg, &ed25519_dalek::Signature::from_bytes(raw))
        .map_err(|_| Error::VerificationFailed)
}