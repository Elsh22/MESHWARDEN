//! Ed25519 signing, the one concrete signature algorithm in the PoC (ADR-005).

use ed25519_dalek::{Signer as _, Verifier as _};
use rand_core::OsRng;

use crate::{AlgId, Error, Result, Signature, Signer, Verifier};

const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

/// Ed25519 keypair. Implements both [`Signer`] and [`Verifier`].
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
        // Agility-layer correctness (ADR-007): a signature tagged with a
        // different algorithm must be rejected before any byte inspection.
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
        self.signing_key
            .verifying_key()
            .verify(msg, &ed25519_dalek::Signature::from_bytes(raw))
            .map_err(|_| Error::VerificationFailed)
    }
}
