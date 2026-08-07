//! Node keystore: owns the node's Ed25519 keypair and derives its identity.

use mw_crypto::ed25519::Keypair;
use mw_crypto::{Signature, Signer};

use crate::NodeId;

/// Wraps a [`Keypair`] (which zeroizes its secret on drop) and exposes the
/// node's identity, public key bytes, and signing via [`Signer`].
pub struct Keystore {
    keypair: Keypair,
}

impl Keystore {
    /// Generates a fresh keystore from the OS entropy source.
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate(),
        }
    }

    /// The node identity derived from this keystore's public key.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_public_key_bytes(&self.keypair.public_key_bytes())
    }

    /// Raw Ed25519 public key bytes, as advertised to peers.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.keypair.public_key_bytes()
    }
}

impl Signer for Keystore {
    fn sign(&self, msg: &[u8]) -> mw_crypto::Result<Signature> {
        self.keypair.sign(msg)
    }
}
