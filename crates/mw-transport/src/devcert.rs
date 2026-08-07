//! Slice-1 throwaway self-signed server certificate.
//!
//! The TLS server must present *some* certificate; in this slice it is a
//! fresh, self-signed ECDSA P-256 certificate with no relation to any mesh
//! identity — deliberately NOT an Ed25519 identity key. Binding the channel
//! to a `NodeId`/`NodeCertificate` is ADR-017 / slice 2, at which point this
//! module disappears.
//!
//! rcgen's built-in signing backends are `ring`/`aws-lc-rs`, both C-backed
//! and excluded by ADR-016, so the certificate is signed through rcgen's
//! [`SigningKey`] extension point with a RustCrypto `p256` key — the same
//! primitives the TLS provider already carries. P-256 stays out of
//! `mw-crypto` (ADR-007) because it is not a mesh algorithm; it exists only
//! to satisfy the TLS server-certificate requirement in this slice.

use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::EncodePrivateKey as _;
use rcgen::{
    CertificateParams, PKCS_ECDSA_P256_SHA256, PublicKeyData, SerialNumber, SignatureAlgorithm,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{Error, Result};

/// RustCrypto-backed ECDSA P-256 signer plugged into rcgen.
struct P256Signer {
    key: p256::ecdsa::SigningKey,
    /// Uncompressed SEC1 point — the `subjectPublicKey` BIT STRING contents.
    public_key_sec1: Vec<u8>,
}

impl PublicKeyData for P256Signer {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key_sec1
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for P256Signer {
    fn sign(&self, msg: &[u8]) -> core::result::Result<Vec<u8>, rcgen::Error> {
        let sig: p256::ecdsa::Signature = self.key.sign(msg);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// Generates a fresh self-signed certificate for `localhost` and its
/// PKCS#8 private key, ready for [`crate::server_config`].
pub fn generate() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let devcert_err = |e: &dyn core::fmt::Display| Error::DevCert(e.to_string());

    let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let signer = P256Signer {
        public_key_sec1: key.verifying_key().to_encoded_point(false).as_bytes().to_vec(),
        key: key.clone(),
    };

    let mut params =
        CertificateParams::new(vec!["localhost".to_owned()]).map_err(|e| devcert_err(&e))?;
    // Without a built-in backend rcgen cannot derive a serial number itself;
    // uniqueness is irrelevant for a throwaway cert.
    params.serial_number = Some(SerialNumber::from(1u64));
    let cert = params.self_signed(&signer).map_err(|e| devcert_err(&e))?;

    let key_pkcs8 = key.to_pkcs8_der().map_err(|e| devcert_err(&e))?;
    let key_der = PrivatePkcs8KeyDer::from(key_pkcs8.as_bytes().to_vec());
    Ok((cert.der().clone(), key_der.into()))
}
