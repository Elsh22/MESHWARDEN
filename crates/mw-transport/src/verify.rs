//! Slice-1 placeholder server-certificate verification.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// **Slice-1 placeholder**: accepts whatever certificate the server
/// presents. It still checks that the handshake signature is valid for that
/// certificate's key (proof of possession), but performs no chain, name, or
/// expiry validation and — critically — no binding of the peer to a mesh
/// identity. Real peer authentication (NodeId/NodeCertificate binding) is
/// ADR-017 / slice 2. A channel verified by this type is confidential
/// against passive observers only; do not make trust decisions on it.
#[derive(Debug)]
pub struct AcceptAnyServerCert {
    algs: WebPkiSupportedAlgorithms,
}

impl AcceptAnyServerCert {
    pub fn new() -> Self {
        crate::install_default_provider();
        let algs = CryptoProvider::get_default()
            .expect("install_default_provider was just called")
            .signature_verification_algorithms;
        Self { algs }
    }
}

impl Default for AcceptAnyServerCert {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Unreachable: configs built by this crate are TLS 1.3-only.
        Err(rustls::Error::General(
            "TLS 1.2 is disabled in this configuration".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
