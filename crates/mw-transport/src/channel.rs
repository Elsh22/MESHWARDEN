//! TLS 1.3 session establishment and `mw-proto` framing over the stream.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use mw_proto::Frame;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::verify::AcceptAnyServerCert;
use crate::{Error, Result, install_default_provider};

/// Marker wrapper for a slice-1 TLS stream: the channel inside is
/// confidential against passive observers but **NOT mesh-authenticated** —
/// the peer has not been bound to any `NodeId`/`NodeCertificate` (that is
/// ADR-017 / slice 2). Every stream produced by [`connect`] and [`accept`]
/// is wrapped in this type so no caller can mistake it for an authenticated
/// channel. **Nothing may make trust decisions on it.**
#[derive(Debug)]
pub struct Unauthenticated<S>(S);

impl<S> Unauthenticated<S> {
    /// The wrapped stream (e.g. to inspect the negotiated TLS parameters).
    pub fn get_ref(&self) -> &S {
        &self.0
    }

    /// Unwraps the stream. The unauthenticated caveat still applies to
    /// whatever the caller does with it.
    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Unauthenticated<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Unauthenticated<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

/// TLS 1.3-only client configuration using the process-default provider
/// (ADR-016) and the slice-1 placeholder verifier ([`AcceptAnyServerCert`]):
/// the resulting channel is confidential but not authenticated (ADR-017).
pub fn client_config() -> ClientConfig {
    install_default_provider();
    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::new()))
        .with_no_client_auth()
}

/// TLS 1.3-only server configuration using the process-default provider
/// (ADR-016), presenting `cert`/`key` (slice 1: a [`crate::devcert`]
/// throwaway). No client authentication is requested — that is ADR-017.
pub fn server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    install_default_provider();
    Ok(
        ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?,
    )
}

/// Runs the client side of the TLS handshake over any async byte stream
/// (e.g. one end of `tokio::io::duplex`). The result is deliberately
/// [`Unauthenticated`]: slice 1 binds no peer identity.
pub async fn connect<S>(
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    io: S,
) -> Result<Unauthenticated<tokio_rustls::client::TlsStream<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    TlsConnector::from(config)
        .connect(server_name, io)
        .await
        .map(Unauthenticated)
        .map_err(Error::Handshake)
}

/// Runs the server side of the TLS handshake over any async byte stream.
/// The result is deliberately [`Unauthenticated`]: slice 1 binds no peer
/// identity.
pub async fn accept<S>(
    config: Arc<ServerConfig>,
    io: S,
) -> Result<Unauthenticated<tokio_rustls::server::TlsStream<S>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    TlsAcceptor::from(config)
        .accept(io)
        .await
        .map(Unauthenticated)
        .map_err(Error::Handshake)
}

/// [`Frame`] transport over an established stream: length-delimited frames
/// (`mw-proto`) written whole and reassembled on read with a
/// [`Frame::decode_prefix`] buffering loop.
pub struct FramedChannel<S> {
    stream: S,
    read_buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> FramedChannel<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: Vec::new(),
        }
    }

    /// Encodes and writes one frame.
    pub async fn send(&mut self, frame: &Frame) -> Result<()> {
        let bytes = frame.encode()?;
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Reads until one complete frame is buffered and returns it, leaving
    /// any trailing bytes buffered for the next call. A stream that closes
    /// mid-frame (or before one) surfaces as an `UnexpectedEof` I/O error.
    pub async fn recv(&mut self) -> Result<Frame> {
        loop {
            if let Some((frame, consumed)) = Frame::decode_prefix(&self.read_buf)? {
                self.read_buf.drain(..consumed);
                return Ok(frame);
            }
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Consumes the channel, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}
