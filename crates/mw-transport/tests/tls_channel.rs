use std::sync::Arc;

use mw_proto::{Frame, Hello, MessageType, WireVersion, alg_from_u16};
use mw_transport::{FramedChannel, accept, client_config, connect, server_config};
use rustls::pki_types::ServerName;

/// Full slice-1 round trip: TLS 1.3 handshake over an in-process duplex
/// (pure-Rust provider, ADR-016), then one Hello frame sent client→server
/// decodes equal on the other side. Deterministic: both sides are driven by
/// the same runtime with no timers.
#[tokio::test]
async fn tls13_hello_frame_round_trips_over_duplex() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let (cert, key) = mw_transport::devcert::generate().expect("throwaway cert generates");
    let server_cfg = Arc::new(server_config(cert, key).expect("server config builds"));
    let client_cfg = Arc::new(client_config());

    let server = tokio::spawn(async move {
        let tls = accept(server_cfg, server_io).await?;
        assert_eq!(
            tls.get_ref().get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "server negotiated something other than TLS 1.3"
        );
        let mut channel = FramedChannel::new(tls);
        channel.recv().await
    });

    let server_name = ServerName::try_from("localhost").expect("valid name");
    let tls = connect(client_cfg, server_name, client_io)
        .await
        .expect("client handshake completes");
    assert_eq!(
        tls.get_ref().get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "client negotiated something other than TLS 1.3"
    );

    // AlgIds via the registry codes: this crate doesn't depend on mw-crypto
    // in slice 1, so the wire mapping in mw-proto is the way in.
    let hello = Hello {
        supported_algs: vec![
            alg_from_u16(0x0001).expect("ED25519 is registered"),
            alg_from_u16(0x0010).expect("SHA256 is registered"),
        ],
    };
    let sent = Frame::new(
        WireVersion::V1,
        MessageType::Hello,
        hello.to_bytes().expect("hello encodes"),
    );

    let mut channel = FramedChannel::new(tls);
    channel.send(&sent).await.expect("frame sends");

    let received = server
        .await
        .expect("server task completes")
        .expect("server receives a frame");
    assert_eq!(received, sent, "frame must round-trip byte-identically");

    let received_hello = Hello::from_bytes(&received.payload).expect("payload decodes");
    assert_eq!(received_hello, hello, "Hello must round-trip");
}

/// The `decode_prefix` buffering loop must reassemble frames from arbitrary
/// chunk boundaries: two back-to-back frames are written in 3-byte slices
/// (splitting both headers and payloads) and must decode intact and in
/// order. Runs over a bare duplex — the framing layer is stream-agnostic,
/// so TLS is not needed to exercise it.
#[tokio::test]
async fn buffered_decode_reassembles_split_frames() {
    // Capacity 3 caps every read at 3 bytes, so `recv` is forced through the
    // partial-header and partial-payload paths of the decode_prefix loop.
    let (mut writer, reader) = tokio::io::duplex(3);

    let frame_a = Frame::new(WireVersion::V1, MessageType::Hello, vec![0xAA; 5]);
    let frame_b = Frame::new(WireVersion::V1, MessageType::Hello, vec![0xBB; 19]);
    let mut bytes = frame_a.encode().expect("frame encodes");
    bytes.extend_from_slice(&frame_b.encode().expect("frame encodes"));

    let writer_task = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt as _;
        for chunk in bytes.chunks(3) {
            writer.write_all(chunk).await.expect("chunk writes");
            writer.flush().await.expect("chunk flushes");
        }
        writer // keep the write side open until both frames are read
    });

    let mut channel = FramedChannel::new(reader);
    let got_a = channel.recv().await.expect("first frame decodes");
    let got_b = channel.recv().await.expect("second frame decodes");
    assert_eq!(got_a, frame_a, "first frame must survive 3-byte chunking");
    assert_eq!(got_b, frame_b, "second frame must survive 3-byte chunking");

    drop(writer_task.await.expect("writer task completes"));
}

/// ADR-016: the process-default rustls provider must be `rustls-rustcrypto`.
/// `CryptoProvider` has no identity accessor, so compare the cipher-suite
/// set — the pure-Rust provider's suite list differs from every C-backed
/// built-in, so equality pins the provider.
#[test]
fn installed_provider_is_rustls_rustcrypto() {
    mw_transport::install_default_provider();
    let installed = rustls::crypto::CryptoProvider::get_default()
        .expect("install_default_provider installed one");

    let expected = rustls_rustcrypto::provider();
    let installed_suites: Vec<_> = installed.cipher_suites.iter().map(|s| s.suite()).collect();
    let expected_suites: Vec<_> = expected.cipher_suites.iter().map(|s| s.suite()).collect();
    assert_eq!(
        installed_suites, expected_suites,
        "installed provider's cipher suites are not rustls-rustcrypto's"
    );

    let installed_groups: Vec<_> = installed.kx_groups.iter().map(|g| g.name()).collect();
    let expected_groups: Vec<_> = expected.kx_groups.iter().map(|g| g.name()).collect();
    assert_eq!(
        installed_groups, expected_groups,
        "installed provider's key-exchange groups are not rustls-rustcrypto's"
    );
}
