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
            tls.get_ref().1.protocol_version(),
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
        tls.get_ref().1.protocol_version(),
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
