use mw_crypto::AlgId;
use mw_proto::{
    alg_from_u16, alg_to_u16, Error, Frame, Hello, MessageType, WireVersion, MAX_PAYLOAD_LEN,
};

const REGISTRY_CODES: &[(u16, AlgId)] = &[
    (0x0001, AlgId::Ed25519),
    (0x0002, AlgId::X25519),
    (0x0010, AlgId::Sha256),
    (0x0011, AlgId::Sha384),
    (0x0020, AlgId::MlKem768),
    (0x0030, AlgId::MlDsa87),
    (0x0031, AlgId::SlhDsa128s),
];

#[test]
fn alg_from_u16_round_trips_every_registry_code() {
    for &(code, alg) in REGISTRY_CODES {
        let decoded = alg_from_u16(code).expect("registry code must decode");
        assert_eq!(decoded, alg);
        assert_eq!(alg_to_u16(decoded), code);
    }
}

#[test]
fn alg_from_u16_rejects_unknown_code() {
    let err = alg_from_u16(0x00FF).expect_err("unknown code must be rejected");
    assert_eq!(err, Error::UnknownAlgorithm(0x00FF));
}

#[test]
fn alg_from_u16_rejects_zero_reserved_invalid() {
    let err = alg_from_u16(0x0000).expect_err("0x0000 is permanently invalid");
    assert_eq!(err, Error::UnknownAlgorithm(0x0000));
}

#[test]
fn frame_encode_decode_round_trip() {
    let frame = Frame::new(
        WireVersion::V1,
        MessageType::Hello,
        b"opaque-payload".to_vec(),
    );
    let bytes = frame.encode().expect("encode must succeed");
    let decoded = Frame::decode(&bytes).expect("decode must succeed");
    assert_eq!(decoded, frame);
}

#[test]
fn truncated_frame_is_rejected_without_panic() {
    let frame = Frame::new(WireVersion::V1, MessageType::Hello, vec![1, 2, 3, 4]);
    let bytes = frame.encode().expect("encode must succeed");

    // Truncate after a partial header / body.
    for n in 0..bytes.len() {
        let err = Frame::decode(&bytes[..n]).expect_err("truncated input must fail");
        assert!(
            matches!(err, Error::MalformedFrame),
            "expected MalformedFrame at truncate {n}, got {err:?}"
        );
    }
}

#[test]
fn unknown_wire_version_is_rejected() {
    let mut bytes = Frame::new(WireVersion::V1, MessageType::Hello, b"x".to_vec())
        .encode()
        .expect("encode");
    // Overwrite major with an unsupported value.
    bytes[0..2].copy_from_slice(&99u16.to_be_bytes());

    let err = Frame::decode(&bytes).expect_err("unsupported major must fail");
    assert_eq!(err, Error::UnsupportedWireVersion(99));
}

#[test]
fn encode_rejects_unsupported_wire_version() {
    let frame = Frame {
        version: WireVersion { major: 99 },
        message_type: MessageType::Hello.as_u16(),
        payload: b"x".to_vec(),
    };
    let err = frame.encode().expect_err("unsupported major must fail on encode");
    assert_eq!(err, Error::UnsupportedWireVersion(99));
}

#[test]
fn oversized_payload_declaration_is_rejected() {
    let mut header = Vec::new();
    header.extend_from_slice(&WireVersion::V1.major.to_be_bytes());
    header.extend_from_slice(&MessageType::Hello.as_u16().to_be_bytes());
    let too_big = (MAX_PAYLOAD_LEN as u32).saturating_add(1);
    header.extend_from_slice(&too_big.to_be_bytes());

    let err = Frame::decode(&header).expect_err("oversized length must fail");
    assert!(matches!(
        err,
        Error::PayloadTooLarge {
            len,
            max: MAX_PAYLOAD_LEN
        } if len == MAX_PAYLOAD_LEN + 1
    ));
}

#[test]
fn hello_shape_carries_alg_ids() {
    let hello = Hello {
        supported_algs: vec![AlgId::Ed25519, AlgId::Sha256],
    };
    assert_eq!(hello.supported_algs.len(), 2);
    assert_eq!(alg_to_u16(hello.supported_algs[0]), 0x0001);
}
