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
fn decode_prefix_leaves_trailing_bytes_and_recovers_next_frame() {
    let first = Frame::new(WireVersion::V1, MessageType::Hello, b"first".to_vec());
    let second = Frame::new(WireVersion::V1, MessageType::Hello, b"second-payload".to_vec());

    let frame_bytes = first.encode().expect("encode first");
    let mut buf = frame_bytes.clone();
    buf.extend_from_slice(&second.encode().expect("encode second"));

    let (decoded, consumed) = Frame::decode_prefix(&buf)
        .expect("prefix decode must succeed")
        .expect("complete frame must be present");
    assert_eq!(decoded, first);
    assert_eq!(consumed, frame_bytes.len());

    let (decoded_next, consumed_next) = Frame::decode_prefix(&buf[consumed..])
        .expect("second prefix decode must succeed")
        .expect("second frame must be present");
    assert_eq!(decoded_next, second);
    assert_eq!(consumed + consumed_next, buf.len());
}

#[test]
fn decode_prefix_returns_none_on_partial_header() {
    let bytes = Frame::new(WireVersion::V1, MessageType::Hello, b"abc".to_vec())
        .encode()
        .expect("encode");
    // Every prefix shorter than the 8-byte header is "need more data".
    for n in 0..8 {
        let out = Frame::decode_prefix(&bytes[..n]).expect("partial header must not error");
        assert!(out.is_none(), "expected None at len {n}");
    }
}

#[test]
fn decode_prefix_returns_none_on_partial_payload() {
    let bytes = Frame::new(WireVersion::V1, MessageType::Hello, vec![1, 2, 3, 4])
        .encode()
        .expect("encode");
    // Full header present, payload incomplete.
    for n in 8..bytes.len() {
        let out = Frame::decode_prefix(&bytes[..n]).expect("partial payload must not error");
        assert!(out.is_none(), "expected None at len {n}");
    }
}

#[test]
fn decode_prefix_rejects_oversized_declaration_before_buffering() {
    let mut header = Vec::new();
    header.extend_from_slice(&WireVersion::V1.major.to_be_bytes());
    header.extend_from_slice(&MessageType::Hello.as_u16().to_be_bytes());
    let too_big = (MAX_PAYLOAD_LEN as u32).saturating_add(1);
    header.extend_from_slice(&too_big.to_be_bytes());

    // Buffer is truncated (no payload bytes at all), yet the bogus length is
    // rejected immediately instead of waiting for more input.
    let err = Frame::decode_prefix(&header).expect_err("oversized length must fail");
    assert!(matches!(
        err,
        Error::PayloadTooLarge {
            len,
            max: MAX_PAYLOAD_LEN
        } if len == MAX_PAYLOAD_LEN + 1
    ));
}

#[test]
fn hello_postcard_round_trip() {
    let hello = Hello {
        supported_algs: vec![AlgId::Ed25519, AlgId::X25519, AlgId::Sha256],
    };
    let bytes = hello.to_bytes().expect("to_bytes must succeed");
    let decoded = Hello::from_bytes(&bytes).expect("from_bytes must succeed");
    assert_eq!(decoded, hello);
}

#[test]
fn hello_from_bytes_rejects_garbage_without_panic() {
    let garbage: &[u8] = &[0xFF, 0xFE, 0xFD, 0xFC, 0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x00];
    let err = Hello::from_bytes(garbage).expect_err("garbage must be rejected");
    assert_eq!(err, Error::MalformedPayload);
}

#[test]
fn hello_shape_carries_alg_ids() {
    let hello = Hello {
        supported_algs: vec![AlgId::Ed25519, AlgId::Sha256],
    };
    assert_eq!(hello.supported_algs.len(), 2);
    assert_eq!(alg_to_u16(hello.supported_algs[0]), 0x0001);
}
