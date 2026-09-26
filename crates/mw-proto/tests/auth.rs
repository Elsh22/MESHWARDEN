//! Authentication wire message and transcript tests (ADR-017 Slice 3 §9).
//!
//! Ordered by evidential weight: rejection fixtures before round-trips.
//! Hand-built byte fixtures are the source of truth for canonicality.

use mw_crypto::AlgId;
use mw_proto::{
    AUTH_ROLE_CLIENT, AUTH_ROLE_SERVER, AUTH_TRANSCRIPT_DOMAIN_V1, AuthConfirm, AuthInit,
    AuthResponse, AuthTranscriptV1, BoundedBytes, BoundedVec, EXPORTER_LABEL_V1, Error, Hello,
    MAX_AUTH_CONFIRM_BYTES, MAX_AUTH_INIT_BYTES, MAX_AUTH_RESPONSE_BYTES,
    MAX_AUTH_TRANSCRIPT_BYTES, MAX_CERTIFICATE_WIRE_BYTES, MAX_HELLO_ALGS, MAX_PROOF_SIGNATURES,
    MAX_SIGNATURE_BYTES, MessageType, WireSignature,
};

// ---------------------------------------------------------------------------
// Golden vectors (derived once from encoder output; permanently frozen where noted)
// ---------------------------------------------------------------------------

/// Synthetic AuthInit: auth_version=1, nonce=0x11×32, cert=0xAA×4.
const AUTH_INIT_GOLDEN: [u8; 39] = [
    0x01, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x04, 0xaa, 0xaa, 0xaa, 0xaa,
];

/// Synthetic AuthResponse: auth_version=1, nonce=0x22×32, cert=0xCC×4, one Ed25519 sig 0xBB×64.
const AUTH_RESPONSE_GOLDEN: [u8; 106] = [
    0x01, 0x20, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    0x22, 0x22, 0x04, 0xcc, 0xcc, 0xcc, 0xcc, 0x01, 0x01, 0x40, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
];

/// Synthetic AuthConfirm: one Ed25519 sig 0xBB×64.
const AUTH_CONFIRM_GOLDEN: [u8; 67] = [
    0x01, 0x01, 0x40, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb,
];

/// Offset of the certificate length varint in [`AUTH_INIT_GOLDEN`].
const AUTH_INIT_CERT_LEN_OFFSET: usize = 34;

/// Permanently frozen AuthTranscriptV1 golden vector.
///
/// ADR-017: this encoding must never change — a change breaks every deployed
/// signature. Derived once from synthetic field values; do not regenerate.
const AUTH_TRANSCRIPT_GOLDEN: [u8; 207] = [
    0x10, 0x4d, 0x45, 0x53, 0x48, 0x57, 0x41, 0x52, 0x44, 0x45, 0x4e, 0x2d, 0x41, 0x55, 0x54, 0x48,
    0x00, 0x01, 0x01, 0x01, 0x20, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
    0x33, 0x33, 0x33, 0x33, 0x33, 0x22, 0x6d, 0x77, 0x3a, 0x6e, 0x6f, 0x64, 0x65, 0x3a, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x22, 0x6d, 0x77, 0x3a, 0x6e, 0x6f, 0x64, 0x65,
    0x3a, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x20, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x20, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x08, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x08, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
];

fn ed25519_sig(bytes: &[u8]) -> WireSignature {
    WireSignature {
        algorithm: AlgId::Ed25519.as_u16(),
        signature: BoundedBytes::from_slice(bytes).expect("sig within bound"),
    }
}

fn golden_transcript() -> AuthTranscriptV1 {
    AuthTranscriptV1::new(
        AUTH_TRANSCRIPT_DOMAIN_V1.to_vec(),
        1,
        AlgId::Ed25519.as_u16(),
        AUTH_ROLE_CLIENT,
        vec![0x33; 32],
        b"mw:node:AAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        b"mw:node:BBBBBBBBBBBBBBBBBBBBBBBBBB".to_vec(),
        vec![0x44; 32],
        vec![0x55; 32],
        vec![0x66; 8],
        vec![0x77; 8],
    )
    .expect("golden transcript fields")
}

// ---------------------------------------------------------------------------
// §9.1–9.3 — golden vectors
// ---------------------------------------------------------------------------

#[test]
fn auth_transcript_v1_golden_vector_is_permanently_frozen() {
    let bytes = golden_transcript()
        .to_signing_bytes()
        .expect("encode golden transcript");
    assert_eq!(
        bytes.as_slice(),
        &AUTH_TRANSCRIPT_GOLDEN[..],
        "AuthTranscriptV1 golden must never change (breaks deployed signatures)"
    );
    assert_eq!(AUTH_TRANSCRIPT_DOMAIN_V1.len(), 16);
    assert_eq!(AUTH_TRANSCRIPT_DOMAIN_V1, b"MESHWARDEN-AUTH\0");
    assert_eq!(EXPORTER_LABEL_V1, "EXPERIMENTAL-MESHWARDEN-AUTH-v1");
}

#[test]
fn auth_init_golden_vector_is_stable() {
    let msg = AuthInit {
        auth_version: 1,
        client_nonce: BoundedBytes::from_slice(&[0x11; 32]).expect("nonce"),
        client_certificate: BoundedBytes::from_slice(&[0xAA; 4]).expect("cert"),
    };
    let bytes = msg.to_bytes().expect("encode");
    assert_eq!(bytes.as_slice(), &AUTH_INIT_GOLDEN[..]);
}

#[test]
fn auth_response_golden_vector_is_stable() {
    let msg = AuthResponse {
        auth_version: 1,
        server_nonce: BoundedBytes::from_slice(&[0x22; 32]).expect("nonce"),
        server_certificate: BoundedBytes::from_slice(&[0xCC; 4]).expect("cert"),
        signatures: BoundedVec::new(vec![ed25519_sig(&[0xBB; 64])]).expect("sigs"),
    };
    let bytes = msg.to_bytes().expect("encode");
    assert_eq!(bytes.as_slice(), &AUTH_RESPONSE_GOLDEN[..]);
}

#[test]
fn auth_confirm_golden_vector_is_stable() {
    let msg = AuthConfirm {
        signatures: BoundedVec::new(vec![ed25519_sig(&[0xBB; 64])]).expect("sigs"),
    };
    let bytes = msg.to_bytes().expect("encode");
    assert_eq!(bytes.as_slice(), &AUTH_CONFIRM_GOLDEN[..]);
}

#[test]
fn hello_postcard_golden_vector_is_stable() {
    // §9.3 — unmodified Hello golden (also pinned in tests/proto.rs).
    let hello =
        Hello::from_algorithms(&[AlgId::Ed25519, AlgId::X25519, AlgId::Sha256]).expect("in bound");
    let bytes = hello.to_bytes().expect("to_bytes");
    assert_eq!(bytes, [0x03, 0x01, 0x02, 0x10]);
}

// ---------------------------------------------------------------------------
// §9.4–9.7 — canonicality byte fixtures (rejection first)
// ---------------------------------------------------------------------------

#[test]
fn overlong_varint_in_signature_list_count_is_non_canonical() {
    // Encode count 1 as `[0x81, 0x00]` instead of `[0x01]`. Postcard accepts
    // the overlong form on decode; the re-encode comparison must reject it.
    assert_eq!(AUTH_CONFIRM_GOLDEN[0], 0x01);
    let mut overlong = Vec::with_capacity(AUTH_CONFIRM_GOLDEN.len() + 1);
    overlong.extend_from_slice(&[0x81, 0x00]);
    overlong.extend_from_slice(&AUTH_CONFIRM_GOLDEN[1..]);

    let err = AuthConfirm::from_bytes(&overlong)
        .expect_err("overlong signature-count varint must be rejected");
    assert_eq!(
        err,
        Error::NonCanonicalEncoding,
        "expected NonCanonicalEncoding from re-encode comparison, got {err:?}"
    );
}

#[test]
fn overlong_varint_in_bounded_bytes_length_is_non_canonical() {
    // Overlong certificate length in AuthInit: `04` → `84 00`.
    assert_eq!(AUTH_INIT_GOLDEN[AUTH_INIT_CERT_LEN_OFFSET], 0x04);
    let mut overlong = Vec::with_capacity(AUTH_INIT_GOLDEN.len() + 1);
    overlong.extend_from_slice(&AUTH_INIT_GOLDEN[..AUTH_INIT_CERT_LEN_OFFSET]);
    overlong.extend_from_slice(&[0x84, 0x00]);
    overlong.extend_from_slice(&AUTH_INIT_GOLDEN[AUTH_INIT_CERT_LEN_OFFSET + 1..]);

    let err = AuthInit::from_bytes(&overlong)
        .expect_err("overlong certificate-length varint must be rejected");
    assert_eq!(
        err,
        Error::NonCanonicalEncoding,
        "expected NonCanonicalEncoding from re-encode comparison, got {err:?}"
    );
}

#[test]
fn one_trailing_byte_is_trailing_bytes_not_non_canonical() {
    let mut input = AUTH_CONFIRM_GOLDEN.to_vec();
    input.push(0x00);
    let err = AuthConfirm::from_bytes(&input).expect_err("trailing byte must be rejected");
    assert_eq!(
        err,
        Error::TrailingBytes { remaining: 1 },
        "trailing bytes must be distinguishable from NonCanonicalEncoding, got {err:?}"
    );
}

#[test]
fn truncation_at_every_prefix_length_is_rejected_without_panic() {
    for len in 0..AUTH_INIT_GOLDEN.len() {
        assert!(
            AuthInit::from_bytes(&AUTH_INIT_GOLDEN[..len]).is_err(),
            "AuthInit prefix {len} must be rejected"
        );
    }
    for len in 0..AUTH_RESPONSE_GOLDEN.len() {
        assert!(
            AuthResponse::from_bytes(&AUTH_RESPONSE_GOLDEN[..len]).is_err(),
            "AuthResponse prefix {len} must be rejected"
        );
    }
    for len in 0..AUTH_CONFIRM_GOLDEN.len() {
        assert!(
            AuthConfirm::from_bytes(&AUTH_CONFIRM_GOLDEN[..len]).is_err(),
            "AuthConfirm prefix {len} must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// §9.8–9.11 — bounds
// ---------------------------------------------------------------------------

#[test]
fn declared_signature_count_above_max_proof_signatures_is_bound_exceeded() {
    // Declared count 5 (> MAX_PROOF_SIGNATURES=4), with enough trailing bytes
    // that postcard can see the declaration.
    let mut input = vec![0x05u8];
    // One minimal WireSignature stub so the seq visitor can start (alg + empty bytes).
    // Actually for BoundExceeded on declared count we only need the count visible;
    // BoundedVec rejects declared > N before decoding elements when size_hint is set.
    input.extend_from_slice(&[0x01, 0x00]); // alg=1, sig len=0 — may or may not be reached
    let err = AuthConfirm::from_bytes(&input).expect_err("count 5 must fail");
    assert_eq!(
        err,
        Error::BoundExceeded {
            declared: 5,
            max: MAX_PROOF_SIGNATURES
        }
    );
}

#[test]
fn declared_certificate_length_above_max_is_bound_exceeded() {
    // AuthInit: auth_version=1, nonce exact 32, certificate declared 2049 with
    // bytes present. Encode a Vec of that length to obtain the postcard
    // length-prefix + payload, then splice after the nonce.
    let over_len = MAX_CERTIFICATE_WIRE_BYTES + 1;
    let mut input = vec![0x01u8, 0x20];
    input.extend_from_slice(&[0x11; 32]);
    let cert_field = postcard::to_allocvec(&vec![0u8; over_len]).expect("encode over-len bytes");
    input.extend_from_slice(&cert_field);
    let err = AuthInit::from_bytes(&input).expect_err("cert len 2049 must fail");
    assert_eq!(
        err,
        Error::BoundExceeded {
            declared: over_len,
            max: MAX_CERTIFICATE_WIRE_BYTES
        }
    );
}

#[test]
fn input_above_max_auth_bytes_is_message_too_large_before_parsing() {
    let init = vec![0xAAu8; MAX_AUTH_INIT_BYTES + 1];
    assert_eq!(
        AuthInit::from_bytes(&init).expect_err("oversize AuthInit"),
        Error::MessageTooLarge {
            len: MAX_AUTH_INIT_BYTES + 1,
            max: MAX_AUTH_INIT_BYTES
        }
    );

    let resp = vec![0xAAu8; MAX_AUTH_RESPONSE_BYTES + 1];
    assert_eq!(
        AuthResponse::from_bytes(&resp).expect_err("oversize AuthResponse"),
        Error::MessageTooLarge {
            len: MAX_AUTH_RESPONSE_BYTES + 1,
            max: MAX_AUTH_RESPONSE_BYTES
        }
    );

    let confirm = vec![0xAAu8; MAX_AUTH_CONFIRM_BYTES + 1];
    assert_eq!(
        AuthConfirm::from_bytes(&confirm).expect_err("oversize AuthConfirm"),
        Error::MessageTooLarge {
            len: MAX_AUTH_CONFIRM_BYTES + 1,
            max: MAX_AUTH_CONFIRM_BYTES
        }
    );
}

#[test]
fn auth_transcript_worst_case_fits_max_auth_transcript_bytes() {
    let worst = AuthTranscriptV1::new(
        AUTH_TRANSCRIPT_DOMAIN_V1.to_vec(),
        u16::MAX,
        u16::MAX,
        AUTH_ROLE_SERVER,
        vec![0xFF; 32],
        vec![0x41; 34],
        vec![0x42; 34],
        vec![0x43; 32],
        vec![0x44; 32],
        vec![0x45; MAX_CERTIFICATE_WIRE_BYTES],
        vec![0x46; MAX_CERTIFICATE_WIRE_BYTES],
    )
    .expect("worst-case fields must construct");
    let bytes = worst.to_signing_bytes().expect("worst-case must encode");
    eprintln!(
        "AuthTranscriptV1 worst-case encoded size: {} bytes (MAX_AUTH_TRANSCRIPT_BYTES={})",
        bytes.len(),
        MAX_AUTH_TRANSCRIPT_BYTES
    );
    assert!(
        bytes.len() <= MAX_AUTH_TRANSCRIPT_BYTES,
        "worst case {} exceeds {}",
        bytes.len(),
        MAX_AUTH_TRANSCRIPT_BYTES
    );
    // Pin the measured value so silent growth is visible.
    assert_eq!(bytes.len(), 4293);
}

// ---------------------------------------------------------------------------
// §9.12–9.14 — exact-length
// ---------------------------------------------------------------------------

#[test]
fn transcript_exact_length_fields_reject_len_minus_one_and_plus_one() {
    let base = |domain: Vec<u8>,
                channel: Vec<u8>,
                client_node: Vec<u8>,
                server_node: Vec<u8>,
                client_nonce: Vec<u8>,
                server_nonce: Vec<u8>| {
        AuthTranscriptV1::new(
            domain,
            1,
            0x0001,
            AUTH_ROLE_CLIENT,
            channel,
            client_node,
            server_node,
            client_nonce,
            server_nonce,
            vec![0x66; 8],
            vec![0x77; 8],
        )
    };

    let good_domain = AUTH_TRANSCRIPT_DOMAIN_V1.to_vec();
    let good_channel = vec![0x33; 32];
    let good_client_node = b"mw:node:AAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
    let good_server_node = b"mw:node:BBBBBBBBBBBBBBBBBBBBBBBBBB".to_vec();
    let good_client_nonce = vec![0x44; 32];
    let good_server_nonce = vec![0x55; 32];

    // domain: upper bound is 16, so len+1 is BoundExceeded; len-1 is ExactLength.
    assert!(matches!(
        base(
            vec![0x00; 15],
            good_channel.clone(),
            good_client_node.clone(),
            good_server_node.clone(),
            good_client_nonce.clone(),
            good_server_nonce.clone()
        ),
        Err(Error::ExactLength {
            expected: 16,
            actual: 15
        })
    ));
    assert!(matches!(
        base(
            vec![0x00; 17],
            good_channel.clone(),
            good_client_node.clone(),
            good_server_node.clone(),
            good_client_nonce.clone(),
            good_server_nonce.clone()
        ),
        Err(Error::BoundExceeded {
            declared: 17,
            max: 16
        })
    ));

    for (name, channel, client_node, server_node, client_nonce, server_nonce, expected, actual) in [
        (
            "channel-1",
            vec![0x33; 31],
            good_client_node.clone(),
            good_server_node.clone(),
            good_client_nonce.clone(),
            good_server_nonce.clone(),
            32usize,
            31usize,
        ),
        (
            "client_node-1",
            good_channel.clone(),
            vec![0x41; 33],
            good_server_node.clone(),
            good_client_nonce.clone(),
            good_server_nonce.clone(),
            34,
            33,
        ),
        (
            "server_node-1",
            good_channel.clone(),
            good_client_node.clone(),
            vec![0x42; 33],
            good_client_nonce.clone(),
            good_server_nonce.clone(),
            34,
            33,
        ),
        (
            "client_nonce-1",
            good_channel.clone(),
            good_client_node.clone(),
            good_server_node.clone(),
            vec![0x44; 31],
            good_server_nonce.clone(),
            32,
            31,
        ),
        (
            "server_nonce-1",
            good_channel.clone(),
            good_client_node.clone(),
            good_server_node.clone(),
            good_client_nonce.clone(),
            vec![0x55; 31],
            32,
            31,
        ),
    ] {
        let err = base(
            good_domain.clone(),
            channel,
            client_node,
            server_node,
            client_nonce,
            server_nonce,
        )
        .expect_err(name);
        assert_eq!(
            err,
            Error::ExactLength { expected, actual },
            "{name}: {err:?}"
        );
    }

    // +1 within upper bound where possible (channel/nonce/node upper == exact,
    // so +1 is BoundExceeded).
    assert!(matches!(
        base(
            good_domain.clone(),
            vec![0x33; 33],
            good_client_node.clone(),
            good_server_node.clone(),
            good_client_nonce.clone(),
            good_server_nonce.clone()
        ),
        Err(Error::BoundExceeded {
            declared: 33,
            max: 32
        })
    ));
    assert!(matches!(
        base(
            good_domain,
            good_channel,
            vec![0x41; 35],
            good_server_node,
            good_client_nonce,
            good_server_nonce
        ),
        Err(Error::BoundExceeded {
            declared: 35,
            max: 34
        })
    ));
}

#[test]
fn transcript_domain_wrong_bytes_at_correct_length_is_rejected() {
    let mut wrong = AUTH_TRANSCRIPT_DOMAIN_V1.to_vec();
    wrong[0] = b'X';
    let err = AuthTranscriptV1::new(
        wrong,
        1,
        0x0001,
        AUTH_ROLE_CLIENT,
        vec![0x33; 32],
        b"mw:node:AAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
        b"mw:node:BBBBBBBBBBBBBBBBBBBBBBBBBB".to_vec(),
        vec![0x44; 32],
        vec![0x55; 32],
        vec![0x66; 8],
        vec![0x77; 8],
    )
    .expect_err("wrong domain bytes must fail");
    assert_eq!(err, Error::MalformedWire);
}

#[test]
fn transcript_role_accepts_client_and_server_rejects_others() {
    let mk = |role| {
        AuthTranscriptV1::new(
            AUTH_TRANSCRIPT_DOMAIN_V1.to_vec(),
            1,
            0x0001,
            role,
            vec![0x33; 32],
            b"mw:node:AAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec(),
            b"mw:node:BBBBBBBBBBBBBBBBBBBBBBBBBB".to_vec(),
            vec![0x44; 32],
            vec![0x55; 32],
            vec![0x66; 8],
            vec![0x77; 8],
        )
    };
    assert!(mk(AUTH_ROLE_CLIENT).is_ok());
    assert!(mk(AUTH_ROLE_SERVER).is_ok());
    assert_eq!(mk(0x00).expect_err("0x00"), Error::InvalidAuthRole(0x00));
    assert_eq!(mk(0x03).expect_err("0x03"), Error::InvalidAuthRole(0x03));
}

// ---------------------------------------------------------------------------
// §9.15–9.16 — Amendment 1 asymmetry (pair; do not "harmonize")
// ---------------------------------------------------------------------------

/// Acted-upon side of Amendment 1: `WireSignature.algorithm` rejects unknowns.
#[test]
fn unknown_wire_signature_algorithm_is_rejected_with_code() {
    // Pair with `unknown_hello_algorithm_code_is_accepted` — do not harmonize.
    let bytes = AUTH_CONFIRM_GOLDEN.to_vec();
    // algorithm sits at offset 1 (after count 0x01); replace 0x01 with 0xFF 0x01
    // (postcard u16 varint for 0x00FF = 255 → 0xFF 0x01).
    assert_eq!(bytes[1], 0x01);
    let mut forged = Vec::new();
    forged.push(bytes[0]); // count
    forged.extend_from_slice(&[0xFF, 0x01]); // algorithm 0x00FF
    forged.extend_from_slice(&bytes[2..]); // signature length + bytes
    let err = AuthConfirm::from_bytes(&forged).expect_err("unknown alg must fail");
    assert_eq!(err, Error::UnknownAlgorithm(0x00FF));
}

/// Descriptive side of Amendment 1: `Hello.supported_algs` accepts unknowns.
#[test]
fn unknown_hello_algorithm_code_is_accepted() {
    // Pair with `unknown_wire_signature_algorithm_is_rejected_with_code`.
    let hello = Hello::new(vec![0x0001, 0x00FF, 0x0010]).expect("in bound");
    let bytes = hello.to_bytes().expect("encode");
    let decoded = Hello::from_bytes(&bytes).expect("unknown Hello codes must be accepted");
    assert_eq!(decoded.algorithm_codes(), &[0x0001, 0x00FF, 0x0010]);
    assert_eq!(decoded.to_bytes().expect("re-encode"), bytes);
    let known: Vec<AlgId> = decoded.known_algorithms().collect();
    assert_eq!(known, vec![AlgId::Ed25519, AlgId::Sha256]);
}

// ---------------------------------------------------------------------------
// §9.17–9.19 — decoding is not validation; symmetry
// ---------------------------------------------------------------------------

#[test]
fn auth_confirm_empty_signature_list_decodes_successfully() {
    // Arity is slice 4's AuthMachine job — decode must not reject empty lists.
    let msg = AuthConfirm {
        signatures: BoundedVec::new(vec![]).expect("empty"),
    };
    let bytes = msg.to_bytes().expect("encode empty");
    assert_eq!(bytes, [0x00]);
    let decoded = AuthConfirm::from_bytes(&bytes).expect("empty list must decode");
    assert!(decoded.signatures.is_empty());
}

#[test]
fn auth_response_two_signatures_decodes_successfully() {
    // Within MAX_PROOF_SIGNATURES; v1 arity rejection is the machine's job.
    let msg = AuthResponse {
        auth_version: 1,
        server_nonce: BoundedBytes::from_slice(&[0x22; 32]).expect("nonce"),
        server_certificate: BoundedBytes::from_slice(&[0xCC; 4]).expect("cert"),
        signatures: BoundedVec::new(vec![ed25519_sig(&[0xBB; 64]), ed25519_sig(&[0xDD; 64])])
            .expect("two sigs"),
    };
    let bytes = msg.to_bytes().expect("encode");
    let decoded = AuthResponse::from_bytes(&bytes).expect("two-sig response must decode");
    assert_eq!(decoded.signatures.len(), 2);
}

#[test]
fn encode_decode_symmetry_at_bound_edges() {
    // AuthInit with max-size certificate.
    let init = AuthInit {
        auth_version: 1,
        client_nonce: BoundedBytes::from_slice(&[0x11; 32]).expect("nonce"),
        client_certificate: BoundedBytes::from_slice(&[0xAAu8; MAX_CERTIFICATE_WIRE_BYTES])
            .expect("max cert"),
    };
    let bytes = init.to_bytes().expect("encode max AuthInit");
    assert!(bytes.len() <= MAX_AUTH_INIT_BYTES);
    assert_eq!(AuthInit::from_bytes(&bytes).expect("decode"), init);

    // AuthConfirm with MAX_PROOF_SIGNATURES signatures at MAX_SIGNATURE_BYTES.
    let sigs: Vec<WireSignature> = (0..MAX_PROOF_SIGNATURES)
        .map(|i| ed25519_sig(&[i as u8; MAX_SIGNATURE_BYTES]))
        .collect();
    let confirm = AuthConfirm {
        signatures: BoundedVec::new(sigs).expect("at proof bound"),
    };
    let bytes = confirm.to_bytes().expect("encode max AuthConfirm");
    assert!(bytes.len() <= MAX_AUTH_CONFIRM_BYTES);
    assert_eq!(AuthConfirm::from_bytes(&bytes).expect("decode"), confirm);

    // Hello at MAX_HELLO_ALGS.
    let codes: Vec<u16> = (0..MAX_HELLO_ALGS as u16).collect();
    let hello = Hello::new(codes.clone()).expect("at hello bound");
    let bytes = hello.to_bytes().expect("encode");
    let decoded = Hello::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded.algorithm_codes(), codes.as_slice());
}

#[test]
fn hello_bound_plus_one_is_rejected_at_exact_edge() {
    assert_eq!(
        MAX_HELLO_ALGS, 64,
        "fixtures below are written for a bound of 64"
    );

    // Constructor side: 65 codes is one over the bound.
    assert_eq!(
        Hello::new((0..65u16).collect()),
        Err(Error::BoundExceeded {
            declared: 65,
            max: 64
        })
    );

    // Wire form is a bare postcard sequence: count varint, then each code as a
    // varint. Codes 0x00..=0x40 are all single-byte varints.
    let mut at_bound = vec![0x40u8];
    at_bound.extend(0x00u8..=0x3F);
    let mut plus_one = vec![0x41u8];
    plus_one.extend(0x00u8..=0x40);
    assert_eq!(at_bound.len(), 65);
    assert_eq!(plus_one.len(), 66);

    // The encoder produces the hand-written at-bound fixture exactly.
    assert_eq!(
        Hello::new((0..64u16).collect())
            .unwrap()
            .to_bytes()
            .unwrap(),
        at_bound
    );

    // At-bound fixture decodes, so the +1 rejection is the bound check, not malformed input.
    let hello = Hello::from_bytes(&at_bound).expect("64 codes is at the bound");
    assert_eq!(
        hello.algorithm_codes(),
        (0..64u16).collect::<Vec<_>>().as_slice()
    );

    assert_eq!(
        Hello::from_bytes(&plus_one),
        Err(Error::BoundExceeded {
            declared: 65,
            max: 64
        })
    );
}

#[test]
fn message_type_codes_and_from_u16_are_exhaustive() {
    assert_eq!(MessageType::Hello.as_u16(), 0x0001);
    assert_eq!(MessageType::AuthInit.as_u16(), 0x0002);
    assert_eq!(MessageType::AuthResponse.as_u16(), 0x0003);
    assert_eq!(MessageType::AuthConfirm.as_u16(), 0x0004);
    assert_eq!(MessageType::ALL.len(), 4);
    for &mt in MessageType::ALL {
        assert_eq!(MessageType::from_u16(mt.as_u16()), Some(mt));
    }
    assert_eq!(MessageType::from_u16(0x0000), None);
    assert_eq!(MessageType::from_u16(0xFFFF), None);
}

#[test]
fn auth_init_encode_rejects_non_exact_nonce() {
    let msg = AuthInit {
        auth_version: 1,
        client_nonce: BoundedBytes::from_slice(&[0x11; 31]).expect("within upper bound"),
        client_certificate: BoundedBytes::from_slice(&[0xAA; 4]).expect("cert"),
    };
    assert_eq!(
        msg.to_bytes().expect_err("short nonce"),
        Error::ExactLength {
            expected: 32,
            actual: 31
        }
    );
}
