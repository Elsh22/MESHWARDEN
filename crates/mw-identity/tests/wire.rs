//! Certificate wire representation tests (ADR-017 §*Certificate representations*).
//!
//! Evidential weight lives in the **hand-constructed byte fixtures** whose
//! expected outcome is rejection. Round-tripping a Rust value proves almost
//! nothing about the canonicality check: encoder and decoder can share a bug.
//!
//! Deliberately **absent** (ADR-017 Correction C / §*Certificate representations*
//! prefix-observation note): a test that `certificate_signing_bytes` is a byte
//! prefix of `certificate_wire_bytes`. That relationship is an encoding
//! observation, not a contract; pinning it would convert a coincidence into a
//! contract and would fail on a future field addition for no security reason.

use mw_crypto::ed25519::PublicKey;
use mw_crypto::{AlgId, Signature};
use mw_identity::{
    CertificateFields, Error, Keystore, MAX_CERT_LIFETIME_SECS, NodeCertificate, NodeId,
};
use mw_proto::{
    MAX_CERT_CAPABILITIES, MAX_CERTIFICATE_WIRE_BYTES, MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES,
};
use serde::Serialize;

/// Wire golden vector: complete certificate bytes, derived once from
/// `NodeCertificate::to_wire_bytes` for the fixed synthetic fields below
/// (subject/issuer keys `[0x11; 32]` / `[0x22; 32]`, capabilities Ed25519+Sha256,
/// window 1000..2000, stub signature `0xAB`×64, alg Ed25519), then pasted as a
/// literal. Regenerating at test time would prove nothing.
const WIRE_GOLDEN_HEX: &str = "\
226d773a6e6f64653a414c4b4554495937584d54485a445a5646324d57524a34364859\
201111111111111111111111111111111111111111111111111111111111111111\
020110e807d00f\
226d773a6e6f64653a54355a4f554448555355334f4852544d5042375841554d473334\
0140\
abababababababababababababababababababababababababababababababab\
abababababababababababababababababababababababababababababababab";

const WIRE_GOLDEN_LEN: usize = 176;

/// Offset of the capabilities-count varint in [`WIRE_GOLDEN_HEX`].
const GOLDEN_CAP_COUNT_OFFSET: usize = 68;

/// Offset of the `valid_from` varint in [`WIRE_GOLDEN_HEX`].
const GOLDEN_VALID_FROM_OFFSET: usize = 71;

fn wire_golden_bytes() -> Vec<u8> {
    (0..WIRE_GOLDEN_HEX.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&WIRE_GOLDEN_HEX[i..i + 2], 16).expect("hex"))
        .collect()
}

fn golden_fields() -> (NodeId, Vec<u8>, NodeId) {
    let subject_pk = vec![0x11u8; 32];
    let issuer_pk = vec![0x22u8; 32];
    (
        NodeId::from_public_key_bytes(&subject_pk),
        subject_pk,
        NodeId::from_public_key_bytes(&issuer_pk),
    )
}

fn golden_certificate() -> NodeCertificate {
    let (subject, public_key, issuer) = golden_fields();
    NodeCertificate {
        subject,
        public_key,
        capabilities: vec![AlgId::Ed25519.as_u16(), AlgId::Sha256.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer,
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0xABu8; 64],
        },
    }
}

/// Twin of the private signing form, for comparing canonical signing bytes.
#[derive(Serialize)]
struct SigningForm<'a> {
    subject: &'a NodeId,
    public_key: &'a [u8],
    capabilities: Vec<u16>,
    valid_from: u64,
    valid_until: u64,
    issuer: &'a NodeId,
}

fn signing_bytes(cert: &NodeCertificate) -> Vec<u8> {
    postcard::to_allocvec(&SigningForm {
        subject: &cert.subject,
        public_key: &cert.public_key,
        capabilities: cert.capabilities.clone(),
        valid_from: cert.valid_from,
        valid_until: cert.valid_until,
        issuer: &cert.issuer,
    })
    .expect("signing form encodes")
}

fn verifier_of(keystore: &Keystore) -> PublicKey {
    PublicKey::from_bytes(&keystore.public_key_bytes()).expect("keystore key")
}

// ---------------------------------------------------------------------------
// §7.2–7.5 — rejection fixtures (bytes are the source of truth)
// ---------------------------------------------------------------------------

#[test]
fn overlong_varint_in_capability_count_is_non_canonical() {
    // Encode count 2 as `[0x82, 0x00]` instead of `[0x02]`. Postcard accepts
    // the overlong form on decode; the re-encode comparison must reject it.
    // If this test ever fails by accepting the bytes, the canonicality check
    // is not working. If it fails with a different error, the check may be
    // untested rather than working.
    let golden = wire_golden_bytes();
    assert_eq!(golden[GOLDEN_CAP_COUNT_OFFSET], 0x02);
    let mut overlong = Vec::with_capacity(golden.len() + 1);
    overlong.extend_from_slice(&golden[..GOLDEN_CAP_COUNT_OFFSET]);
    overlong.extend_from_slice(&[0x82, 0x00]);
    overlong.extend_from_slice(&golden[GOLDEN_CAP_COUNT_OFFSET + 1..]);

    let err = NodeCertificate::from_wire_bytes(&overlong)
        .expect_err("overlong capability-count varint must be rejected");
    assert!(
        matches!(err, Error::NonCanonicalEncoding),
        "expected NonCanonicalEncoding from re-encode comparison, got {err:?}"
    );
}

#[test]
fn overlong_varint_in_timestamp_is_non_canonical() {
    // Second, structurally different canonicality vector: overlong `valid_from`.
    let golden = wire_golden_bytes();
    assert_eq!(
        &golden[GOLDEN_VALID_FROM_OFFSET..GOLDEN_VALID_FROM_OFFSET + 2],
        &[0xe8, 0x07]
    );
    let mut overlong = Vec::with_capacity(golden.len() + 1);
    overlong.extend_from_slice(&golden[..GOLDEN_VALID_FROM_OFFSET]);
    overlong.extend_from_slice(&[0xe8, 0x87, 0x00]);
    overlong.extend_from_slice(&golden[GOLDEN_VALID_FROM_OFFSET + 2..]);

    let err = NodeCertificate::from_wire_bytes(&overlong)
        .expect_err("overlong timestamp varint must be rejected");
    assert!(
        matches!(err, Error::NonCanonicalEncoding),
        "expected NonCanonicalEncoding from re-encode comparison, got {err:?}"
    );
}

#[test]
fn one_trailing_byte_is_trailing_bytes_not_non_canonical() {
    let mut input = wire_golden_bytes();
    input.push(0x00);
    let err = NodeCertificate::from_wire_bytes(&input).expect_err("trailing byte must be rejected");
    assert!(
        matches!(
            err,
            Error::Wire(mw_proto::Error::TrailingBytes { remaining: 1 })
        ),
        "trailing bytes must be distinguishable from NonCanonicalEncoding, got {err:?}"
    );
}

#[test]
fn truncation_at_every_prefix_length_is_rejected_without_panic() {
    let golden = wire_golden_bytes();
    for len in 0..golden.len() {
        let result = NodeCertificate::from_wire_bytes(&golden[..len]);
        assert!(
            result.is_err(),
            "prefix length {len} must be rejected, got {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// §7.1 — wire golden vector (after the rejection fixtures above)
// ---------------------------------------------------------------------------

#[test]
fn wire_golden_vector_decodes_and_reencodes_identically() {
    let bytes = wire_golden_bytes();
    assert_eq!(bytes.len(), WIRE_GOLDEN_LEN);

    let cert = NodeCertificate::from_wire_bytes(&bytes).expect("golden must decode");
    let (subject, public_key, issuer) = golden_fields();
    assert_eq!(cert.subject, subject);
    assert_eq!(cert.public_key, public_key);
    assert_eq!(
        cert.capabilities,
        vec![AlgId::Ed25519.as_u16(), AlgId::Sha256.as_u16()]
    );
    assert_eq!(cert.valid_from, 1_000);
    assert_eq!(cert.valid_until, 2_000);
    assert_eq!(cert.issuer, issuer);
    assert_eq!(cert.signature.alg, AlgId::Ed25519);
    assert_eq!(cert.signature.bytes, vec![0xABu8; 64]);

    let reencoded = golden_certificate()
        .to_wire_bytes()
        .expect("golden fields must encode");
    assert_eq!(
        reencoded, bytes,
        "encode of golden fields must match fixture"
    );
    assert_eq!(reencoded.len(), WIRE_GOLDEN_LEN);
}

// ---------------------------------------------------------------------------
// §7.6–7.10 — bounds
// ---------------------------------------------------------------------------

#[test]
fn declared_capability_count_one_over_max_with_bytes_present_is_bound_exceeded() {
    // Build a structurally complete certificate whose capability count is 65,
    // with all 65 element bytes present, then decode.
    let (subject, public_key, issuer) = golden_fields();
    let mut caps = vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES];
    caps.push(AlgId::Sha256.as_u16());
    assert_eq!(caps.len(), MAX_CERT_CAPABILITIES + 1);

    #[derive(Serialize)]
    struct Encode<'a> {
        subject: &'a NodeId,
        public_key: &'a [u8],
        capabilities: &'a [u16],
        valid_from: u64,
        valid_until: u64,
        issuer: &'a NodeId,
        signature_algorithm: u16,
        signature: &'a [u8],
    }
    let bytes = postcard::to_allocvec(&Encode {
        subject: &subject,
        public_key: &public_key,
        capabilities: &caps,
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: &issuer,
        signature_algorithm: AlgId::Ed25519.as_u16(),
        signature: &[0xABu8; 64],
    })
    .expect("encodes");
    assert!(bytes.len() <= MAX_CERTIFICATE_WIRE_BYTES);

    let err = NodeCertificate::from_wire_bytes(&bytes).expect_err("65 caps must fail");
    assert!(
        matches!(
            err,
            Error::Wire(mw_proto::Error::BoundExceeded {
                declared: d,
                max: MAX_CERT_CAPABILITIES
            }) if d == MAX_CERT_CAPABILITIES + 1
        ),
        "expected wrapped BoundExceeded, got {err:?}"
    );
}

#[test]
fn declared_public_key_length_above_max_with_bytes_present_is_bound_exceeded() {
    let (subject, _, issuer) = golden_fields();
    let oversized = vec![0x11u8; MAX_PUBLIC_KEY_BYTES + 1];

    #[derive(Serialize)]
    struct Encode<'a> {
        subject: &'a NodeId,
        public_key: &'a [u8],
        capabilities: &'a [u16],
        valid_from: u64,
        valid_until: u64,
        issuer: &'a NodeId,
        signature_algorithm: u16,
        signature: &'a [u8],
    }
    let bytes = postcard::to_allocvec(&Encode {
        subject: &subject,
        public_key: &oversized,
        capabilities: &[AlgId::Ed25519.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: &issuer,
        signature_algorithm: AlgId::Ed25519.as_u16(),
        signature: &[0xABu8; 64],
    })
    .expect("encodes");
    assert!(bytes.len() <= MAX_CERTIFICATE_WIRE_BYTES);

    let err = NodeCertificate::from_wire_bytes(&bytes).expect_err("oversize pk must fail");
    assert!(
        matches!(
            err,
            Error::Wire(mw_proto::Error::BoundExceeded {
                declared: d,
                max: MAX_PUBLIC_KEY_BYTES
            }) if d == MAX_PUBLIC_KEY_BYTES + 1
        ),
        "expected wrapped BoundExceeded, got {err:?}"
    );
}

#[test]
fn declared_signature_length_above_max_with_bytes_present_is_bound_exceeded() {
    let (subject, public_key, issuer) = golden_fields();
    let oversized = vec![0xABu8; MAX_SIGNATURE_BYTES + 1];

    #[derive(Serialize)]
    struct Encode<'a> {
        subject: &'a NodeId,
        public_key: &'a [u8],
        capabilities: &'a [u16],
        valid_from: u64,
        valid_until: u64,
        issuer: &'a NodeId,
        signature_algorithm: u16,
        signature: &'a [u8],
    }
    let bytes = postcard::to_allocvec(&Encode {
        subject: &subject,
        public_key: &public_key,
        capabilities: &[AlgId::Ed25519.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: &issuer,
        signature_algorithm: AlgId::Ed25519.as_u16(),
        signature: &oversized,
    })
    .expect("encodes");
    assert!(bytes.len() <= MAX_CERTIFICATE_WIRE_BYTES);

    let err = NodeCertificate::from_wire_bytes(&bytes).expect_err("oversize sig must fail");
    assert!(
        matches!(
            err,
            Error::Wire(mw_proto::Error::BoundExceeded {
                declared: d,
                max: MAX_SIGNATURE_BYTES
            }) if d == MAX_SIGNATURE_BYTES + 1
        ),
        "expected wrapped BoundExceeded, got {err:?}"
    );
}

#[test]
fn twenty_forty_nine_bytes_of_garbage_is_wire_too_large_not_parse_error() {
    let garbage = vec![0x5Au8; MAX_CERTIFICATE_WIRE_BYTES + 1];
    assert_eq!(garbage.len(), 2049);
    let err = NodeCertificate::from_wire_bytes(&garbage).expect_err("2049 must fail");
    assert!(
        matches!(
            err,
            Error::WireTooLarge {
                len: 2049,
                max: MAX_CERTIFICATE_WIRE_BYTES
            }
        ),
        "length gate must precede parsing, got {err:?}"
    );
}

#[test]
fn to_wire_bytes_rejects_oversize_encoding_and_too_many_capabilities() {
    let (subject, _, issuer) = golden_fields();

    // Too many capabilities — same variant as sign/verify.
    let too_many = NodeCertificate {
        subject,
        public_key: vec![0x11u8; 32],
        capabilities: vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES + 1],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer,
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0xABu8; 64],
        },
    };
    let err = too_many
        .to_wire_bytes()
        .expect_err("65 caps must fail encode");
    assert!(
        matches!(
            err,
            Error::TooManyCapabilities {
                count: c,
                max: MAX_CERT_CAPABILITIES
            } if c == MAX_CERT_CAPABILITIES + 1
        ),
        "{err:?}"
    );

    // Encoding that exceeds MAX_CERTIFICATE_WIRE_BYTES (public_key large enough
    // that the unbounded postcard form clears the certificate budget).
    let oversize_pk = NodeCertificate {
        subject,
        public_key: vec![0x11u8; 2_000],
        capabilities: vec![AlgId::Ed25519.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer,
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0xABu8; 64],
        },
    };
    let err = oversize_pk
        .to_wire_bytes()
        .expect_err("2000-byte public_key encoding must exceed wire budget");
    assert!(
        matches!(
            err,
            Error::WireTooLarge {
                max: MAX_CERTIFICATE_WIRE_BYTES,
                ..
            }
        ),
        "expected WireTooLarge, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// §7.11–7.15 — semantic
// ---------------------------------------------------------------------------

#[test]
fn unknown_signature_algorithm_code_is_rejected_with_code() {
    let bytes = wire_golden_bytes();
    // signature_algorithm sits just after the issuer string: replace Ed25519
    // (0x01) with 0x00FF encoded as postcard u16 varint `0xff 0x01`.
    let alg_offset = bytes.len() - 1 /*alg was 1 byte*/ - 1 /*sig len*/ - 64;
    assert_eq!(bytes[alg_offset], 0x01, "golden alg byte");
    let mut mutated = Vec::with_capacity(bytes.len() + 1);
    mutated.extend_from_slice(&bytes[..alg_offset]);
    mutated.extend_from_slice(&[0xff, 0x01]); // u16 0x00FF as postcard varint
    mutated.extend_from_slice(&bytes[alg_offset + 1..]);

    let err = NodeCertificate::from_wire_bytes(&mutated).expect_err("unknown alg");
    match err {
        Error::UnknownAlgorithm(code) => assert_eq!(code.code, 0x00FF),
        other => panic!("expected UnknownAlgorithm(0x00FF), got {other:?}"),
    }
}

#[test]
fn unknown_capability_code_survives_wire_decode_and_reencodes() {
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let fields = CertificateFields {
        subject: subject.node_id(),
        public_key: subject.public_key_bytes(),
        capabilities: vec![AlgId::Ed25519.as_u16(), 0x00FF],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: issuer.node_id(),
    };
    let cert = NodeCertificate::sign(fields, &issuer).expect("signs");
    let bytes = cert.to_wire_bytes().expect("encodes");
    let decoded = NodeCertificate::from_wire_bytes(&bytes).expect("decodes");
    assert_eq!(decoded.capabilities, vec![AlgId::Ed25519.as_u16(), 0x00FF]);
    assert_eq!(decoded.to_wire_bytes().expect("reencodes"), bytes);
    assert!(decoded.has_capability(AlgId::Ed25519));
    assert!(!decoded.has_capability(AlgId::Sha256));
}

#[test]
fn sixty_four_capabilities_encode_within_wire_byte_budget() {
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let fields = CertificateFields {
        subject: subject.node_id(),
        public_key: subject.public_key_bytes(),
        capabilities: vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES],
        valid_from: 1_000,
        valid_until: 1_000 + MAX_CERT_LIFETIME_SECS,
        issuer: issuer.node_id(),
    };
    let cert = NodeCertificate::sign(fields, &issuer).expect("64 caps must sign");
    let bytes = cert.to_wire_bytes().expect("64 caps must encode");
    let measured = bytes.len();
    assert!(
        measured <= MAX_CERTIFICATE_WIRE_BYTES,
        "64-capability certificate is {measured} bytes, bound is {MAX_CERTIFICATE_WIRE_BYTES}"
    );
    // Measured on this target after slice 2b: 239 bytes (earlier spike: 238).
    assert_eq!(
        measured, 239,
        "64-capability wire size changed unexpectedly: {measured}"
    );
    NodeCertificate::from_wire_bytes(&bytes).expect("64-cap wire must decode");
}

#[test]
fn decoding_is_not_verification_corrupted_signature_decodes_then_fails_verify() {
    let mut bytes = wire_golden_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let cert =
        NodeCertificate::from_wire_bytes(&bytes).expect("corrupted signature must still decode");
    let issuer_pk = PublicKey::from_bytes(&[0x22u8; 32]).expect("golden issuer key");
    let err = cert
        .verify(&issuer_pk, 1_500)
        .expect_err("verify must fail");
    assert!(
        matches!(err, Error::BadSignature(_)),
        "expected BadSignature after decode, got {err:?}"
    );
}

#[test]
fn sign_to_wire_from_wire_verify_round_trip_preserves_signing_bytes() {
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let cert = NodeCertificate::sign(
        CertificateFields {
            subject: subject.node_id(),
            public_key: subject.public_key_bytes(),
            capabilities: vec![AlgId::Ed25519.as_u16(), AlgId::Sha256.as_u16()],
            valid_from: 1_000,
            valid_until: 2_000,
            issuer: issuer.node_id(),
        },
        &issuer,
    )
    .expect("signs");
    let original_signing = signing_bytes(&cert);
    let wire = cert.to_wire_bytes().expect("encodes");
    let decoded = NodeCertificate::from_wire_bytes(&wire).expect("decodes");
    decoded
        .verify(&verifier_of(&issuer), 1_500)
        .expect("decoded certificate must verify");
    assert_eq!(
        signing_bytes(&decoded),
        original_signing,
        "canonical signing bytes must be preserved across the wire form"
    );
}
