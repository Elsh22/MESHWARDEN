use mw_crypto::ed25519::PublicKey;
use mw_crypto::{AlgId, Signature, Signer};
use mw_identity::{
    CertificateFields, Error, Keystore, MAX_CERT_LIFETIME_SECS, NodeCertificate, NodeId,
};
use mw_proto::MAX_CERT_CAPABILITIES;
use serde::Serialize;

fn fields(
    subject: &Keystore,
    issuer: &Keystore,
    valid_from: u64,
    valid_until: u64,
) -> CertificateFields {
    CertificateFields {
        subject: subject.node_id(),
        public_key: subject.public_key_bytes(),
        // Mechanical Vec<u16> adaptation (ADR-017 Amendment 1 / slice 2a H2).
        capabilities: vec![AlgId::Ed25519.as_u16(), AlgId::Sha256.as_u16()],
        valid_from,
        valid_until,
        issuer: issuer.node_id(),
    }
}

fn verifier_of(keystore: &Keystore) -> PublicKey {
    PublicKey::from_bytes(&keystore.public_key_bytes()).expect("keystore emits a valid key")
}

/// Twin of the private signing form in `cert.rs`, for tests that must mint a
/// certificate `sign` refuses (over-long window, etc.) while still producing
/// a signature over the real canonical bytes.
#[derive(Serialize)]
struct SigningForm<'a> {
    subject: &'a NodeId,
    public_key: &'a [u8],
    capabilities: Vec<u16>,
    valid_from: u64,
    valid_until: u64,
    issuer: &'a NodeId,
}

fn sign_struct_directly(
    subject: NodeId,
    public_key: Vec<u8>,
    capabilities: Vec<u16>,
    valid_from: u64,
    valid_until: u64,
    issuer: NodeId,
    signer: &impl Signer,
) -> NodeCertificate {
    let msg = postcard::to_allocvec(&SigningForm {
        subject: &subject,
        public_key: &public_key,
        capabilities: capabilities.clone(),
        valid_from,
        valid_until,
        issuer: &issuer,
    })
    .expect("signing form encodes");
    let signature = signer.sign(&msg).expect("issuer signs");
    NodeCertificate {
        subject,
        public_key,
        capabilities,
        valid_from,
        valid_until,
        issuer,
        signature,
    }
}

#[test]
fn node_id_derivation_is_deterministic_and_round_trips() {
    // Property: NodeId derivation is deterministic; Display/FromStr round-trip.
    // ADR-008 / locked naming convention.
    let keystore = Keystore::generate();
    let key_bytes = keystore.public_key_bytes();

    let a = NodeId::from_public_key_bytes(&key_bytes);
    let b = NodeId::from_public_key_bytes(&key_bytes);
    assert_eq!(a, b, "same key bytes must derive the same NodeId");
    assert_eq!(a, keystore.node_id());

    let text = a.to_string();
    assert!(text.starts_with("mw:node:"), "unexpected form: {text}");
    assert_eq!(text.len(), "mw:node:".len() + 26);

    let parsed: NodeId = text.parse().expect("Display output must parse back");
    assert_eq!(parsed, a);
}

#[test]
fn malformed_node_id_strings_are_rejected() {
    // Property: malformed textual NodeIds are rejected.
    // ADR-017 §Testing obligations (structural parse failures).
    let valid = Keystore::generate().node_id().to_string();
    let encoded = valid.strip_prefix("mw:node:").unwrap();

    let cases = [
        String::new(),
        "mw:node:".to_owned(),
        format!("node:{encoded}"),
        format!("mw:task:{encoded}"),
        encoded.to_owned(),
        format!("mw:node:{}", &encoded[..25]),
        format!("mw:node:{encoded}A"),
        format!("mw:node:{}", encoded.to_lowercase()),
        format!("mw:node:{}1", &encoded[..25]), // '1' is outside the RFC 4648 base32 alphabet
        format!("mw:node:{}======", &encoded[..20]), // padding is rejected
    ];
    for case in cases {
        let result = case.parse::<NodeId>();
        assert!(
            matches!(result, Err(Error::MalformedNodeId(_))),
            "expected MalformedNodeId for {case:?}, got {result:?}"
        );
    }
}

#[test]
fn node_id_rejects_nonzero_trailing_bits() {
    // Property: 26-char Base32 with non-zero trailing bits is rejected.
    // ADR-017 §Testing obligations — load-bearing for AuthTranscriptV1 node-id fields.
    // 16 bytes → 26 chars encode 130 bits; the last character's low 2 bits must be zero.
    let s = "mw:node:CEIRCEIRCEIRCEIRCEIRCEIRCF";
    let result = s.parse::<NodeId>();
    assert!(
        matches!(result, Err(Error::MalformedNodeId(_))),
        "non-zero trailing bits must be rejected, got {result:?}"
    );
}

#[test]
fn node_id_rejects_lowercase_input() {
    // Property: lowercase Base32 input is rejected (canonical textual form).
    // ADR-017 §Testing obligations — load-bearing for AuthTranscriptV1 node-id fields.
    let valid = Keystore::generate().node_id().to_string();
    let lower = valid.to_lowercase();
    assert_ne!(valid, lower);
    let result = lower.parse::<NodeId>();
    assert!(
        matches!(result, Err(Error::MalformedNodeId(_))),
        "lowercase NodeId must be rejected, got {result:?}"
    );
}

#[test]
fn certificate_sign_verify_round_trips_at_a_valid_now() {
    // Property: a well-formed certificate signs and verifies inside its window.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 1_000 + 3_600), &issuer)
        .expect("in-bounds lifetime must sign");

    let issuer_pk = verifier_of(&issuer);
    cert.verify(&issuer_pk, 1_000).expect("valid at valid_from");
    cert.verify(&issuer_pk, 2_500).expect("valid mid-window");
}

#[test]
fn certificate_is_expired_at_and_after_valid_until() {
    // Property: verify reports Expired at and after valid_until (exclusive).
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();
    let issuer_pk = verifier_of(&issuer);

    for now in [2_000, 3_000] {
        let result = cert.verify(&issuer_pk, now);
        assert!(
            matches!(result, Err(Error::Expired { .. })),
            "expected Expired at now={now}, got {result:?}"
        );
    }
}

#[test]
fn certificate_is_not_yet_valid_before_valid_from() {
    // Property: verify reports NotYetValid before valid_from.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    let result = cert.verify(&verifier_of(&issuer), 999);
    assert!(
        matches!(result, Err(Error::NotYetValid { .. })),
        "{result:?}"
    );
}

#[test]
fn tampering_with_capabilities_breaks_the_binding() {
    // Property: capability bytes are covered by the signature.
    // Mechanical Vec<u16> adaptation for element comparison (H2).
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    assert_eq!(cert.capabilities[0], AlgId::Ed25519.as_u16());
    cert.capabilities[0] = AlgId::X25519.as_u16();

    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::BadSignature(_))),
        "expected BadSignature after capability flip, got {result:?}"
    );
}

#[test]
fn subject_key_mismatch_is_rejected_by_sign_and_verify() {
    // Property: subject must equal NodeId(public_key) on sign and verify.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let impostor = Keystore::generate();

    // sign refuses to mint a certificate whose subject isn't derived from
    // its public_key.
    let mut inconsistent = fields(&subject, &issuer, 1_000, 2_000);
    inconsistent.subject = impostor.node_id();
    let result = NodeCertificate::sign(inconsistent, &issuer);
    assert!(
        matches!(result, Err(Error::SubjectKeyMismatch)),
        "{result:?}"
    );

    // verify rejects the same inconsistency on a received certificate,
    // regardless of the signature.
    let mut cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();
    cert.subject = impostor.node_id();
    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::SubjectKeyMismatch)),
        "{result:?}"
    );
}

#[test]
fn wrong_issuer_key_fails_as_issuer_mismatch_not_bad_signature() {
    // Property: wrong-but-valid issuer key → IssuerKeyMismatch, not BadSignature.
    // ADR-017 §Certificate validation ordering.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let other = Keystore::generate();

    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    // `other`'s key is a perfectly valid Ed25519 key — just not the one the
    // certificate names as issuer.
    let result = cert.verify(&verifier_of(&other), 1_500);
    assert!(
        matches!(result, Err(Error::IssuerKeyMismatch)),
        "expected IssuerKeyMismatch, got {result:?}"
    );
}

#[test]
fn self_signed_certificate_with_issuer_equal_subject_verifies() {
    // Property: self-signed (issuer == subject) certificates verify.
    let node = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&node, &node, 1_000, 2_000), &node)
        .expect("self-signed certificate must sign");
    assert_eq!(cert.subject, cert.issuer);
    cert.verify(&verifier_of(&node), 1_500)
        .expect("self-signed certificate must verify");
}

#[test]
fn tampered_signature_bytes_fail_as_bad_signature() {
    // Property: flipped signature bytes → BadSignature.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    // Same length, one byte flipped: still a well-formed signature encoding,
    // so the failure must come from verification, not parsing.
    let last = cert.signature.bytes.len() - 1;
    cert.signature.bytes[last] ^= 0xFF;

    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::BadSignature(_))),
        "expected BadSignature after signature tamper, got {result:?}"
    );
}

#[test]
fn expired_certificate_with_wrong_issuer_reports_issuer_mismatch() {
    // Normative: ADR-017 §Certificate validation ordering — issuer mismatch
    // precedes temporal validation, so a certificate that is both expired and
    // issuer-mismatched reports IssuerKeyMismatch (not Expired).
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let other = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    let result = cert.verify(&verifier_of(&other), 3_000); // expired AND wrong issuer
    assert!(
        matches!(result, Err(Error::IssuerKeyMismatch)),
        "ADR-017 ordering: mismatch precedes temporal validation, got {result:?}"
    );
}

/// Records the exact message handed to the signer, so the canonical signing
/// form can be pinned without any secret-key material.
struct CapturingSigner(std::cell::RefCell<Vec<u8>>);

impl mw_crypto::Signer for CapturingSigner {
    fn sign(&self, msg: &[u8]) -> mw_crypto::Result<Signature> {
        *self.0.borrow_mut() = msg.to_vec();
        Ok(Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0u8; 64],
        })
    }
}

#[test]
fn golden_vector_canonical_form_and_node_id_are_unchanged() {
    // CANONICAL-FORM golden vector, minted from the implementation as
    // audited on 2026-08-07. It pins the NodeId derivation and the exact
    // canonical signing bytes (ADR-015) for fixed inputs. If it starts
    // failing, the canonical form or the NodeId derivation changed — both
    // are locked; that is a semantics break, not a test to update casually.
    //
    // It does NOT assert signature bytes: `Keystore`/`Keypair` expose no
    // seeded constructor (deliberately), so a real fixed-key signature
    // cannot be produced without widening the mw-crypto API.
    let subject_pk = [0x11u8; 32];
    let issuer_pk = [0x22u8; 32];

    let subject = NodeId::from_public_key_bytes(&subject_pk);
    let issuer = NodeId::from_public_key_bytes(&issuer_pk);
    assert_eq!(subject.to_string(), "mw:node:ALKETIY7XMTHZDZVF2MWRJ46HY");
    assert_eq!(issuer.to_string(), "mw:node:T5ZOUDHUSU3OHRTMPB7XAUMG34");

    let signer = CapturingSigner(std::cell::RefCell::new(Vec::new()));
    let cert = NodeCertificate::sign(
        CertificateFields {
            subject,
            public_key: subject_pk.to_vec(),
            capabilities: vec![AlgId::Ed25519.as_u16(), AlgId::Sha256.as_u16()],
            valid_from: 1_000,
            valid_until: 2_000,
            issuer,
        },
        &signer,
    )
    .expect("golden fields must sign");
    assert_eq!(cert.subject, subject);

    let canonical_hex: String = signer
        .0
        .borrow()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        canonical_hex,
        // postcard: subject string (len 0x22 = 34), 32-byte public key,
        // 2 capability codes (0x0001, 0x0010 as varints), valid_from 1000,
        // valid_until 2000 (varints), issuer string.
        "226d773a6e6f64653a414c4b4554495937584d54485a445a5646324d57524a34364859\
         2011111111111111111111111111111111111111111111111111111111111111110201\
         10e807d00f226d773a6e6f64653a54355a4f554448555355334f4852544d5042375841\
         554d473334"
    );
}

#[test]
fn lifetime_over_the_maximum_is_rejected_at_construction() {
    // Property: over-max and inverted windows rejected by sign (ADR-009).
    // Zero-length covered by dedicated test (ADR-017 H5).
    let issuer = Keystore::generate();
    let subject = Keystore::generate();

    let over = fields(&subject, &issuer, 1_000, 1_000 + MAX_CERT_LIFETIME_SECS + 1);
    let result = NodeCertificate::sign(over, &issuer);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "{result:?}"
    );

    let at_max = fields(&subject, &issuer, 1_000, 1_000 + MAX_CERT_LIFETIME_SECS);
    NodeCertificate::sign(at_max, &issuer).expect("exactly MAX_CERT_LIFETIME_SECS is allowed");

    let inverted = fields(&subject, &issuer, 2_000, 1_000);
    let result = NodeCertificate::sign(inverted, &issuer);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "{result:?}"
    );
}

// ---------------------------------------------------------------------------
// Inherited ADR-017 obligations (slice 2a H8)
// ---------------------------------------------------------------------------

#[test]
fn unknown_capability_code_signs_and_verifies() {
    // Property: unknown descriptive capability code (e.g. 0x00FF) is accepted.
    // ADR-017 Amendment 1 / §Descriptive capability codes / §Testing obligations.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut f = fields(&subject, &issuer, 1_000, 2_000);
    f.capabilities.push(0x00FF);
    let cert = NodeCertificate::sign(f, &issuer).expect("unknown capability must sign");
    cert.verify(&verifier_of(&issuer), 1_500)
        .expect("unknown capability must verify");
}

#[test]
fn unknown_capability_code_signing_bytes_indifferent_to_resolvability() {
    // Property: canonical signing bytes are indifferent to resolvability.
    // ADR-017 §Testing obligations — a certificate carrying an unknown
    // capability code has the same signing bytes as an equivalent certificate
    // whose codes are supplied as raw u16 literals (including the unknown),
    // proving the form does not filter or remap through AlgId.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();

    let signer_via_algid = CapturingSigner(std::cell::RefCell::new(Vec::new()));
    let mut f_via_algid = fields(&subject, &issuer, 1_000, 2_000);
    f_via_algid.capabilities = vec![AlgId::Ed25519.as_u16(), 0x00FF];
    NodeCertificate::sign(f_via_algid, &signer_via_algid).expect("signs");

    let signer_via_raw = CapturingSigner(std::cell::RefCell::new(Vec::new()));
    let mut f_via_raw = fields(&subject, &issuer, 1_000, 2_000);
    // Identical raw list: 0x0001 is Ed25519's registry code; 0x00FF is unknown.
    f_via_raw.capabilities = vec![0x0001, 0x00FF];
    NodeCertificate::sign(f_via_raw, &signer_via_raw).expect("signs");

    assert_eq!(
        &*signer_via_algid.0.borrow(),
        &*signer_via_raw.0.borrow(),
        "signing bytes must be identical for the same raw u16 list regardless \
         of whether individual codes are resolvable"
    );
}

#[test]
fn has_capability_searches_raw_codes_with_unknown_present() {
    // Property: has_capability is correct with unknown codes present.
    // ADR-017 §Testing obligations / Amendment 1 accessor discipline.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut f = fields(&subject, &issuer, 1_000, 2_000);
    f.capabilities = vec![AlgId::Ed25519.as_u16(), 0x00FF];
    let cert = NodeCertificate::sign(f, &issuer).unwrap();

    assert!(cert.has_capability(AlgId::Ed25519));
    assert!(!cert.has_capability(AlgId::Sha256));
    assert!(!cert.has_capability(AlgId::X25519));
}

#[test]
fn capability_codes_includes_unknown_known_capabilities_omits_it() {
    // Property: capability_codes is complete; known_capabilities is lossy.
    // ADR-017 §Testing obligations — pins documented lossiness.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut f = fields(&subject, &issuer, 1_000, 2_000);
    f.capabilities = vec![AlgId::Ed25519.as_u16(), 0x00FF, AlgId::Sha256.as_u16()];
    let cert = NodeCertificate::sign(f, &issuer).unwrap();

    assert_eq!(
        cert.capability_codes(),
        &[AlgId::Ed25519.as_u16(), 0x00FF, AlgId::Sha256.as_u16()]
    );
    let known: Vec<AlgId> = cert.known_capabilities().collect();
    assert_eq!(known, vec![AlgId::Ed25519, AlgId::Sha256]);
    assert!(!known.iter().any(|&a| a.as_u16() == 0x00FF));
}

/// Shared sign+verify rejection check for a subject `public_key` fixture that
/// `PublicKey::from_bytes` must reject. Subject is derived from the bad key so
/// the failure is well-formedness, not `SubjectKeyMismatch`.
fn assert_malformed_subject_key_rejected_by_sign_and_verify(bad_key: Vec<u8>) -> mw_crypto::Error {
    let issuer = Keystore::generate();
    let subject = Keystore::generate();

    let from_bytes_err = PublicKey::from_bytes(&bad_key)
        .expect_err("fixture must be rejected by PublicKey::from_bytes");

    let mut f = fields(&subject, &issuer, 1_000, 2_000);
    f.public_key = bad_key.clone();
    f.subject = NodeId::from_public_key_bytes(&bad_key);
    let result = NodeCertificate::sign(f, &issuer);
    let sign_err = match result {
        Err(Error::MalformedSubjectPublicKey(e)) => e,
        other => panic!("sign must reject malformed subject key, got {other:?}"),
    };

    // Well-formedness precedes signature, so a stub signature suffices.
    let cert = NodeCertificate {
        subject: NodeId::from_public_key_bytes(&bad_key),
        public_key: bad_key,
        capabilities: vec![AlgId::Ed25519.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: issuer.node_id(),
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0u8; 64],
        },
    };
    let result = cert.verify(&verifier_of(&issuer), 1_500);
    let verify_err = match result {
        Err(Error::MalformedSubjectPublicKey(e)) => e,
        other => panic!("verify must reject malformed subject key, got {other:?}"),
    };

    // The typed error is identical across length and point failures (both map
    // to `mw_crypto::Error::MalformedKey { alg: Ed25519 }`); pin that here.
    assert!(matches!(
        from_bytes_err,
        mw_crypto::Error::MalformedKey {
            alg: AlgId::Ed25519
        }
    ));
    assert_eq!(
        format!("{from_bytes_err:?}"),
        format!("{sign_err:?}"),
        "sign must surface the same typed MalformedKey as from_bytes"
    );
    assert_eq!(
        format!("{from_bytes_err:?}"),
        format!("{verify_err:?}"),
        "verify must surface the same typed MalformedKey as from_bytes"
    );
    from_bytes_err
}

#[test]
fn subject_public_key_of_wrong_length_rejected_by_sign_and_verify() {
    // Property: wrong-length public_key rejected by sign and verify.
    // ADR-017 §Legacy: NodeCertificate.public_key is untagged / §Testing obligations.
    // Reaches `PublicKey::from_bytes` length branch (`try_into` to `[u8; 32]`).
    let bad_key = vec![0x11u8; 31];
    let err = assert_malformed_subject_key_rejected_by_sign_and_verify(bad_key);
    assert!(matches!(
        err,
        mw_crypto::Error::MalformedKey {
            alg: AlgId::Ed25519
        }
    ));
}

#[test]
fn subject_public_key_invalid_point_rejected_by_sign_and_verify() {
    // Property: 32-byte non-Ed25519-point public_key rejected by sign and verify.
    // ADR-017 §Legacy: NodeCertificate.public_key is untagged / §Testing obligations
    // (RSK-017-15 mitigation: well-formedness checking).
    //
    // Fixture `[0x02; 32]` is 32 bytes of correct length whose decompression
    // fails on ed25519-dalek 2.2.0, so this reaches the `VerifyingKey::from_bytes`
    // branch rather than the length branch. That failure is a computed property
    // of these specific bytes — changing them requires re-checking point
    // validity (same discipline as the `[0x11; 32]` / `[0x22; 32]` fixture note
    // in ADR-017 §Testing obligations).
    //
    // Note: `mw_crypto::Error::MalformedKey` does not distinguish length from
    // point failure; both branches of `PublicKey::from_bytes` map to the same
    // variant. Observed error for this fixture is therefore identical in type
    // to the wrong-length case.
    let bad_key = vec![0x02u8; 32];
    let err = assert_malformed_subject_key_rejected_by_sign_and_verify(bad_key);
    assert!(matches!(
        err,
        mw_crypto::Error::MalformedKey {
            alg: AlgId::Ed25519
        }
    ));
}

#[test]
fn capability_count_bound_enforced_in_sign_and_verify() {
    // Property: exactly MAX_CERT_CAPABILITIES accepted; +1 rejected in both paths.
    // ADR-017 §Capability bound.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();

    let mut at_max = fields(&subject, &issuer, 1_000, 2_000);
    at_max.capabilities = vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES];
    let cert = NodeCertificate::sign(at_max, &issuer).expect("exactly max must sign");
    cert.verify(&verifier_of(&issuer), 1_500)
        .expect("exactly max must verify");

    let mut over = fields(&subject, &issuer, 1_000, 2_000);
    over.capabilities = vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES + 1];
    let result = NodeCertificate::sign(over, &issuer);
    assert!(
        matches!(
            result,
            Err(Error::TooManyCapabilities {
                count: c,
                max: MAX_CERT_CAPABILITIES
            }) if c == MAX_CERT_CAPABILITIES + 1
        ),
        "sign must reject +1, got {result:?}"
    );

    let over_cert = NodeCertificate {
        subject: subject.node_id(),
        public_key: subject.public_key_bytes(),
        capabilities: vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES + 1],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: issuer.node_id(),
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0u8; 64],
        },
    };
    let result = over_cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(
            result,
            Err(Error::TooManyCapabilities {
                count: c,
                max: MAX_CERT_CAPABILITIES
            }) if c == MAX_CERT_CAPABILITIES + 1
        ),
        "verify must reject +1, got {result:?}"
    );
}

#[test]
fn zero_length_window_rejected_by_sign_and_verify() {
    // Property: valid_until == valid_from rejected by sign and verify.
    // ADR-017 §Certificate validation ordering (H5).
    let issuer = Keystore::generate();
    let subject = Keystore::generate();

    let result = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 1_000), &issuer);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "sign must reject zero-length window, got {result:?}"
    );

    let cert = sign_struct_directly(
        subject.node_id(),
        subject.public_key_bytes(),
        vec![AlgId::Ed25519.as_u16()],
        1_000,
        1_000,
        issuer.node_id(),
        &issuer,
    );
    let result = cert.verify(&verifier_of(&issuer), 1_000);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "verify must reject zero-length window, got {result:?}"
    );
}

#[test]
fn inverted_window_rejected_by_sign_and_verify() {
    // Property: inverted window rejected by both paths.
    // ADR-017 §Certificate validation ordering (H5).
    let issuer = Keystore::generate();
    let subject = Keystore::generate();

    let result = NodeCertificate::sign(fields(&subject, &issuer, 2_000, 1_000), &issuer);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "sign must reject inverted window, got {result:?}"
    );

    let cert = sign_struct_directly(
        subject.node_id(),
        subject.public_key_bytes(),
        vec![AlgId::Ed25519.as_u16()],
        2_000,
        1_000,
        issuer.node_id(),
        &issuer,
    );
    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "verify must reject inverted window, got {result:?}"
    );
}

#[test]
fn over_max_lifetime_rejected_by_verify_not_only_sign() {
    // Property: lifetime cap re-enforced in verify (H-1 / RSK-017-4 coupling).
    // ADR-017 §Certificate validation ordering. Constructed directly because
    // sign refuses over-long windows.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let valid_from = 1_000;
    let valid_until = 1_000 + MAX_CERT_LIFETIME_SECS + 1;
    let cert = sign_struct_directly(
        subject.node_id(),
        subject.public_key_bytes(),
        vec![AlgId::Ed25519.as_u16()],
        valid_from,
        valid_until,
        issuer.node_id(),
        &issuer,
    );
    let result = cert.verify(&verifier_of(&issuer), valid_from + 1);
    assert!(
        matches!(result, Err(Error::LifetimeExceedsMaximum { .. })),
        "verify must reject over-max lifetime, got {result:?}"
    );
}

#[test]
fn verify_precedence_over_count_before_subject_mismatch() {
    // Property: capability count precedes subject mismatch.
    // ADR-017 §Certificate validation ordering.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let impostor = Keystore::generate();
    let cert = NodeCertificate {
        subject: impostor.node_id(),
        public_key: subject.public_key_bytes(),
        capabilities: vec![AlgId::Ed25519.as_u16(); MAX_CERT_CAPABILITIES + 1],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: issuer.node_id(),
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0u8; 64],
        },
    };
    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::TooManyCapabilities { .. })),
        "over-count must precede subject mismatch, got {result:?}"
    );
}

#[test]
fn verify_precedence_malformed_key_before_subject_mismatch() {
    // Property: subject key well-formedness precedes subject mismatch.
    // ADR-017 §Certificate validation ordering.
    let issuer = Keystore::generate();
    let impostor = Keystore::generate();
    let bad_key = vec![0x11u8; 31];
    let cert = NodeCertificate {
        subject: impostor.node_id(), // mismatched relative to NodeId(bad_key)
        public_key: bad_key,
        capabilities: vec![AlgId::Ed25519.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer: issuer.node_id(),
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0u8; 64],
        },
    };
    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::MalformedSubjectPublicKey(_))),
        "malformed key must precede subject mismatch, got {result:?}"
    );
}

#[test]
fn verify_precedence_bad_signature_before_expired() {
    // Property: signature check precedes temporal Expired.
    // ADR-017 §Certificate validation ordering.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();
    let last = cert.signature.bytes.len() - 1;
    cert.signature.bytes[last] ^= 0xFF;
    let result = cert.verify(&verifier_of(&issuer), 3_000); // expired AND bad sig
    assert!(
        matches!(result, Err(Error::BadSignature(_))),
        "bad signature must precede expired, got {result:?}"
    );
}

#[test]
fn duplicate_capability_codes_are_accepted() {
    // Property: duplicate capability codes are accepted (no dedup).
    // ADR-017 §Capability bound — pinning prevents silent canonical-byte changes.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut f = fields(&subject, &issuer, 1_000, 2_000);
    f.capabilities = vec![
        AlgId::Ed25519.as_u16(),
        AlgId::Ed25519.as_u16(),
        AlgId::Sha256.as_u16(),
    ];
    let cert = NodeCertificate::sign(f, &issuer).expect("duplicates must sign");
    cert.verify(&verifier_of(&issuer), 1_500)
        .expect("duplicates must verify");
    assert_eq!(cert.capability_codes().len(), 3);
}
