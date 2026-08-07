use mw_crypto::ed25519::PublicKey;
use mw_crypto::{AlgId, Signature};
use mw_identity::{
    CertificateFields, Error, Keystore, MAX_CERT_LIFETIME_SECS, NodeCertificate, NodeId,
};

fn fields(
    subject: &Keystore,
    issuer: &Keystore,
    valid_from: u64,
    valid_until: u64,
) -> CertificateFields {
    CertificateFields {
        subject: subject.node_id(),
        public_key: subject.public_key_bytes(),
        capabilities: vec![AlgId::Ed25519, AlgId::Sha256],
        valid_from,
        valid_until,
        issuer: issuer.node_id(),
    }
}

fn verifier_of(keystore: &Keystore) -> PublicKey {
    PublicKey::from_bytes(&keystore.public_key_bytes()).expect("keystore emits a valid key")
}

#[test]
fn node_id_derivation_is_deterministic_and_round_trips() {
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
fn certificate_sign_verify_round_trips_at_a_valid_now() {
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
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    let result = cert.verify(&verifier_of(&issuer), 999);
    assert!(matches!(result, Err(Error::NotYetValid { .. })), "{result:?}");
}

#[test]
fn tampering_with_capabilities_breaks_the_binding() {
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let mut cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    assert_eq!(cert.capabilities[0], AlgId::Ed25519);
    cert.capabilities[0] = AlgId::X25519;

    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(
        matches!(result, Err(Error::BadSignature(_))),
        "expected BadSignature after capability flip, got {result:?}"
    );
}

#[test]
fn subject_key_mismatch_is_rejected_by_sign_and_verify() {
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let impostor = Keystore::generate();

    // sign refuses to mint a certificate whose subject isn't derived from
    // its public_key.
    let mut inconsistent = fields(&subject, &issuer, 1_000, 2_000);
    inconsistent.subject = impostor.node_id();
    let result = NodeCertificate::sign(inconsistent, &issuer);
    assert!(matches!(result, Err(Error::SubjectKeyMismatch)), "{result:?}");

    // verify rejects the same inconsistency on a received certificate,
    // regardless of the signature.
    let mut cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();
    cert.subject = impostor.node_id();
    let result = cert.verify(&verifier_of(&issuer), 1_500);
    assert!(matches!(result, Err(Error::SubjectKeyMismatch)), "{result:?}");
}

#[test]
fn wrong_issuer_key_fails_as_issuer_mismatch_not_bad_signature() {
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
    // Root/self-signed case: issuer == subject. Both self-consistency
    // checks (subject vs own key, issuer vs supplied key) must pass and
    // verification must succeed.
    let node = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&node, &node, 1_000, 2_000), &node)
        .expect("self-signed certificate must sign");
    assert_eq!(cert.subject, cert.issuer);
    cert.verify(&verifier_of(&node), 1_500)
        .expect("self-signed certificate must verify");
}

#[test]
fn tampered_signature_bytes_fail_as_bad_signature() {
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
    // PINS CURRENT BEHAVIOR — OPEN ARCHITECTURAL QUESTION. The spec orders
    // the mismatch checks before *signature* verification but is silent on
    // precedence relative to *temporal* validation. Today `verify` runs
    // subject check, issuer check, signature, then the time window, so a
    // certificate that is both expired and issuer-mismatched reports
    // IssuerKeyMismatch. If an ADR later rules that temporal validation
    // comes first, this test is the one that must change — do not "fix" it
    // without that ruling.
    let issuer = Keystore::generate();
    let subject = Keystore::generate();
    let other = Keystore::generate();
    let cert = NodeCertificate::sign(fields(&subject, &issuer, 1_000, 2_000), &issuer).unwrap();

    let result = cert.verify(&verifier_of(&other), 3_000); // expired AND wrong issuer
    assert!(
        matches!(result, Err(Error::IssuerKeyMismatch)),
        "current behavior: mismatch checks precede temporal validation, got {result:?}"
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
            capabilities: vec![AlgId::Ed25519, AlgId::Sha256],
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
