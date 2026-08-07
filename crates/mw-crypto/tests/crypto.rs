use mw_crypto::ed25519::Keypair;
use mw_crypto::{AlgId, Error, Hasher, Signer, Verifier, sha256};

#[test]
fn sign_verify_round_trip() {
    let keypair = Keypair::generate();
    let msg = b"MESHWARDEN task lease v1";
    let sig = keypair.sign(msg).expect("signing must succeed");
    assert_eq!(sig.alg, AlgId::Ed25519);
    keypair.verify(msg, &sig).expect("round-trip must verify");
}

#[test]
fn tampered_message_fails() {
    let keypair = Keypair::generate();
    let sig = keypair.sign(b"original message").expect("signing must succeed");
    let err = keypair
        .verify(b"tampered message", &sig)
        .expect_err("tampered message must not verify");
    assert!(matches!(err, Error::VerificationFailed));
}

#[test]
fn mismatched_alg_id_is_rejected() {
    let keypair = Keypair::generate();
    let msg = b"algorithm agility check";
    let mut sig = keypair.sign(msg).expect("signing must succeed");
    // Valid bytes, wrong tag: the agility layer must reject before
    // inspecting the signature bytes.
    sig.alg = AlgId::MlDsa87;
    let err = keypair
        .verify(msg, &sig)
        .expect_err("mismatched AlgId must be rejected");
    assert!(matches!(
        err,
        Error::AlgMismatch {
            expected: AlgId::Ed25519,
            actual: AlgId::MlDsa87,
        }
    ));
}

#[test]
fn sha256_digest_carries_right_alg() {
    let digest = sha256(b"hello meshwarden");
    assert_eq!(digest.alg, AlgId::Sha256);
    assert_eq!(digest.bytes.len(), 32);

    let mut hasher = Hasher::new(AlgId::Sha256).expect("SHA-256 is implemented");
    hasher.update(b"hello ");
    hasher.update(b"meshwarden");
    let incremental = hasher.finalize();
    assert_eq!(incremental, digest);
}

#[test]
fn reserved_hash_alg_errors_without_panic() {
    let err = Hasher::new(AlgId::Sha384).expect_err("reserved alg must error");
    assert!(matches!(err, Error::UnsupportedAlg(AlgId::Sha384)));
}

#[test]
fn malformed_signature_length_is_rejected() {
    let keypair = Keypair::generate();
    let msg = b"length check";
    let mut sig = keypair.sign(msg).expect("signing must succeed");
    sig.bytes.truncate(16);
    let err = keypair
        .verify(msg, &sig)
        .expect_err("truncated signature must be rejected");
    assert!(matches!(err, Error::MalformedSignature { .. }));
}
