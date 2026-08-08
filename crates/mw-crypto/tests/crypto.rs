use mw_crypto::ed25519::{Keypair, PublicKey};
use mw_crypto::{AlgId, Error, Hasher, Signer, UnknownAlgorithmCode, Verifier, sha256};

/// Independent audit table cross-checking `AlgId::ALL` and compile-time pins.
const REGISTRY_AUDIT: &[(u16, AlgId)] = &[
    (0x0001, AlgId::Ed25519),
    (0x0002, AlgId::X25519),
    (0x0010, AlgId::Sha256),
    (0x0011, AlgId::Sha384),
    (0x0020, AlgId::MlKem768),
    (0x0030, AlgId::MlDsa87),
    (0x0031, AlgId::SlhDsa128s),
];

#[test]
fn every_registry_code_yields_correct_variant() {
    for &(code, expected) in REGISTRY_AUDIT {
        assert_eq!(AlgId::from_u16(code), Ok(expected));
    }
}

#[test]
fn every_variant_yields_correct_code() {
    for &alg in AlgId::ALL {
        let expected_code = REGISTRY_AUDIT
            .iter()
            .find(|&&(_, v)| v == alg)
            .map(|&(c, _)| c)
            .expect("audit table must cover every variant in ALL");
        assert_eq!(alg.as_u16(), expected_code);
    }
}

#[test]
fn alg_from_u16_round_trips_every_registry_variant() {
    for &alg in AlgId::ALL {
        let code = alg.as_u16();
        assert_eq!(AlgId::from_u16(code), Ok(alg));
    }
    for &(code, _) in REGISTRY_AUDIT {
        let decoded = AlgId::from_u16(code).expect("audit code must decode");
        assert_eq!(decoded.as_u16(), code);
    }
}

#[test]
fn explicit_discriminant_agrees_with_as_u16() {
    for &alg in AlgId::ALL {
        assert_eq!(alg as u16, alg.as_u16());
    }
}

#[test]
fn all_contains_no_duplicate_variants() {
    for (i, &a) in AlgId::ALL.iter().enumerate() {
        for &b in &AlgId::ALL[i + 1..] {
            assert_ne!(a, b, "duplicate variant in ALL");
        }
    }
}

#[test]
fn all_contains_no_duplicate_codes() {
    for (i, &a) in AlgId::ALL.iter().enumerate() {
        for &b in &AlgId::ALL[i + 1..] {
            assert_ne!(a.as_u16(), b.as_u16(), "duplicate code in ALL");
        }
    }
}

#[test]
fn all_length_matches_registry() {
    assert_eq!(AlgId::ALL.len(), 7);
}

#[test]
fn alg_from_u16_rejects_unknown_code() {
    for code in [0x0000, 0x0003, 0x00FF, 0xFFFF] {
        assert_eq!(AlgId::from_u16(code), Err(UnknownAlgorithmCode { code }));
    }
}

#[test]
fn trait_impls_agree_with_methods() {
    for &alg in AlgId::ALL {
        assert_eq!(u16::from(alg), alg.as_u16());
    }
    for &(code, expected) in REGISTRY_AUDIT {
        assert_eq!(AlgId::try_from(code), Ok(expected));
        assert_eq!(AlgId::try_from(code), AlgId::from_u16(code));
    }
    for code in [0x0000, 0x00FF] {
        assert_eq!(AlgId::try_from(code), AlgId::from_u16(code));
    }
}

#[test]
fn unknown_algorithm_code_implements_error_traits() {
    let err = UnknownAlgorithmCode { code: 0x00FF };
    assert!(format!("{err}").contains("00ff") || format!("{err}").contains("0x00ff"));
    let _: &dyn std::error::Error = &err;
}

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
    let sig = keypair
        .sign(b"original message")
        .expect("signing must succeed");
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

#[test]
fn public_key_verifies_peer_signature() {
    let signer = Keypair::generate();
    let msg = b"signed by a peer";
    let sig = signer.sign(msg).expect("signing must succeed");
    // Simulate receiving only the public key bytes over the wire.
    let peer = PublicKey::from_bytes(&signer.public_key_bytes()).expect("valid key");
    peer.verify(msg, &sig).expect("peer public key must verify");
}

#[test]
fn public_key_rejects_wrong_signer() {
    let a = Keypair::generate();
    let b = Keypair::generate();
    let sig = a.sign(b"from a").expect("signing must succeed");
    let b_pub = PublicKey::from_bytes(&b.public_key_bytes()).expect("valid key");
    assert!(matches!(
        b_pub.verify(b"from a", &sig),
        Err(mw_crypto::Error::VerificationFailed)
    ));
}

#[test]
fn malformed_public_key_is_rejected() {
    let err = PublicKey::from_bytes(&[0u8; 10]).expect_err("short key must be rejected");
    assert!(matches!(err, mw_crypto::Error::MalformedKey { .. }));
}
