//! Tests for the bounded decode primitives (ADR-017 §Pre-authentication
//! resource bounds, §Bounds-before-allocation obligation, §Normative parsing
//! rules).
//!
//! Empirical note pinned throughout: on the pinned postcard (1.1.3) the
//! opaque-`size_hint` flavor wrapper works — `SeqAccess::size_hint` exposes
//! the declared element count to the sequence visitor, so `BoundedVec`
//! rejects an oversized declared count with typed `BoundExceeded` before
//! decoding any element. The byte-string path (`deserialize_bytes`) has no
//! pre-take count visibility: a declared length larger than the remaining
//! input fails inside postcard's `try_take_n` (a pure bounds check on the
//! borrowed slice — no allocation), surfacing as generic `MalformedWire`
//! (§4 item 5 fallback, allocation safety unconditional).

use std::fmt;

use mw_proto::{BoundedBytes, BoundedVec, Error, Hello, decode_exact};
use serde::Deserialize;
use serde::de::Visitor;

type Bytes8 = BoundedBytes<8>;
type Bytes4 = BoundedBytes<4>;
type Vec8 = BoundedVec<u16, 8>;
type Nested = BoundedVec<BoundedBytes<4>, 8>;

/// Test-local wrapper whose `Deserialize` calls [`decode_exact`] on the
/// borrowed byte payload — a genuine nested decode scope.
#[derive(Debug)]
struct NestedExactDecode;

impl<'de> Deserialize<'de> for NestedExactDecode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVis;

        impl<'de> Visitor<'de> for BytesVis {
            type Value = NestedExactDecode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "bytes whose payload is decoded via nested decode_exact")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match decode_exact::<Bytes4>(v) {
                    Ok(_) => Ok(NestedExactDecode),
                    Err(_) => Err(E::custom("nested decode_exact failed")),
                }
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match decode_exact::<Bytes4>(v) {
                    Ok(_) => Ok(NestedExactDecode),
                    Err(_) => Err(E::custom("nested decode_exact failed")),
                }
            }
        }

        deserializer.deserialize_bytes(BytesVis)
    }
}

/// Postcard varint encoding of `u64::MAX` (10 bytes) — a declared
/// length/count near `usize::MAX` on 64-bit targets.
const ENORMOUS_VARINT: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

// ---------------------------------------------------------------------------
// Byte-compatibility pins — prevent silent wire changes
// ---------------------------------------------------------------------------

/// §10 test 1 — pins that `BoundedBytes<N>` serializes byte-identically to
/// the equivalent `&[u8]` (D1 requirement; ADR-015 single-codec discipline).
#[test]
fn bounded_bytes_serializes_identically_to_byte_slice() {
    let cases: &[&[u8]] = &[
        &[],                       // empty
        &[0xAA],                   // one byte
        &[1, 2, 3, 4, 5, 6, 7, 8], // at bound (N = 8)
    ];
    for raw in cases {
        let bounded = Bytes8::from_slice(raw).expect("within bound");
        let bounded_bytes = postcard::to_allocvec(&bounded).expect("serialize bounded");
        let slice_bytes = postcard::to_allocvec(*raw).expect("serialize slice");
        assert_eq!(
            bounded_bytes, slice_bytes,
            "BoundedBytes wire form must equal &[u8] wire form for {raw:?}"
        );
    }
}

/// §10 test 2 — pins that `BoundedVec<u16, N>` serializes byte-identically
/// to the equivalent `Vec<u16>` postcard sequence (D2 requirement 6).
#[test]
fn bounded_vec_serializes_identically_to_vec() {
    let cases: &[&[u16]] = &[
        &[],                                 // empty
        &[0x0777],                           // one element (2-byte varint)
        &[1, 2, 3, 0x0777, 5, 6, 7, 0xFFFF], // at bound (N = 8)
    ];
    for raw in cases {
        let bounded = Vec8::new(raw.to_vec()).expect("within bound");
        let bounded_bytes = postcard::to_allocvec(&bounded).expect("serialize bounded");
        let vec_bytes = postcard::to_allocvec(&raw.to_vec()).expect("serialize vec");
        assert_eq!(
            bounded_bytes, vec_bytes,
            "BoundedVec wire form must equal Vec<u16> wire form for {raw:?}"
        );
    }
}

// §10 test 3 — the existing `Hello` golden vector `[0x03, 0x01, 0x02, 0x10]`
// is pinned unchanged by `hello_postcard_golden_vector_is_stable` in
// `tests/proto.rs`. It is deliberately not duplicated or modified here.

// ---------------------------------------------------------------------------
// Bound enforcement
// ---------------------------------------------------------------------------

/// §10 test 4 — pins that every constructor accepts exactly `N` and rejects
/// `N + 1` with the typed bound error (D1/D2: no unchecked construction).
#[test]
fn constructors_accept_bound_and_reject_one_over() {
    let at_bound = vec![0u8; 8];
    let over = vec![0u8; 9];

    assert!(Bytes8::new(at_bound.clone()).is_ok());
    assert!(Bytes8::from_slice(&at_bound).is_ok());
    assert_eq!(
        Bytes8::new(over.clone()).expect_err("N + 1 must be rejected"),
        Error::BoundExceeded {
            declared: 9,
            max: 8
        }
    );
    assert_eq!(
        Bytes8::from_slice(&over).expect_err("N + 1 must be rejected"),
        Error::BoundExceeded {
            declared: 9,
            max: 8
        }
    );

    assert!(Vec8::new(vec![0u16; 8]).is_ok());
    assert_eq!(
        Vec8::new(vec![0u16; 9]).expect_err("N + 1 must be rejected"),
        Error::BoundExceeded {
            declared: 9,
            max: 8
        }
    );
}

/// §10 test 5 — pins that a value of exactly `N` round-trips through the
/// strict decoder (bound is inclusive; ADR-017 bounds are `<=`).
#[test]
fn round_trip_through_decode_exact_at_bound() {
    let bytes = Bytes8::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).expect("at bound");
    let encoded = postcard::to_allocvec(&bytes).expect("encode");
    let decoded: Bytes8 = decode_exact(&encoded).expect("decode at bound");
    assert_eq!(decoded, bytes);

    let vec = Vec8::new(vec![1, 2, 3, 4, 5, 6, 7, 8]).expect("at bound");
    let encoded = postcard::to_allocvec(&vec).expect("encode");
    let decoded: Vec8 = decode_exact(&encoded).expect("decode at bound");
    assert_eq!(decoded, vec);
}

/// §10 test 6 — pins that input declaring `N + 1` bytes/elements, with all
/// bytes actually present, is the typed `BoundExceeded { N + 1, N }`
/// (ADR-017 decode-time bound enforcement).
#[test]
fn declared_one_over_bound_with_bytes_present_is_bound_exceeded() {
    // 9 declared bytes, all 9 present.
    let mut input = vec![0x09u8];
    input.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(
        decode_exact::<Bytes8>(&input).expect_err("over bound must fail"),
        Error::BoundExceeded {
            declared: 9,
            max: 8
        }
    );

    // 9 declared u16 elements, all 9 present (values < 0x80: 1 byte each).
    let mut input = vec![0x09u8];
    input.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    assert_eq!(
        decode_exact::<Vec8>(&input).expect_err("over bound must fail"),
        Error::BoundExceeded {
            declared: 9,
            max: 8
        }
    );
}

/// §10 test 7 — pins the exact-length gate (ADR-017 §Exact-length
/// validation): exact accepted, shorter and longer rejected as
/// `ExactLength`.
#[test]
fn require_exact_len_accepts_exact_and_rejects_other_lengths() {
    let bytes = Bytes8::from_slice(&[1, 2, 3, 4]).expect("within bound");

    assert_eq!(
        bytes.require_exact_len(4).expect("exact must pass"),
        &[1, 2, 3, 4]
    );
    assert_eq!(
        bytes
            .require_exact_len(3)
            .expect_err("shorter expectation must fail"),
        Error::ExactLength {
            expected: 3,
            actual: 4
        }
    );
    assert_eq!(
        bytes
            .require_exact_len(5)
            .expect_err("longer expectation must fail"),
        Error::ExactLength {
            expected: 5,
            actual: 4
        }
    );
}

// ---------------------------------------------------------------------------
// Allocation-safety adversarial cases — ADR-017 obligation 4
// ---------------------------------------------------------------------------

/// §10 test 8 (BoundedVec) — pins ADR-017 obligation 4: a tiny input
/// declaring an enormous element count is rejected promptly with no
/// oversized allocation. On the pinned postcard 1.1.3 the flavor wrapper
/// works, so the failure is the typed `BoundExceeded` carrying the declared
/// count, produced before any element decode.
#[test]
fn vec_tiny_input_with_enormous_declared_count_is_rejected_promptly() {
    // Declared count near usize::MAX (u64::MAX), one stray byte of "input".
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    assert_eq!(
        decode_exact::<Vec8>(&input).expect_err("enormous count must fail"),
        Error::BoundExceeded {
            declared: u64::MAX as usize,
            max: 8
        }
    );

    // Declared count comfortably above N but far below usize::MAX (1000).
    let input = [0xE8u8, 0x07, 0x00];
    assert_eq!(
        decode_exact::<Vec8>(&input).expect_err("count 1000 must fail"),
        Error::BoundExceeded {
            declared: 1000,
            max: 8
        }
    );
}

/// §10 test 8 (BoundedBytes) — pins ADR-017 obligation 4 for the byte-string
/// path. On the pinned postcard 1.1.3 `deserialize_bytes` offers no
/// pre-take count visibility: the enormous declared length fails inside
/// `try_take_n` — a pure bounds check on the borrowed input slice, so no
/// allocation of any size occurs — and surfaces as the generic
/// `MalformedWire` (§4 item 5 fallback; typed early rejection is
/// best-effort, allocation safety is unconditional).
#[test]
fn bytes_tiny_input_with_enormous_declared_len_is_rejected_promptly() {
    // Declared length near usize::MAX (u64::MAX), one stray byte.
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    assert_eq!(
        decode_exact::<Bytes8>(&input).expect_err("enormous length must fail"),
        Error::MalformedWire
    );

    // Declared length comfortably above N but far below usize::MAX (1000).
    let input = [0xE8u8, 0x07, 0x00];
    assert_eq!(
        decode_exact::<Bytes8>(&input).expect_err("length 1000 must fail"),
        Error::MalformedWire
    );
}

/// §10 test 9 — pins ADR-017 obligation 4 for the nested type, enormous
/// outer declaration: the outer `BoundedVec` count is visible via the
/// working flavor wrapper, so the failure is typed `BoundExceeded`.
#[test]
fn nested_enormous_outer_declaration_is_rejected_promptly() {
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    assert_eq!(
        decode_exact::<Nested>(&input).expect_err("enormous outer count must fail"),
        Error::BoundExceeded {
            declared: u64::MAX as usize,
            max: 8
        }
    );
}

/// §10 test 9 — pins ADR-017 obligation 4 for the nested type, enormous
/// inner declaration: the inner `BoundedBytes` length fails inside
/// postcard's `try_take_n` with no allocation (byte path has no pre-take
/// visibility on the pinned 1.1.3), surfacing as `MalformedWire`.
#[test]
fn nested_enormous_inner_declaration_is_rejected_promptly() {
    // Outer count 1 (within bound), inner byte length u64::MAX, 1 stray byte.
    let mut input = vec![0x01u8];
    input.extend_from_slice(&ENORMOUS_VARINT);
    input.push(0x00);
    assert_eq!(
        decode_exact::<Nested>(&input).expect_err("enormous inner length must fail"),
        Error::MalformedWire
    );
}

/// §10 test 10 — pins that truncation at every prefix length of a valid
/// encoding is rejected without panic, for both types (style of the existing
/// `truncated_frame_is_rejected_without_panic`).
#[test]
fn truncated_bounded_input_is_rejected_without_panic() {
    let bytes = Bytes8::from_slice(&[1, 2, 3, 4, 5]).expect("within bound");
    let encoded = postcard::to_allocvec(&bytes).expect("encode");
    decode_exact::<Bytes8>(&encoded).expect("full input must decode");
    for n in 0..encoded.len() {
        let err = decode_exact::<Bytes8>(&encoded[..n]).expect_err("truncated input must fail");
        assert_eq!(
            err,
            Error::MalformedWire,
            "unexpected error at truncate {n}"
        );
    }

    let vec = Vec8::new(vec![1, 2, 0x0777]).expect("within bound");
    let encoded = postcard::to_allocvec(&vec).expect("encode");
    decode_exact::<Vec8>(&encoded).expect("full input must decode");
    for n in 0..encoded.len() {
        let err = decode_exact::<Vec8>(&encoded[..n]).expect_err("truncated input must fail");
        assert_eq!(
            err,
            Error::MalformedWire,
            "unexpected error at truncate {n}"
        );
    }
}

/// §10 test 11 — pins that a declared count/length of zero decodes to an
/// empty value without error (the bound is an upper bound, not a minimum).
#[test]
fn zero_declared_count_decodes_to_empty_value() {
    let decoded: Bytes8 = decode_exact(&[0x00]).expect("empty byte string must decode");
    assert!(decoded.is_empty());
    assert_eq!(decoded.len(), 0);

    let decoded: Vec8 = decode_exact(&[0x00]).expect("empty sequence must decode");
    assert!(decoded.is_empty());
    assert_eq!(decoded.len(), 0);
}

// ---------------------------------------------------------------------------
// Violation channel (D3)
// ---------------------------------------------------------------------------

/// §10 test 12 — pins that the violation channel is cleared on entry: a
/// failing decode followed by a *differently* failing decode reports the
/// second decode's own cause, in both orders (D3 scoping requirement).
#[test]
fn violation_channel_is_cleared_between_decodes() {
    // First failure records a bound violation...
    let over: [u8; 6] = [0x05, 1, 2, 3, 4, 5];
    assert_eq!(
        decode_exact::<Bytes4>(&over).expect_err("over bound must fail"),
        Error::BoundExceeded {
            declared: 5,
            max: 4
        }
    );
    // ...the next, differently-failing decode must report its own cause,
    // not the stale violation.
    let truncated: [u8; 3] = [0x05, 1, 2];
    assert_eq!(
        decode_exact::<Bytes4>(&truncated).expect_err("truncated must fail"),
        Error::MalformedWire
    );

    // And in the reverse order: a generic failure must not suppress a
    // subsequent typed violation.
    assert_eq!(
        decode_exact::<Bytes4>(&truncated).expect_err("truncated must fail"),
        Error::MalformedWire
    );
    assert_eq!(
        decode_exact::<Bytes4>(&over).expect_err("over bound must fail"),
        Error::BoundExceeded {
            declared: 5,
            max: 4
        }
    );
}

/// §10 test 13 — pins that a successful decode following a failed one is
/// unaffected by the earlier failure (D3 scoping requirement).
#[test]
fn successful_decode_after_failed_decode_is_unaffected() {
    let over: [u8; 6] = [0x05, 1, 2, 3, 4, 5];
    assert!(decode_exact::<Bytes4>(&over).is_err());

    let valid: [u8; 3] = [0x02, 0xAA, 0xBB];
    let decoded: Bytes4 = decode_exact(&valid).expect("valid input must decode after a failure");
    assert_eq!(
        decoded,
        Bytes4::from_slice(&[0xAA, 0xBB]).expect("in bound")
    );
}

/// §10 test 14 — pins nested violation attribution: the innermost violation
/// that actually occurred is reported (D3 nesting-safety requirement). Here
/// the outer count (2 <= 8) is fine and the second inner byte string (5 > 4)
/// violates.
#[test]
fn nested_decode_reports_innermost_violation() {
    let input: [u8; 9] = [
        0x02, // outer count: 2 (within outer bound 8)
        0x01, 0xAA, // element 0: 1 byte, within inner bound 4
        0x05, 1, 2, 3, 4, 5, // element 1: 5 bytes, exceeds inner bound 4
    ];
    assert_eq!(
        decode_exact::<Nested>(&input).expect_err("inner violation must fail"),
        Error::BoundExceeded {
            declared: 5,
            max: 4
        }
    );
}

/// Pins depth-aware violation-channel ownership across nested `decode_exact`
/// calls: a bound violation raised in an inner decode must surface as
/// `BoundExceeded` from the outer decode (not be downgraded to
/// `MalformedWire` by an inner scope clearing the channel), and the channel
/// must still be cleared once the outermost scope exits.
#[test]
fn nested_decode_exact_preserves_inner_bound_exceeded() {
    // Inner payload: BoundedBytes<4> declaring length 5 (genuine BoundExceeded).
    let inner: [u8; 6] = [0x05, 1, 2, 3, 4, 5];
    // Outer wire: that inner payload as a postcard byte string.
    let input = postcard::to_allocvec(&inner.as_slice()).expect("encode wrapper bytes");

    assert_eq!(
        decode_exact::<NestedExactDecode>(&input)
            .expect_err("inner bound violation must surface from outer decode"),
        Error::BoundExceeded {
            declared: 5,
            max: 4
        }
    );

    // After the outermost scope exits, a differently-failing decode reports
    // its own cause — not a stale BoundExceeded.
    let truncated: [u8; 3] = [0x05, 1, 2];
    assert_eq!(
        decode_exact::<Bytes4>(&truncated).expect_err("truncated must fail"),
        Error::MalformedWire
    );
}

// ---------------------------------------------------------------------------
// Finalization (D4)
// ---------------------------------------------------------------------------

/// §10 test 15 — pins ADR-017 §Normative parsing rules rule 1: one trailing
/// byte is the typed `TrailingBytes { remaining: 1 }`, not a generic error.
#[test]
fn decode_exact_rejects_one_trailing_byte() {
    let mut input = postcard::to_allocvec(&Bytes8::from_slice(&[0xAA, 0xBB]).expect("in bound"))
        .expect("encode");
    input.push(0x00);
    assert_eq!(
        decode_exact::<Bytes8>(&input).expect_err("trailing byte must fail"),
        Error::TrailingBytes { remaining: 1 }
    );
}

/// §10 test 16 — pins the trailing-byte count: many trailing bytes report
/// the correct `remaining` (framing-bug vs attack distinction, maintainer
/// decision in D4).
#[test]
fn decode_exact_rejects_many_trailing_bytes_with_correct_count() {
    let mut input =
        postcard::to_allocvec(&Vec8::new(vec![1, 2, 3]).expect("in bound")).expect("encode");
    input.extend_from_slice(&[0u8; 7]);
    assert_eq!(
        decode_exact::<Vec8>(&input).expect_err("trailing bytes must fail"),
        Error::TrailingBytes { remaining: 7 }
    );
}

/// §10 test 17 — pins finding M-4: `Hello::from_bytes` is now strict and
/// rejects trailing bytes. The chosen error is the typed
/// `TrailingBytes` (generic decode failures are `MalformedWire`).
#[test]
fn hello_from_bytes_rejects_trailing_bytes() {
    // The golden Hello vector plus one trailing byte.
    let input: [u8; 5] = [0x03, 0x01, 0x02, 0x10, 0x00];
    assert_eq!(
        Hello::from_bytes(&input).expect_err("trailing byte must fail"),
        Error::TrailingBytes { remaining: 1 }
    );
}

/// §10 test 18 — pins that a valid-prefix-but-truncated input is a decode
/// failure (`MalformedWire`), never misreported as `TrailingBytes` (D4).
#[test]
fn decode_exact_truncated_mid_value_is_decode_failure_not_trailing() {
    // Declares 5 bytes, provides 2: truncated mid-value.
    let input: [u8; 3] = [0x05, 1, 2];
    assert_eq!(
        decode_exact::<Bytes8>(&input).expect_err("truncated must fail"),
        Error::MalformedWire
    );
}

// ---------------------------------------------------------------------------
// Structural
// ---------------------------------------------------------------------------

/// §10 test 19 — pins the construction discipline (D1/D2 requirements): no
/// public field, no `Deref`, no `AsRef`, no unchecked constructor. This test
/// constructs exclusively through `new` / `from_slice` / deserialization —
/// the only routes that exist — and reads back exclusively through
/// `as_slice` / `into_inner`. If an unchecked route or a silent slice decay
/// (`Deref` / `AsRef`) were ever added, review of this test's premise fails.
#[test]
fn construction_only_through_validated_paths() {
    let a = Bytes8::new(vec![1, 2, 3]).expect("validated owned construction");
    let b = Bytes8::from_slice(&[1, 2, 3]).expect("validated borrowed construction");
    let c: Bytes8 =
        decode_exact(&postcard::to_allocvec(&a).expect("encode")).expect("validated decode");
    assert_eq!(a, b);
    assert_eq!(a, c);
    assert_eq!(a.as_slice(), &[1, 2, 3]);
    assert_eq!(a.into_inner(), vec![1, 2, 3]);

    let v = Vec8::new(vec![7u16]).expect("validated owned construction");
    let w: Vec8 =
        decode_exact(&postcard::to_allocvec(&v).expect("encode")).expect("validated decode");
    assert_eq!(v, w);
    assert_eq!(v.as_slice(), &[7u16]);
    assert_eq!(v.into_inner(), vec![7u16]);

    // The bound is part of the public diagnostics surface.
    assert_eq!(Bytes8::MAX_LEN, 8);
    assert_eq!(Vec8::MAX_LEN, 8);
}

/// §10 test 20 — pins that `BoundedBytes`'s `Debug` output never contains
/// the byte contents (D1: these carry key and signature bytes in later
/// slices).
#[test]
fn bounded_bytes_debug_hides_contents() {
    let bytes = Bytes8::from_slice(&[222, 222, 222, 222, 222]).expect("within bound");
    let debug = format!("{bytes:?}");
    assert!(
        !debug.contains("222"),
        "Debug output leaked contents: {debug}"
    );
    assert!(
        debug.contains("len"),
        "Debug output should show length: {debug}"
    );
}

/// Pins that `BoundedVec`'s `Debug` output never contains element values
/// (matching `BoundedBytes` length-only hygiene).
#[test]
fn bounded_vec_debug_hides_elements() {
    let vec = Vec8::new(vec![2222, 2222, 2222]).expect("within bound");
    let debug = format!("{vec:?}");
    assert!(
        !debug.contains("2222"),
        "Debug output leaked elements: {debug}"
    );
    assert!(
        debug.contains("len"),
        "Debug output should show length: {debug}"
    );
}
