//! Peak-allocation proofs for `NodeCertificate::from_wire_bytes`
//! (ADR-017 §Bounds-before-allocation obligation).
//!
//! The bounded primitives in `mw-proto` were built for this decoder. These
//! tests prove the property at the certificate level rather than inheriting
//! it by argument.
//!
//! Harness design is deliberately duplicated from
//! `crates/mw-proto/tests/allocation.rs` (accepted for this slice — no shared
//! dev-dependency crate). Same rules: `System`-wrapping counting allocator,
//! `const`-initialized thread-local counters, no allocation or formatting
//! inside `alloc` / `dealloc`, scoped reset-run-measure helper.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use mw_crypto::{AlgId, Signature};
use mw_identity::{CertificateWireField, Error, NodeCertificate, NodeId};
use mw_proto::{MAX_CERT_CAPABILITIES, MAX_PUBLIC_KEY_BYTES};

// ---------------------------------------------------------------------------
// Counting allocator (duplicated from mw-proto/tests/allocation.rs)
// ---------------------------------------------------------------------------

thread_local! {
    /// Live bytes currently allocated on this thread.
    static LIVE: Cell<usize> = const { Cell::new(0) };
    /// High-water mark of `LIVE` since the current measurement scope began.
    static PEAK: Cell<usize> = const { Cell::new(0) };
}

/// Global allocator wrapping [`System`], counting per-thread peak live bytes.
///
/// Must not allocate, format, or panic inside `alloc`/`dealloc`: counter
/// access uses `const`-initialized thread-locals via `try_with` (never
/// panics, even during thread teardown), and does nothing else.
struct CountingAlloc;

// `realloc` and `alloc_zeroed` are deliberately not overridden. `GlobalAlloc`'s
// default `realloc` routes through `self.alloc` / `self.dealloc`, and default
// `alloc_zeroed` routes through `self.alloc`, so reallocation-driven growth is
// counted. Forwarding either to `System` directly would bypass the counters
// and blind every allocation assertion in this file silently.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract; the
        // layout is forwarded to `System` unchanged.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let _ = LIVE.try_with(|live| {
                let now = live.get().saturating_add(layout.size());
                live.set(now);
                let _ = PEAK.try_with(|peak| {
                    if now > peak.get() {
                        peak.set(now);
                    }
                });
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(layout.size())));
        // SAFETY: the caller upholds `GlobalAlloc::dealloc`'s contract; the
        // pointer and layout are forwarded to `System` unchanged.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// Runs `f` and returns its result together with the peak live-byte growth
/// observed on this thread during the call (peak minus the baseline at
/// entry).
fn peak_alloc_of<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let baseline = LIVE.with(Cell::get);
    PEAK.with(|peak| peak.set(baseline));
    let result = f();
    let peak = PEAK.with(Cell::get);
    (result, peak.saturating_sub(baseline))
}

// ---------------------------------------------------------------------------
// Threshold and discrimination helpers (same discipline as mw-proto)
// ---------------------------------------------------------------------------

/// Peak-allocation ceiling for an adversarial (rejected) decode: 4 KiB.
const ADVERSARIAL_PEAK_LIMIT: usize = 4 * 1024;

/// Postcard varint encoding of `usize::MAX` on 64-bit targets (10 bytes).
const ENORMOUS_VARINT: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

/// Valid `NodeId` postcard prefix (`mw:node:ALKETIY7XMTHZDZVF2MWRJ46HY`),
/// taken from the wire golden vector's leading subject field.
fn subject_prefix() -> Vec<u8> {
    let id = NodeId::from_public_key_bytes(&[0x11u8; 32]);
    postcard::to_allocvec(&id).expect("NodeId encodes")
}

fn declared_count_from_fixture(fixture: &[u8]) -> usize {
    let (count, _rest) = postcard::take_from_bytes::<usize>(fixture)
        .expect("fixture must begin with a postcard varint usize");
    count
}

fn assert_discrimination_margin(fixture: &[u8], element_size: usize) {
    assert!(element_size > 0);
    let declared = declared_count_from_fixture(fixture) as u128;
    let element_size = element_size as u128;
    let max_elements = 1_048_576u128 / element_size;
    let naive_elements = declared.min(max_elements);
    let naive_bytes = naive_elements.saturating_mul(element_size);
    let need = 2u128 * ADVERSARIAL_PEAK_LIMIT as u128;
    assert!(
        naive_bytes >= need,
        "discrimination margin failed: declared {declared}, element_size {element_size}, \
         naive_bytes {naive_bytes}, need >= {need}"
    );
}

// ---------------------------------------------------------------------------
// Harness self-tests
// ---------------------------------------------------------------------------

#[test]
fn harness_self_test_observes_deliberate_large_allocation() {
    let (_, peak) = peak_alloc_of(|| {
        let v = Vec::<u8>::with_capacity(4 * 1024 * 1024);
        std::hint::black_box(v)
    });
    assert!(
        peak >= 4 * 1024 * 1024,
        "harness failed to observe a deliberate 4 MiB allocation: peak {peak} bytes"
    );
    assert!(peak > ADVERSARIAL_PEAK_LIMIT);
}

#[test]
fn harness_self_test_observes_realloc_growth() {
    const FINAL_LEN: usize = 64 * 1024;
    let (len, peak) = peak_alloc_of(|| {
        let mut v = Vec::<u8>::new();
        for i in 0..FINAL_LEN {
            v.push(i as u8);
        }
        let len = v.len();
        std::hint::black_box(v);
        len
    });
    assert_eq!(len, FINAL_LEN);
    assert!(
        peak > 0,
        "harness observed no allocation during realloc growth: peak {peak} bytes; \
         realloc may have been overridden or forwarded — every allocation \
         assertion in this file is then unreliable"
    );
    assert!(
        peak >= FINAL_LEN / 2,
        "harness peak {peak} not roughly proportional to final Vec size {FINAL_LEN}"
    );
}

#[test]
fn enormous_varint_decodes_as_usize_max_on_64_bit() {
    assert_eq!(usize::MAX, u64::MAX as usize, "64-bit assumption");
    assert_eq!(declared_count_from_fixture(&ENORMOUS_VARINT), usize::MAX);
}

// ---------------------------------------------------------------------------
// Certificate-level adversarial cases
// ---------------------------------------------------------------------------

#[test]
fn enormous_declared_capability_count_allocates_nothing_large() {
    // subject || empty public_key || enormous capability count
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u16>());
    let mut input = subject_prefix();
    input.push(0x00); // public_key length 0
    input.extend_from_slice(&ENORMOUS_VARINT);
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| NodeCertificate::from_wire_bytes(&input));
    let err = result.expect_err("enormous capability count must fail");
    assert!(
        matches!(
            err,
            Error::Wire(mw_proto::Error::BoundExceeded {
                max: MAX_CERT_CAPABILITIES,
                ..
            })
        ),
        "expected BoundExceeded on capabilities, got {err:?}"
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
    eprintln!(
        "alloc_case=capabilities declared={} esz={} peak={} err={err:?}",
        declared_count_from_fixture(&ENORMOUS_VARINT),
        std::mem::size_of::<u16>(),
        peak
    );
}

#[test]
fn enormous_declared_public_key_length_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, 1);
    let mut input = subject_prefix();
    input.extend_from_slice(&ENORMOUS_VARINT);
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| NodeCertificate::from_wire_bytes(&input));
    let err = result.expect_err("enormous public_key length must fail");
    // Tiny input: postcard cannot take the declared bytes → MalformedWire
    // (bound check on BoundedBytes only runs after a successful borrow).
    assert!(
        matches!(err, Error::Wire(mw_proto::Error::MalformedWire)),
        "expected MalformedWire for truncated enormous pk declaration, got {err:?}"
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
    eprintln!(
        "alloc_case=public_key declared={} esz=1 peak={} err={err:?}",
        declared_count_from_fixture(&ENORMOUS_VARINT),
        peak
    );
}

#[test]
fn enormous_declared_signature_length_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, 1);
    // Minimal prefix through signature_algorithm, then enormous sig length.
    let subject = subject_prefix();
    let mut input = subject;
    input.push(0x00); // empty public_key
    input.push(0x00); // zero capabilities
    input.push(0x00); // valid_from = 0
    input.push(0x00); // valid_until = 0
    input.extend_from_slice(&subject_prefix()); // issuer (same shape)
    input.push(0x01); // signature_algorithm = Ed25519
    input.extend_from_slice(&ENORMOUS_VARINT);
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| NodeCertificate::from_wire_bytes(&input));
    let err = result.expect_err("enormous signature length must fail");
    assert!(
        matches!(err, Error::Wire(mw_proto::Error::MalformedWire)),
        "expected MalformedWire for truncated enormous sig declaration, got {err:?}"
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
    eprintln!(
        "alloc_case=signature declared={} esz=1 peak={} err={err:?}",
        declared_count_from_fixture(&ENORMOUS_VARINT),
        peak
    );
}

#[test]
fn enormous_declared_subject_string_length_allocates_nothing_large() {
    // NodeId::Deserialize borrows via visit_str; a naive String visitor would
    // preallocate from the declared length (element size 1).
    assert_discrimination_margin(&ENORMOUS_VARINT, 1);
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| NodeCertificate::from_wire_bytes(&input));
    let err = result.expect_err("enormous subject string length must fail");
    assert!(
        matches!(err, Error::Wire(mw_proto::Error::MalformedWire)),
        "expected MalformedWire for truncated enormous subject declaration, got {err:?}"
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
    eprintln!(
        "alloc_case=subject declared={} esz=1 peak={} err={err:?}",
        declared_count_from_fixture(&ENORMOUS_VARINT),
        peak
    );
}

#[test]
fn to_wire_bytes_megabyte_public_key_allocates_no_encoding() {
    // The deleted unbounded-encode preference arm would postcard-encode the
    // out-of-bound public_key (~1 MiB) before returning WireTooLarge. Field
    // checks reject without constructing a DTO or encoding.
    let subject = NodeId::from_public_key_bytes(&[0x11u8; 32]);
    let issuer = NodeId::from_public_key_bytes(&[0x22u8; 32]);
    // Allocate the oversized field outside the measurement window.
    let cert = NodeCertificate {
        subject,
        public_key: vec![0x11u8; 1024 * 1024],
        capabilities: vec![AlgId::Ed25519.as_u16()],
        valid_from: 1_000,
        valid_until: 2_000,
        issuer,
        signature: Signature {
            alg: AlgId::Ed25519,
            bytes: vec![0xABu8; 64],
        },
    };
    // Declared size read from the certificate — never restated below.
    let declared = cert.public_key.len();
    assert!(
        declared > MAX_PUBLIC_KEY_BYTES,
        "fixture must be over the public_key bound"
    );
    let need = 2 * ADVERSARIAL_PEAK_LIMIT;
    assert!(
        declared >= need,
        "discrimination margin failed: declared {declared}, need >= {need}"
    );

    let (result, peak) = peak_alloc_of(|| cert.to_wire_bytes());
    let err = result.expect_err("1 MiB public_key must fail encode");
    assert!(
        matches!(
            err,
            Error::FieldBoundExceeded {
                field: CertificateWireField::PublicKey,
                len,
                max: MAX_PUBLIC_KEY_BYTES,
            } if len == declared
        ),
        "expected FieldBoundExceeded(PublicKey), got {err:?}"
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}; \
         encode may have materialised the out-of-bound field"
    );
    eprintln!("alloc_case=to_wire_public_key declared={declared} esz=1 peak={peak} err={err:?}");
}
