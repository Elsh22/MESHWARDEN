//! Peak-allocation proofs for the bounded decode path (ADR-017
//! §Bounds-before-allocation obligation).
//!
//! The adversarial tests in `tests/bounded.rs` assert the returned *error
//! type*, which proves rejection occurred but not that nothing large was
//! allocated on the way. ADR-017's obligation is about allocation, so these
//! tests observe allocation directly through a counting global allocator.
//!
//! The allocator lives in this integration-test file so it applies only to
//! this test binary — never to the library or to other test binaries.
//!
//! # Measurement mode
//!
//! The harness records **peak live bytes** (high-water mark of
//! allocated-minus-freed), not cumulative bytes requested. A preallocation
//! from an attacker-controlled declared count manifests as a single large
//! live allocation, which peak-live captures exactly; cumulative counting
//! would also accumulate benign short-lived churn and make thresholds
//! mushier for no gain.
//!
//! Counters are **thread-local**, not process-global: the integration test
//! binary runs tests on parallel threads, and a process-wide counter would
//! be polluted by unrelated tests. Only allocation on the measuring test's
//! own thread matters. The thread-locals are `const`-initialized so that
//! first access inside `alloc` cannot itself allocate (a lazily-initialized
//! thread-local can, which would recurse through the allocator).

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use mw_proto::{BoundedBytes, BoundedVec, Error, Hello, decode_exact};

// ---------------------------------------------------------------------------
// Counting allocator
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
// Threshold
// ---------------------------------------------------------------------------

/// Peak-allocation ceiling for an adversarial (rejected) decode: 4 KiB.
///
/// Reasoning: a rejected bounded decode legitimately allocates at most a few
/// dozen bytes (small `Vec` growth for elements decoded before rejection,
/// error values). 4 KiB is generous headroom over that — the tests must
/// catch a *preallocation from a declared count*, not measure precisely —
/// while sitting 256x below the ~1 MiB `serde` `size_hint::cautious`
/// preallocation cap and far below anything proportional to an enormous
/// declared count. A regression to hint-driven preallocation cannot slip
/// under it.
const ADVERSARIAL_PEAK_LIMIT: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// Shared shapes and inputs (mirroring tests/bounded.rs)
// ---------------------------------------------------------------------------

type Bytes8 = BoundedBytes<8>;
type Vec8 = BoundedVec<u16, 8>;
type Nested = BoundedVec<BoundedBytes<4>, 8>;

/// Postcard varint encoding of `u64::MAX` (10 bytes) — a declared
/// length/count near `usize::MAX` on 64-bit targets.
const ENORMOUS_VARINT: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

// ---------------------------------------------------------------------------
// Harness self-test
// ---------------------------------------------------------------------------

/// A deliberate 4 MiB allocation inside the scope must be observed to exceed
/// the threshold. A harness that always reported zero would make every other
/// test in this file vacuous, and that failure mode is silent — this test
/// makes it loud.
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

// ---------------------------------------------------------------------------
// Adversarial cases — assert both the error and the peak allocation
// ---------------------------------------------------------------------------

/// Case 1 — `BoundedVec`, tiny input declaring a count near `u64::MAX`.
#[test]
fn bounded_vec_enormous_declared_count_allocates_nothing_large() {
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| decode_exact::<Vec8>(&input));
    assert_eq!(
        result.expect_err("enormous count must fail"),
        Error::BoundExceeded {
            declared: u64::MAX as usize,
            max: 8
        }
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 2 — `BoundedVec`, tiny input declaring a count comfortably above
/// `N` (8) but far below `u64::MAX`.
#[test]
fn bounded_vec_moderate_over_declared_count_allocates_nothing_large() {
    // Declared count 1000 as a postcard varint, one stray byte of "input".
    let input = [0xE8u8, 0x07, 0x00];
    let (result, peak) = peak_alloc_of(|| decode_exact::<Vec8>(&input));
    assert_eq!(
        result.expect_err("count 1000 must fail"),
        Error::BoundExceeded {
            declared: 1000,
            max: 8
        }
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 3 — `BoundedBytes`, tiny input declaring an enormous byte length.
#[test]
fn bounded_bytes_enormous_declared_len_allocates_nothing_large() {
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| decode_exact::<Bytes8>(&input));
    assert_eq!(
        result.expect_err("enormous length must fail"),
        Error::MalformedWire
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 4 — nested `BoundedVec<BoundedBytes<4>, 8>`, enormous **outer**
/// declaration.
#[test]
fn nested_enormous_outer_declaration_allocates_nothing_large() {
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| decode_exact::<Nested>(&input));
    assert_eq!(
        result.expect_err("enormous outer count must fail"),
        Error::BoundExceeded {
            declared: u64::MAX as usize,
            max: 8
        }
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 5 — nested `BoundedVec<BoundedBytes<4>, 8>`, enormous **inner**
/// declaration.
#[test]
fn nested_enormous_inner_declaration_allocates_nothing_large() {
    // Outer count 1 (within bound), inner byte length u64::MAX, 1 stray byte.
    let mut input = vec![0x01u8];
    input.extend_from_slice(&ENORMOUS_VARINT);
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| decode_exact::<Nested>(&input));
    assert_eq!(
        result.expect_err("enormous inner length must fail"),
        Error::MalformedWire
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 6 — valid at-bound values of each type decode with peak allocation
/// proportional to the actual value. This confirms the harness sees the
/// decode's real allocations and that the adversarial thresholds are not so
/// loose as to be meaningless: a genuine decode registers nonzero,
/// value-sized peaks well within the same limit.
#[test]
fn valid_at_bound_decodes_show_proportional_allocation() {
    // BoundedBytes<8> at bound: the decoded value owns 8 bytes.
    let input = postcard::to_allocvec(&Bytes8::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap())
        .expect("encode");
    let (result, peak) = peak_alloc_of(|| decode_exact::<Bytes8>(&input));
    assert_eq!(result.expect("at-bound decode must succeed").len(), 8);
    assert!(peak >= 8, "peak {peak} smaller than the decoded value");
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );

    // BoundedVec<u16, 8> at bound: the decoded value owns 8 * 2 bytes.
    let input =
        postcard::to_allocvec(&Vec8::new(vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap()).expect("encode");
    let (result, peak) = peak_alloc_of(|| decode_exact::<Vec8>(&input));
    assert_eq!(result.expect("at-bound decode must succeed").len(), 8);
    assert!(peak >= 16, "peak {peak} smaller than the decoded value");
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );

    // Nested at both bounds: 8 elements owning 4 bytes each.
    let elems: Vec<BoundedBytes<4>> = (0..8)
        .map(|i| BoundedBytes::<4>::from_slice(&[i; 4]).unwrap())
        .collect();
    let input = postcard::to_allocvec(&Nested::new(elems).unwrap()).expect("encode");
    let (result, peak) = peak_alloc_of(|| decode_exact::<Nested>(&input));
    assert_eq!(result.expect("at-bound decode must succeed").len(), 8);
    assert!(peak >= 32, "peak {peak} smaller than the decoded contents");
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 7 — `Hello::from_bytes` with a tiny input declaring an enormous
/// algorithm count.
///
/// This is the E2 regression case: before the `deserialize_algs` rework,
/// delegation to `Vec::<u16>::deserialize` preallocated ~1 MiB from the
/// declared count via `serde`'s `size_hint::cautious` (the opaque flavor
/// wrapper in `decode_exact` makes the declared count visible to every
/// visitor, removing the incidental clamp postcard's `Slice` flavor
/// provided). After the rework, growth comes only from bytes actually
/// present.
#[test]
fn hello_enormous_declared_alg_count_allocates_nothing_large() {
    // Declared algorithm count u64::MAX, one valid algorithm code byte.
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x01);
    let (result, peak) = peak_alloc_of(|| Hello::from_bytes(&input));
    assert_eq!(
        result.expect_err("enormous algorithm count must fail"),
        Error::MalformedPayload
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}
