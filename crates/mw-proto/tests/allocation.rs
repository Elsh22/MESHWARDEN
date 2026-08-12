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
//!
//! # Discrimination arithmetic (serde 1.0.229)
//!
//! Every adversarial case must be able to *detect* the failure it targets:
//! a naive implementation that preallocates from the declared count must
//! exceed the threshold. The naive path is `serde`'s built-in `Vec` visitor,
//! whose preallocation on the resolved **serde 1.0.229** is
//! (`src/core/private/size_hint.rs`):
//!
//! ```text
//! cautious::<Element>(hint) = min(hint, 1_048_576 / size_of::<Element>())   [elements]
//! naive_bytes               = cautious * size_of::<Element>()
//! ```
//!
//! Each adversarial test asserts `naive_bytes >= 2 * ADVERSARIAL_PEAK_LIMIT`
//! by reading the declared count from the fixture's leading varint (single
//! source of truth — not a restated constant) and reproducing the formula
//! above. Case comments still record the arithmetic for human readers.
//! **This cap has changed shape across serde versions** — a serde upgrade
//! may invalidate every margin in this file; re-derive them when bumping.
//! The negative-control test demonstrates (rather than argues) that the
//! harness plus the chosen counts detect the naive path.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use mw_proto::{
    AuthConfirm, AuthInit, BoundedBytes, BoundedVec, Error, Hello, MAX_HELLO_ALGS,
    MAX_PROOF_SIGNATURES, decode_exact,
};

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

/// Postcard varint encoding of `usize::MAX` on 64-bit targets (10 bytes).
///
/// Postcard encodes sequence lengths as a varint `usize`. On a 64-bit target
/// `usize::MAX == u64::MAX`, so this is nine continuation bytes `0xFF`
/// followed by a terminating `0x01`. Verified by
/// [`fixture_varint_prefixes_declare_the_intended_counts`] (decoded value)
/// and by every adversarial case that reads the declared count out of these
/// bytes via [`declared_count_from_fixture`].
const ENORMOUS_VARINT: [u8; 10] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

/// Declared count for the moderate-over case and the negative control.
/// Chosen so `naive_bytes = 4096 * size_of::<u16>() = 8192` clears the
/// 4 KiB threshold with a 2× margin (serde 1.0.229 `cautious`).
const MODERATE_DECLARED_COUNT: usize = 4096;

/// Postcard varint prefix of [`MODERATE_DECLARED_COUNT`], verified by
/// [`fixture_varint_prefixes_declare_the_intended_counts`].
const MODERATE_COUNT_VARINT: [u8; 2] = [0x80, 0x20];

// ---------------------------------------------------------------------------
// Discrimination margin (serde 1.0.229 cautious), read from fixture bytes
// ---------------------------------------------------------------------------

/// Reads the leading postcard varint `usize` out of `fixture`.
///
/// The fixture bytes are the single source of truth for the declared count;
/// callers must not restate that count as a separate constant to assert
/// against (that can drift from the bytes it is meant to guard).
fn declared_count_from_fixture(fixture: &[u8]) -> usize {
    let (count, _rest) = postcard::take_from_bytes::<usize>(fixture)
        .expect("fixture must begin with a postcard varint usize");
    count
}

/// Asserts that a naive serde-1.0.229 `cautious` preallocation from this
/// fixture's declared count would clear `2 * ADVERSARIAL_PEAK_LIMIT`.
///
/// Reproduces:
/// ```text
/// naive_elements = min(declared, 1_048_576 / element_size)
/// naive_bytes    = naive_elements * element_size
/// ```
/// Arithmetic uses `u128` and clamps via `min` before multiplying, so a
/// declared count near `usize::MAX` cannot overflow the helper.
fn assert_discrimination_margin(fixture: &[u8], element_size: usize) {
    assert!(
        element_size > 0,
        "element_size must be nonzero (serde cautious divides by it)"
    );
    let declared = declared_count_from_fixture(fixture) as u128;
    let element_size = element_size as u128;
    let max_elements = 1_048_576u128 / element_size;
    let naive_elements = declared.min(max_elements);
    let naive_bytes = naive_elements.saturating_mul(element_size);
    let need = 2u128 * ADVERSARIAL_PEAK_LIMIT as u128;
    assert!(
        naive_bytes >= need,
        "discrimination margin failed: declared {declared}, element_size {element_size}, \
         naive_bytes {naive_bytes}, need >= 2 * ADVERSARIAL_PEAK_LIMIT ({need})"
    );
}

// ---------------------------------------------------------------------------
// Harness self-test, negative control, fixture verification
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

/// Guard: growth via `Vec` reallocation must be visible to the harness.
///
/// The counting allocator overrides only `alloc`/`dealloc` and relies on
/// `GlobalAlloc`'s default `realloc` forwarding through those methods. If
/// `realloc` is ever overridden or forwarded to `System` directly, this test
/// stops observing growth and every allocation assertion in this file has
/// become unreliable.
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
    // Roughly proportional to final size: allow amortized growth overhead,
    // but require the high-water mark to clear a substantial fraction of
    // the final buffer (well above any incidental decode churn).
    assert!(
        peak >= FINAL_LEN / 2,
        "harness peak {peak} not roughly proportional to final Vec size {FINAL_LEN}"
    );
}

/// Negative control: the same moderate adversarial input decoded as a plain
/// `Vec<u16>` (hint-preallocating) through the same `decode_exact` wrapper
/// and the same harness **must** exceed the threshold.
///
/// This proves the harness plus the chosen count actually detect the naive
/// path. If this test ever starts passing under the threshold, either the
/// harness stopped measuring or serde's `cautious` cap changed — in both
/// cases every other assertion in this file has quietly become vacuous.
#[test]
fn negative_control_plain_vec_exceeds_threshold_on_same_input() {
    // Same declared count and prefix as case 2 / Hello moderate path.
    let mut input = MODERATE_COUNT_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| decode_exact::<Vec<u16>>(&input));
    // Decode fails (declared count exceeds remaining bytes), but not before
    // the naive visitor preallocates from the hint.
    assert!(result.is_err(), "truncated enormous declaration must fail");
    assert!(
        peak > ADVERSARIAL_PEAK_LIMIT,
        "negative control failed to observe naive preallocation: peak {peak} bytes \
         (threshold {ADVERSARIAL_PEAK_LIMIT}); harness or serde cautious cap may \
         have changed — every other assertion in this file is then vacuous"
    );
    // Also pin that the observed peak is at least the computed naive_bytes.
    let naive_bytes = MODERATE_DECLARED_COUNT * std::mem::size_of::<u16>();
    assert!(
        peak >= naive_bytes,
        "peak {peak} below expected naive_bytes {naive_bytes}"
    );
}

/// Verify that every hand-computed varint fixture prefix declares the count
/// it claims: moderate and outer-count-1 by encoding a real value of that
/// length, and [`ENORMOUS_VARINT`] by decoding the leading varint (encoding
/// `usize::MAX` elements is infeasible).
///
/// A wrong prefix would declare a different count than intended and the
/// allocation tests could still pass for the wrong reason.
#[test]
fn fixture_varint_prefixes_declare_the_intended_counts() {
    // Moderate declared count 4096.
    let encoded = postcard::to_allocvec(&vec![0u16; MODERATE_DECLARED_COUNT]).expect("encodes");
    assert_eq!(
        &encoded[..MODERATE_COUNT_VARINT.len()],
        &MODERATE_COUNT_VARINT,
        "MODERATE_COUNT_VARINT must be the postcard prefix of a {MODERATE_DECLARED_COUNT}-element Vec<u16>"
    );
    assert_eq!(
        declared_count_from_fixture(&MODERATE_COUNT_VARINT),
        MODERATE_DECLARED_COUNT
    );

    // Outer-count-1 prefix used by the nested-inner case.
    let one = postcard::to_allocvec(&vec![0u16; 1]).expect("encodes");
    assert_eq!(&one[..1], &[0x01], "outer count 1 must encode as 0x01");

    // ENORMOUS_VARINT: postcard encodes sequence lengths as varint usize.
    // On a 64-bit target the intended value is usize::MAX (== u64::MAX).
    assert_eq!(
        usize::MAX,
        u64::MAX as usize,
        "ENORMOUS_VARINT verification assumes a 64-bit target (usize::MAX == u64::MAX)"
    );
    assert_eq!(
        declared_count_from_fixture(&ENORMOUS_VARINT),
        usize::MAX,
        "ENORMOUS_VARINT must decode as usize::MAX on this target"
    );

    // Discrimination arithmetic for nested outer depends on the element size.
    // BoundedBytes<N> is a single Vec<u8> (no extra fields); pin that.
    assert_eq!(
        std::mem::size_of::<BoundedBytes<4>>(),
        std::mem::size_of::<Vec<u8>>(),
        "nested-outer naive_bytes arithmetic assumes BoundedBytes<4> == Vec<u8>"
    );
    assert_eq!(
        std::mem::size_of::<BoundedBytes<4>>(),
        24,
        "nested-outer margin comment assumes 24-byte BoundedBytes on this target"
    );
}

// ---------------------------------------------------------------------------
// Adversarial cases — assert both the error and the peak allocation
// ---------------------------------------------------------------------------

/// Case 1 — `BoundedVec`, tiny input declaring a count near `u64::MAX`.
///
/// Discrimination: declared `u64::MAX`, element `u16` (2 bytes) →
/// `naive_bytes = min(u64::MAX, 1_048_576 / 2) * 2 = 1_048_576` vs
/// threshold 4_096 → margin 256x.
#[test]
fn bounded_vec_enormous_declared_count_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u16>());
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
///
/// Discrimination: declared 4_096, element `u16` (2 bytes) →
/// `naive_bytes = min(4_096, 524_288) * 2 = 8_192` vs threshold 4_096 →
/// margin 2x. The previous count here was 1_000, whose `naive_bytes` of
/// 2_000 sat *under* the threshold, so a hint-preallocating implementation
/// would have passed — the count was raised (never the threshold) to make
/// the case discriminate.
#[test]
fn bounded_vec_moderate_over_declared_count_allocates_nothing_large() {
    // Declared count 4096 as a postcard varint (prefix verified by
    // `fixture_varint_prefixes_declare_the_intended_counts`), one stray byte.
    assert_discrimination_margin(&MODERATE_COUNT_VARINT, std::mem::size_of::<u16>());
    let mut input = MODERATE_COUNT_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| decode_exact::<Vec8>(&input));
    assert_eq!(
        result.expect_err("count 4096 must fail"),
        Error::BoundExceeded {
            declared: MODERATE_DECLARED_COUNT,
            max: 8
        }
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// Case 3 — `BoundedBytes`, tiny input declaring an enormous byte length.
///
/// Discrimination: declared `u64::MAX`, naive counterpart `Vec<u8>`
/// (element 1 byte) → `naive_bytes = min(u64::MAX, 1_048_576) * 1 =
/// 1_048_576` vs threshold 4_096 → margin 256x.
#[test]
fn bounded_bytes_enormous_declared_len_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u8>());
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
///
/// Discrimination: declared `u64::MAX`, element `BoundedBytes<4>` (one
/// `Vec<u8>`, 24 bytes on 64-bit; size pinned by
/// `fixture_varint_prefixes_declare_the_intended_counts`) →
/// `naive_bytes = min(u64::MAX, 1_048_576 / 24) * 24 = 43_690 * 24 =
/// 1_048_560` vs threshold 4_096 → margin 255x.
#[test]
fn nested_enormous_outer_declaration_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<BoundedBytes<4>>());
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
///
/// Discrimination: the inner declaration is the attack, so the naive
/// counterpart is the inner field as `Vec<u8>` (element 1 byte): declared
/// `u64::MAX` → `naive_bytes = min(u64::MAX, 1_048_576) * 1 = 1_048_576`
/// vs threshold 4_096 → margin 256x.
#[test]
fn nested_enormous_inner_declaration_allocates_nothing_large() {
    // Outer count 1 (within bound), inner byte length u64::MAX, 1 stray byte.
    // Margin guards the *inner* declaration (the attack), read from its own
    // fixture bytes — not the outer `0x01` prefix.
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u8>());
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
///
/// Discrimination: declared `u64::MAX`, element `u16` (2 bytes) →
/// `naive_bytes = min(u64::MAX, 524_288) * 2 = 1_048_576` vs threshold
/// 4_096 → margin 256x. This count was **never under-powered** (unlike the
/// previous moderate BoundedVec count of 1_000). Re-measured after the
/// discrimination fix: peak after rework = 8 bytes; peak before rework
/// (slice 1b report) = 1_048_576 bytes. Meaningful delta unchanged.
#[test]
fn hello_enormous_declared_alg_count_allocates_nothing_large() {
    // Declared algorithm count u64::MAX, one valid algorithm code byte.
    // After Slice 3, Hello uses BoundedVec<u16, MAX_HELLO_ALGS>, so the typed
    // rejection is BoundExceeded (not MalformedPayload).
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u16>());
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x01);
    let (result, peak) = peak_alloc_of(|| Hello::from_bytes(&input));
    assert_eq!(
        result.expect_err("enormous algorithm count must fail"),
        Error::BoundExceeded {
            declared: u64::MAX as usize,
            max: MAX_HELLO_ALGS
        }
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// §9.20 — AuthConfirm with an enormous declared signature count.
///
/// Discrimination: declared `u64::MAX`, element `WireSignature` is larger than
/// `u16`; naive counterpart uses the outer sequence element as if it were a
/// plain `Vec` of a pointer-sized struct. We guard the declared count the
/// same way as BoundedVec<u16>: element size of a struct containing `u16` +
/// `Vec<u8>` is at least `size_of::<u16>()`, and the fixture's declared count
/// still clears 2× threshold under the cautious formula for `u16` (2 bytes).
/// Using `size_of::<u16>()` keeps the margin arithmetic consistent with other
/// sequence cases; the real WireSignature is larger, so naive bytes would be
/// even bigger.
#[test]
fn auth_confirm_enormous_declared_signature_count_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u16>());
    let mut input = ENORMOUS_VARINT.to_vec();
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| AuthConfirm::from_bytes(&input));
    assert_eq!(
        result.expect_err("enormous signature count must fail"),
        Error::BoundExceeded {
            declared: u64::MAX as usize,
            max: MAX_PROOF_SIGNATURES
        }
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}

/// §9.20 — AuthInit with an enormous declared certificate length.
///
/// Discrimination: declared `u64::MAX`, element `u8` → naive_bytes = 1 MiB.
/// Mirrors `bounded_bytes_enormous_declared_len_allocates_nothing_large`:
/// when remaining input is shorter than the declaration, postcard fails
/// before `visit_bytes`, yielding [`Error::MalformedWire`].
#[test]
fn auth_init_enormous_declared_certificate_len_allocates_nothing_large() {
    assert_discrimination_margin(&ENORMOUS_VARINT, std::mem::size_of::<u8>());
    let mut input = vec![0x01u8, 0x20];
    input.extend_from_slice(&[0x11; 32]);
    input.extend_from_slice(&ENORMOUS_VARINT);
    input.push(0x00);
    let (result, peak) = peak_alloc_of(|| AuthInit::from_bytes(&input));
    assert_eq!(
        result.expect_err("enormous certificate length must fail"),
        Error::MalformedWire
    );
    assert!(
        peak <= ADVERSARIAL_PEAK_LIMIT,
        "peak {peak} bytes exceeds limit {ADVERSARIAL_PEAK_LIMIT}"
    );
}
