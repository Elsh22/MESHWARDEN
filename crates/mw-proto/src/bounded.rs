//! Bounded decoding primitives (ADR-017 §Pre-authentication resource bounds).
//!
//! [`BoundedBytes`] and [`BoundedVec`] guarantee a length / element-count
//! upper bound at every construction path, including deserialization. Their
//! decode paths satisfy the ADR-017 §Bounds-before-allocation obligation:
//! allocation growth comes only from bytes actually present in the input,
//! never from an attacker-controlled declared length.
//!
//! [`decode_exact`] is the strict whole-input decode entry point required by
//! ADR-017 §Normative parsing rules rule 1 (reject trailing bytes).
//!
//! # Implementation notes (private)
//!
//! On the pinned postcard (1.1.3), `serde::de::Error::custom` collapses to
//! the payload-free `postcard::Error::SerdeDeCustom`, destroying any typed
//! bound-violation detail raised inside a `Visitor`. A thread-local
//! violation channel, scoped by [`ViolationScope`], carries that detail out
//! of the deserializer. It is an implementation detail of the bounded decode
//! path, never public API.
//!
//! postcard's default `Slice` flavor suppresses a sequence's declared count
//! (`SeqAccess::size_hint` returns `None`) whenever the remaining input is
//! shorter than the declared count. [`OpaqueLenSlice`] wraps `Slice` leaving
//! `Flavor::size_hint` at its default `None`, which makes postcard's
//! `SeqAccess::size_hint` always report the declared count, so the sequence
//! visitor can reject it against `N` before decoding any element. Verified
//! empirically against postcard 1.1.3.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;

use postcard::de_flavors::{Flavor, Slice};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Violation channel (private)
// ---------------------------------------------------------------------------

/// A recorded bound violation: which declared value exceeded which maximum.
#[derive(Debug, Clone, Copy)]
struct Violation {
    declared: usize,
    max: usize,
}

thread_local! {
    /// Single-slot violation channel for the bounded decode path.
    ///
    /// Private to this module; accessed only through [`ViolationScope`] and
    /// [`record_violation`]. Not part of the public API.
    static VIOLATION: Cell<Option<Violation>> = const { Cell::new(None) };

    /// Nesting depth of active [`ViolationScope`] guards on this thread.
    ///
    /// `const`-initialized for the same reason as [`VIOLATION`]: a lazily
    /// initialized thread-local can allocate on first access.
    static SCOPE_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Records a bound violation raised inside a deserialization visitor.
///
/// First violation wins: once a violation is recorded the decode is already
/// failing, and the innermost (first) violation is the actual cause.
fn record_violation(declared: usize, max: usize) {
    VIOLATION.with(|slot| {
        if slot.get().is_none() {
            slot.set(Some(Violation { declared, max }));
        }
    });
}

/// Guard scoping the violation channel to one decode attempt.
///
/// Depth-aware: only the outermost scope clears the channel (on entry and on
/// drop). Inner scopes neither clear nor reset it, so a violation recorded at
/// any nesting depth survives until the outermost scope reads it. Nested
/// [`take`](Self::take) peeks without consuming; only the outermost reader
/// clears the slot.
struct ViolationScope {
    _private: (),
}

impl ViolationScope {
    fn enter() -> Self {
        SCOPE_DEPTH.with(|depth| {
            let next = depth.get().saturating_add(1);
            depth.set(next);
            if next == 1 {
                VIOLATION.with(|slot| slot.set(None));
            }
        });
        Self { _private: () }
    }

    fn take(&self) -> Option<Violation> {
        SCOPE_DEPTH.with(|depth| {
            VIOLATION.with(|slot| {
                if depth.get() <= 1 {
                    slot.take()
                } else {
                    // Nested reader: leave the slot for the outermost scope.
                    slot.get()
                }
            })
        })
    }
}

impl Drop for ViolationScope {
    fn drop(&mut self) {
        SCOPE_DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            if next == 0 {
                VIOLATION.with(|slot| slot.set(None));
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Opaque-length flavor wrapper (private)
// ---------------------------------------------------------------------------

/// Thin [`Flavor`] wrapper over [`Slice`] whose `size_hint` is opaque.
///
/// By leaving [`Flavor::size_hint`] at its default `None`, postcard's
/// `SeqAccess::size_hint` reports the declared element count unconditionally
/// (instead of suppressing it when the remaining input is shorter), letting
/// the [`BoundedVec`] visitor reject an oversized declared count with a typed
/// error before decoding any element.
struct OpaqueLenSlice<'de> {
    inner: Slice<'de>,
}

impl<'de> Flavor<'de> for OpaqueLenSlice<'de> {
    type Remainder = &'de [u8];
    type Source = &'de [u8];

    #[inline]
    fn pop(&mut self) -> postcard::Result<u8> {
        self.inner.pop()
    }

    #[inline]
    fn try_take_n(&mut self, ct: usize) -> postcard::Result<&'de [u8]> {
        self.inner.try_take_n(ct)
    }

    fn finalize(self) -> postcard::Result<&'de [u8]> {
        self.inner.finalize()
    }

    // `size_hint` deliberately NOT delegated: the default `None` is the
    // entire point of this wrapper.
}

// ---------------------------------------------------------------------------
// decode_exact
// ---------------------------------------------------------------------------

/// Decodes `T` from `bytes` and requires that every byte was consumed.
///
/// ADR-017 §Normative parsing rules rule 1: strict decode, reject trailing
/// bytes. A non-empty remainder is [`Error::TrailingBytes`] — distinct from
/// the generic malformed error, separating a framing bug from an attack.
///
/// Bound violations raised by [`BoundedBytes`] / [`BoundedVec`] during the
/// decode surface as typed [`Error::BoundExceeded`]. A decode failure with no
/// recorded violation is the generic [`Error::MalformedWire`] (fail-closed:
/// no specific error is ever inferred from the absence of information).
///
/// Overlong varints are out of scope here; they are caught by the canonical
/// re-encode comparison in the certificate slice (ADR-017 §Normative parsing
/// rules rule 2).
///
/// # Doctrine: opaque size hint
///
/// `decode_exact` deserializes through a flavor wrapper whose `size_hint()`
/// is opaque (always `None`). This is deliberate: it makes postcard's
/// `SeqAccess::size_hint` report the declared element count unconditionally,
/// which is what lets the bounded types see and reject a declared count
/// before decoding elements.
///
/// **Consequence:** the wrapper also removes the incidental clamp postcard's
/// `Slice` flavor provided (suppressing the declared count whenever the
/// remaining input was shorter). The declared count is therefore visible to
/// **every** visitor in the decode, including `serde`'s built-in `Vec` /
/// `String` / map visitors, which preallocate from it (capped at ~1 MiB by
/// `size_hint::cautious`). Any type decoded through `decode_exact` must
/// therefore contain **no field whose `Deserialize` preallocates from
/// `SeqAccess::size_hint`** — in practice, no plain `Vec<T>`, `String`, or
/// map field. Use [`BoundedBytes`] / [`BoundedVec`], or a push-loop visitor
/// that starts from `Vec::new()` and ignores the hint (see
/// `hello::deserialize_algs`).
///
/// # Doctrine: violation channel and async
///
/// The violation channel is a thread-local behind a scoped guard
/// (`ViolationScope`). **It must never be held across an `.await`.**
/// `decode_exact` is synchronous and contains no await points, so this holds
/// today by construction; a future caller that wrapped a decode in an async
/// fn and yielded mid-decode could misattribute a violation across tasks.
/// Noted for the driver slice.
///
/// # Doctrine: `std`-only
///
/// The thread-local makes this module `std`-only. ADR-015 notes postcard's
/// `no_std`/`alloc` fit; if `mw-proto` ever needs `no_std`, this mechanism
/// needs revisiting. Recorded as a known constraint, not a problem to solve
/// now.
pub fn decode_exact<'de, T: serde::Deserialize<'de>>(bytes: &'de [u8]) -> Result<T> {
    let scope = ViolationScope::enter();
    let flavor = OpaqueLenSlice {
        inner: Slice::new(bytes),
    };
    let mut deserializer = postcard::Deserializer::from_flavor(flavor);

    let value = match T::deserialize(&mut deserializer) {
        Ok(value) => value,
        Err(_) => {
            return Err(match scope.take() {
                Some(v) => Error::BoundExceeded {
                    declared: v.declared,
                    max: v.max,
                },
                None => Error::MalformedWire,
            });
        }
    };

    let remaining = deserializer
        .finalize()
        .map_err(|_| Error::MalformedWire)?
        .len();
    if remaining == 0 {
        Ok(value)
    } else {
        Err(Error::TrailingBytes { remaining })
    }
}

// ---------------------------------------------------------------------------
// BoundedBytes
// ---------------------------------------------------------------------------

/// Byte string whose length is guaranteed `<= N` (ADR-017 bounded types).
///
/// Every construction path — [`BoundedBytes::new`],
/// [`BoundedBytes::from_slice`], deserialization — validates against `N`.
/// There is no unchecked path, no `Deref`, and no `AsRef<[u8]>`: access is
/// via [`BoundedBytes::as_slice`] only, so bound-carrying types never
/// silently decay into plain slices.
///
/// `Debug` prints the length, never the contents — these carry key and
/// signature bytes in later slices.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundedBytes<const N: usize> {
    bytes: Vec<u8>,
}

impl<const N: usize> BoundedBytes<N> {
    /// The upper bound, for diagnostics and tests.
    pub const MAX_LEN: usize = N;

    /// Fallible constructor. The only way to build one from owned bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > N {
            return Err(Error::BoundExceeded {
                declared: bytes.len(),
                max: N,
            });
        }
        Ok(Self { bytes })
    }

    /// Fallible constructor from a borrowed slice.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > N {
            return Err(Error::BoundExceeded {
                declared: bytes.len(),
                max: N,
            });
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Exact-length gate for fields whose length is fixed (ADR-017
    /// §Exact-length validation). Returns the slice only if the length is
    /// exactly `expected`.
    pub fn require_exact_len(&self, expected: usize) -> Result<&[u8]> {
        if self.bytes.len() == expected {
            Ok(&self.bytes)
        } else {
            Err(Error::ExactLength {
                expected,
                actual: self.bytes.len(),
            })
        }
    }
}

impl<const N: usize> fmt::Debug for BoundedBytes<N> {
    /// Length only — never the contents (key/signature hygiene, ADR-017).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedBytes")
            .field("len", &self.bytes.len())
            .field("max", &N)
            .finish()
    }
}

impl<const N: usize> Serialize for BoundedBytes<N> {
    /// Byte-identical to serializing the equivalent `&[u8]` (postcard:
    /// varint length + raw bytes).
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.bytes)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedBytes<N> {
    /// Allocation-safe: deserializes via the borrowed-bytes path and
    /// length-checks the borrowed slice **before** copying it to owned
    /// storage (ADR-017 §Bounds-before-allocation obligations 1–3). Never
    /// delegates to `Vec<u8>::deserialize`.
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = BoundedBytes<N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a byte string of at most {N} bytes")
            }

            // postcard's `deserialize_bytes` calls `visit_borrowed_bytes`,
            // whose serde default forwards here: the slice is still the
            // borrowed input, checked before any copy.
            fn visit_bytes<E>(self, v: &[u8]) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() > N {
                    record_violation(v.len(), N);
                    return Err(E::custom("byte string exceeds bound"));
                }
                Ok(BoundedBytes { bytes: v.to_vec() })
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
    }
}

// ---------------------------------------------------------------------------
// BoundedVec
// ---------------------------------------------------------------------------

/// Element sequence whose count is guaranteed `<= N` (ADR-017 bounded types).
///
/// Same construction discipline as [`BoundedBytes`]: every path validates
/// against `N`; no unchecked path, no `Deref`, no `AsRef`.
///
/// `Debug` prints the length and bound, never the elements. Elements are one
/// [`as_slice`](Self::as_slice) call away for legitimate debugging, so hiding
/// costs nothing, while a logged element list cannot be retracted. Today's
/// element types are public data (`u16` capability codes) and nested
/// secret-bearing types carry their own hiding `Debug`, but the policy should
/// not depend on that continuing to be true.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundedVec<T, const N: usize> {
    items: Vec<T>,
}

impl<T, const N: usize> fmt::Debug for BoundedVec<T, N> {
    /// Length only — never the elements (log-hygiene, matching [`BoundedBytes`]).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedVec")
            .field("len", &self.items.len())
            .field("max", &N)
            .finish()
    }
}

impl<T, const N: usize> BoundedVec<T, N> {
    /// The upper bound, for diagnostics and tests.
    pub const MAX_LEN: usize = N;

    /// Fallible constructor. The only way to build one from owned items.
    pub fn new(items: Vec<T>) -> Result<Self> {
        if items.len() > N {
            return Err(Error::BoundExceeded {
                declared: items.len(),
                max: N,
            });
        }
        Ok(Self { items })
    }

    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    pub fn into_inner(self) -> Vec<T> {
        self.items
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<T: Serialize, const N: usize> Serialize for BoundedVec<T, N> {
    /// Byte-identical to serializing the equivalent `Vec<T>` / `&[T]` as a
    /// postcard sequence (varint count + elements).
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.items.len()))?;
        for item in &self.items {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    /// Allocation-safe custom bounded deserialization (ADR-017
    /// §Bounds-before-allocation obligations 1–3):
    ///
    /// - never `Vec::with_capacity` from a declared or hinted length;
    ///   allocation growth comes only from elements actually decoded;
    /// - never delegates to `Vec::<T>::deserialize`;
    /// - when the declared count is observable (`SeqAccess::size_hint`,
    ///   made unconditional by the opaque flavor wrapper in [`decode_exact`]),
    ///   it is rejected against `N` before any element is decoded;
    /// - otherwise rejects as soon as the running count exceeds `N`, without
    ///   decoding the remainder.
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SeqVisitor<T, const N: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for SeqVisitor<T, N> {
            type Value = BoundedVec<T, N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a sequence of at most {N} elements")
            }

            fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Typed early rejection of the declared count, before any
                // element decode or allocation.
                if let Some(declared) = seq.size_hint()
                    && declared > N
                {
                    record_violation(declared, N);
                    return Err(serde::de::Error::custom("sequence exceeds bound"));
                }

                let mut items: Vec<T> = Vec::new();
                while let Some(item) = seq.next_element::<T>()? {
                    if items.len() >= N {
                        // The bound is already full: this element is the
                        // (N+1)th. Reject now; do not decode the remainder.
                        record_violation(items.len().saturating_add(1), N);
                        return Err(serde::de::Error::custom("sequence exceeds bound"));
                    }
                    items.push(item);
                }
                Ok(BoundedVec { items })
            }
        }

        deserializer.deserialize_seq(SeqVisitor(PhantomData))
    }
}
