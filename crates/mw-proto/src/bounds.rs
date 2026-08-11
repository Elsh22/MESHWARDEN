//! Pre-authentication resource bounds (ADR-017).
//!
//! Exactly the bounds this slice needs and no others; later slices add the
//! bounds their own messages use.

/// Maximum size of a complete certificate wire encoding, in bytes.
///
/// Source: ADR-017 §Pre-authentication resource bounds — normative.
pub const MAX_CERTIFICATE_WIRE_BYTES: usize = 2048;

/// Maximum number of entries in `NodeCertificate.capabilities`.
///
/// Source: ADR-017 §Pre-authentication resource bounds — normative. An
/// independent cardinality and resource bound; not derived from the
/// algorithm code space (ADR-017 Revision 4).
pub const MAX_CERT_CAPABILITIES: usize = 64;

/// Maximum size of a signature byte string, in bytes.
///
/// Source: ADR-017 §Pre-authentication resource bounds — normative.
pub const MAX_SIGNATURE_BYTES: usize = 128;

/// Maximum size of a public-key byte string, in bytes.
///
/// Source: maintainer decision, bounded-decode slice. This is a coarse
/// anti-DoS resource bound only, **not** a correctness check: correctness
/// comes from per-algorithm exact-length validation performed via the
/// existing validating constructors in `mw-crypto`, in a later slice.
pub const MAX_PUBLIC_KEY_BYTES: usize = 256;
