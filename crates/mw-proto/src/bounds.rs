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

/// Maximum number of entries in an authentication proof signature list.
///
/// Decode bound only: v1 accepts exactly one signature. The list exists for
/// future dual-signature migration (ADR-017 §Wire messages and signature
/// lists). Arity enforcement belongs to `mw-session`, not decode.
pub const MAX_PROOF_SIGNATURES: usize = 4;

/// Maximum encoded size of an [`crate::AuthInit`] message, in bytes.
pub const MAX_AUTH_INIT_BYTES: usize = 4096;

/// Maximum encoded size of an [`crate::AuthResponse`] message, in bytes.
pub const MAX_AUTH_RESPONSE_BYTES: usize = 4096;

/// Maximum encoded size of an [`crate::AuthConfirm`] message, in bytes.
pub const MAX_AUTH_CONFIRM_BYTES: usize = 1024;

/// Maximum encoded size of an [`crate::AuthTranscriptV1`], in bytes.
///
/// Derived (ADR-017 marks the value derived; arithmetic proven by test):
/// two certificates at [`MAX_CERTIFICATE_WIRE_BYTES`] (2 × 2048) plus exact-
/// length fields (domain 16, channel_binding 32, two node ids 34 each, two
/// nonces 32 each) plus `auth_version` / `auth_algorithm` / `role` and
/// postcard length prefixes. Worst-case encoding is well under 8192; the
/// measured size is pinned by
/// `auth_transcript_worst_case_fits_max_auth_transcript_bytes`.
pub const MAX_AUTH_TRANSCRIPT_BYTES: usize = 8192;

/// Maximum number of entries in `Hello.supported_algs`.
///
/// Independent of [`MAX_CERT_CAPABILITIES`]: Hello advertisement is
/// descriptive/advisory (Amendment 1), while certificate capabilities are
/// attested and identity-bound. Same cardinality (64) for the same anti-DoS
/// profile on a postcard sequence of registry `u16` codes — not an alias,
/// because the quantities are not the same.
pub const MAX_HELLO_ALGS: usize = 64;
