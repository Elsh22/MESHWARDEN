# ADR-015: Wire serialization codec is postcard

Status: Accepted
Date: 2026-08-07
Phase: Phase 6 (prototype build — surfaced building `mw-proto`)

## Context

`mw-proto` frames are a hand-rolled, length-delimited, big-endian header
(`version | message_type | payload_len`) wrapping an opaque payload. The header
is deliberately not serde-encoded — its layout is fixed and trivial. This ADR
concerns the **payload** codec: how structured payloads (`Hello`, and later task
manifests, work units, leases, results) are turned into bytes, and how the
canonical signing forms in `mw-identity` (e.g. `NodeCertificate`) are produced.

The payload codec is a wire contract, not an implementation detail. In a
partitioned, offline-capable mesh with hours-scale certificates and no central
coordinator, two nodes on different builds must serialize and deserialize the
same structure identically, with no opportunity to renegotiate. An unstable or
non-deterministic format is a silent flag-day across a partition — the exact
failure mode the offline model exists to prevent (OFF, NFR degraded-link).

## Decision

Use **postcard** (serde-based) as the single payload codec for all `mw-proto`
payloads and for the canonical, signed forms in `mw-identity`. The framing
header remains hand-rolled big-endian. `serde` derives already exist on the wire
types; postcard is the concrete format they target.

## Alternatives considered

- **CBOR (`ciborium`)** — self-describing, tolerant of field addition/removal,
  good for cross-language interop. Rejected as the default: self-description
  costs wire bytes on every message, which fights the degraded-link/9.6 kbps
  requirement, and MESHWARDEN is an all-Rust mesh with no non-Rust peer to
  interop with. Its forward-compat strengths are the right reason to revisit
  (see triggers), not to adopt now.
- **`bincode`** — fast and compact, but its wire format is explicitly not a
  stability guarantee across major versions. For a format that must stay stable
  across builds separated by a network partition, that is disqualifying.
- **JSON (`serde_json`)** — human-readable, ubiquitous, but bulky on the wire
  and needless for a machine-to-machine mesh protocol on constrained links.
- **Hand-rolled per-type encoders** — maximal control, but a large, error-prone
  surface across ~16 structures; the agility and versioning discipline is better
  served by one audited codec than sixteen bespoke ones.

postcard wins on the intersection that matters here: compact (varint) output for
constrained links, deterministic encoding (required for signing canonical
forms), pure Rust with `no_std`/`alloc` support that fits aging hardware and the
static-musl gate, and a documented, stable wire format.

## Consequences

- One codec spans both the wire and the canonical signing forms, so a
  `NodeCertificate` signature is over exactly the bytes that travel the wire.
- postcard is **not self-describing**: field order and type are load-bearing,
  and naive struct evolution (reordering, inserting non-tail fields) is a
  breaking change. Schema evolution is carried instead by the `WireVersion`
  major and by `AlgId` tagging on crypto-bearing fields — the version field, not
  the codec, owns forward/backward compatibility.
- Because determinism is relied upon for signatures, any change to how a
  canonical form is built (field set, order, codec) invalidates every signature
  previously produced over it.

## Coupled decisions

- **`WireVersion` (ADR to be numbered) and the algorithm registry
  (`docs/spec/algorithm-registry.md`).** Compatibility rests on the version
  field and on `AlgId` codes serialized as `u16`; the codec assumes both.
- **`mw-identity` canonical certificate form.** Its signatures depend on
  postcard's deterministic output. If this ADR changes, ADR-009's certificate
  handling must be re-derived along with every issued signature's validity.

## Revisit triggers

- A payload genuinely needs self-describing evolution (optional/added fields
  across versions without a flag-day) that postcard cannot express cleanly —
  favor CBOR at that point.
- A non-Rust peer must interoperate on the wire — favor CBOR.
- postcard ships a wire-format-breaking major release, forcing a pinned version
  and a migration plan.

## Traceability

OFF (offline/partition tolerance), NFR degraded-link operation. Relates to
ADR-005, ADR-006, ADR-007, ADR-008. New payload/canonical-form schemas are
defined normatively under `docs/spec/`.

---

## Erratum 1 — 2026-08-07

**Scope:** Documentation correction only. This erratum changes no encoding, no canonical
bytes, no signature, and no golden vector.

**Correction.** This ADR previously stated that the exact bytes covered by a
`NodeCertificate` signature travel on the wire. That statement is inaccurate and is
withdrawn.

The certificate signing canonical form is a private, postcard-encoded representation that
**excludes the issuer signature**. It is therefore not, by itself, a complete transferable
certificate.

The accurate statement is: the complete certificate wire representation transfers every field
required to **deterministically reconstruct** the signing canonical form, together with the
signature algorithm identifier and the signature bytes. A verifier reconstructs the signing
bytes from the transferred fields and verifies the signature against them.

**Unchanged by this erratum:**

- postcard remains the canonical codec;
- the signing canonical form is byte-identical to before;
- all existing certificate golden vectors remain valid and must continue to pass;
- no signature produced before this date is affected.

**Introduced elsewhere:** the complete certificate wire representation
(`certificate_wire_bytes`) is defined by ADR-017 and owned by `mw-identity`.