# ADR-017: Mesh Identity Authentication and TLS Channel Binding

- **Status:** Accepted
- **Date:** 2026-08-07
- **Revision:** 4

### Revision history

| Rev | Change |
|---|---|
| 1 | Initial draft — handshake-level versus application-layer identity evaluation |
| 2 | Post-review redraft: ADR-015 preservation, certificate wire format, negotiation removed, honest `Unauthenticated<S>` characterisation, manifest-level dependency gates |
| 3 | Maintainer decisions on Q1–Q5 plus eight mandatory corrections: bounded types replacing fixed-size cryptographic arrays, signature lists, `auth_algorithm`, `AuthMachine`/driver split, single pre-authentication buffering rule, bounds-before-allocation obligation, message-code allocation |
| **4** | **Corrected before first commit; no repository history affected.** (a) Algorithm-allocation wording: `0x0001`–`0x003F` is the current **block layout**, not the allocated set, and `MAX_CERT_CAPABILITIES = 64` is an **independent cardinality bound** with no relationship to the code space. (b) Added *Relationship to `WireVersion.major`*, clarifying the three version axes and deferring wire compatibility to ADR-015. **No normative security decision changed.** |

- **Depends on:** ADR-008 (identity-bound capabilities), ADR-015 (postcard canonical encoding, as amended by Erratum 1), ADR-016 (pure-Rust rustls provider)
- **Builds on:** commit `b1911bd` (certificate self-consistency)
- **Governed by:** `.cursor/rules/crypto-boundary.mdc`

---

## Context

Transport slice 1 established TLS 1.3 over `tokio::io::duplex` using `rustls` 0.23.43 with
the `rustls-rustcrypto` 0.0.2-alpha provider and `tokio-rustls` 0.26.4, wrapped in an
`Unauthenticated<S>` marker. The channel is confidential but carries no mesh identity.

`mw-identity` enforces certificate self-consistency: `subject == NodeId(public_key)` on both
sign and verify, with `IssuerKeyMismatch` returned before signature verification.
`NodeCertificate` carries `subject`, `public_key`, `capabilities: Vec<AlgId>`, `valid_from`,
`valid_until`, `issuer`, and an algorithm-tagged signature. Its signing canonical form is
private, postcard-encoded, and excludes the signature.

`NodeId` has an internal fixed 16-byte SHA-256 prefix and a canonical representation of
exactly 34 ASCII characters: `mw:node:` followed by 26 Base32 characters.

This ADR decides how mesh identity binds to the TLS session.

### Verified capability (exporter spike, closed)

A non-committing capability spike on the pinned stack established:

- `export_keying_material` succeeds immediately after both handshake futures resolve.
- Client and server derive identical 32-byte output for the same session, label, and context.
- Repeated export with identical inputs is deterministic.
- Independent sessions derive different output; different labels derive different output.
- `context = None` and `context = Some(b"")` are **identical**, matching RFC 8446 §7.5.
- Reachable through existing public surface:
  `unauth.get_ref().get_ref().1.export_keying_material(...)`
- Both observed handshakes were full TLS 1.3 using `TLS13_AES_128_GCM_SHA256`.

**Spike scope limitation:** only full handshakes were observed. Exporter behavior under a
resumed TLS 1.3 session was not tested.

### Forces

- ADR-016 is hard; `rustls-rustcrypto` is experimental and must not constrain mesh identity.
- ADR-015 fixes postcard as the canonical codec; a second codec is unacceptable.
- ADR-008 prohibits unbound capability assertions.
- `.cursor/rules/crypto-boundary.mdc` prohibits fixed-size cryptographic arrays in wire and
  spec structures, and requires signature **lists** on new signable protocol objects.
- No ambient clock: every time-dependent validation receives `now` explicitly.
- DDIL: unpredictable partitions; no assumption of CA reachability.
- Zero trust: a valid connection conveys no trust.

---

## Decision

MESHWARDEN authenticates mesh identity at the **application layer**, after TLS 1.3
completes, using mutually exchanged signed proofs bound to the session via an RFC 8446 §7.5
exporter value.

TLS provides confidentiality and integrity only. Mesh identity, capability binding, and peer
authentication are MESHWARDEN concerns and are never delegated to the TLS certificate layer.

### Channel binding

| Parameter | Value |
|---|---|
| Mechanism | RFC 8446 §7.5 TLS exporter via `rustls` `export_keying_material` |
| Label | `EXPERIMENTAL-MESHWARDEN-AUTH-v1` |
| Context | always `None` |
| Length | exactly 32 bytes |
| TLS version | 1.3 only |

**Domain separation operates at two levels, both intentional:**

- **Exporter-level** domain separation lives in the **versioned exporter label**. A `-v2`
  label yields a cryptographically unrelated binding value, so a v1 proof can never validate
  in a v2 session.
- **Signature-level** domain separation additionally lives in the **versioned
  `AuthTranscriptV1` domain field**, which separates MESHWARDEN authentication signatures
  from every other signature the system produces.

Context is unconditionally `None` because RFC 8446 §7.5 makes no distinction between an
absent and an empty context in TLS 1.3 — confirmed empirically on the pinned stack. Placing
separation in the context would create ambiguity with no benefit.

The `EXPERIMENTAL` prefix is permitted for unregistered use per RFC 5705 §4. IANA
registration is a proposal-phase item.

**RFC 9266 `EXPORTER-Channel-Binding` is deliberately not used.** That value is designed to
be *shared* across consumers of one TLS connection — the opposite of the separation required
here — and carries no protocol version.

### Status of the exporter value

The exporter output is **channel-binding material, not a key.**

- Derived from TLS secrets via HKDF. **Its disclosure does not compromise TLS channel
  secrets** (RFC 9266 security considerations). This ADR makes no contrary claim.
- **Never transmitted** in this protocol; covered by signatures only.
- **Must not** be used as an encryption key, MAC key, or general-purpose secret.
- **Should not** be logged, printed, or persisted — operational hygiene, not an RFC
  requirement.
- A redacted `Debug` representation is reasonable. **Zeroization is optional hygiene and is
  explicitly not a condition of RFC compliance**; adopting it requires separate
  justification.

MITM resistance does not rest on secrecy — both endpoints necessarily know the value. It
rests on a relaying attacker terminating two *different* TLS sessions with two *different*
exporter values, and being unable to produce a peer signature over the other session's value.

---

## Certificate representations

Two byte forms, never interchanged:

| Form | Contents | Owner | Status |
|---|---|---|---|
| `certificate_signing_bytes` | postcard encoding of `subject`, `public_key`, `capabilities`, `valid_from`, `valid_until`, `issuer` — **excludes signature** | `mw-identity`, private | **Unchanged by this ADR** |
| `certificate_wire_bytes` | postcard encoding of the complete certificate **including** signature algorithm identifier and signature bytes | `mw-identity`, public | **New** |

`mw-identity` gains `NodeCertificate::to_wire_bytes()` and `::from_wire_bytes()`.
`certificate_signing_bytes` remains private and byte-identical to today; **existing golden
vectors must continue to pass unchanged.**

**`mw-proto` carries certificate bytes opaquely** as a bounded byte vector. It does not parse
them and does not depend on `mw-identity`.

### Normative parsing rules

1. **Strict decode** — reject trailing bytes.
2. **Canonicality check** — re-encoding a decoded certificate must reproduce the received
   octets exactly; a mismatch is rejected.
3. **Sign the observed octets** — `AuthTranscriptV1` covers the **exact octets sent or
   received on the wire**, never a re-encoding. Both endpoints therefore agree on the signed
   bytes by construction.

### Capability bound

`capabilities: Vec<AlgId>` is currently unbounded. This ADR introduces
`MAX_CERT_CAPABILITIES = 64`, enforced **both** during certificate signing/construction
**and** during wire decoding.

- **64 is an independent cardinality and resource bound**, chosen to sit far above any
  plausible legitimate capability count while bounding decode-time allocation and transcript
  size. It is **not** derived from the algorithm code space.
- It does **not** imply that 64 algorithms are allocated, and it does **not** restrict future
  algorithm codes to any particular range.
- `docs/spec/algorithm-registry.md` is the **normative source of truth** for algorithm codes;
  `mw_crypto::AlgId` must match it exactly. Only the individual rows in that document's
  registry table are allocated. `0x0001`–`0x003F` describes the current **block layout** of
  the code space, not the allocated set.
- **No sorting or deduplication requirement is introduced.** That would alter certificate
  semantics beyond the resource-bound objective and is out of scope.
- Canonical bytes for existing valid certificates are unchanged.

### Legacy: `NodeCertificate.signature` remains a scalar

`.cursor/rules/crypto-boundary.mdc` requires signature **lists** on **new** signable protocol
objects. `NodeCertificate` predates this ADR and retains its scalar
algorithm-tagged signature.

**This ADR does not migrate it.** The scalar shape is recorded as a pre-existing legacy form
to be revisited during the broader crypto-agility migration.

**Stop condition:** if the crypto rule is interpreted as requiring immediate certificate
migration, that is a **separate coupled decision** requiring its own ADR. Implementation must
stop and flag it rather than silently expanding scope.

### ADR-015 reconciliation

ADR-015 previously stated that the exact signed bytes travel on the wire. This is inaccurate:
the signing form excludes the signature and is not by itself transferable. The accurate
statement is that the complete certificate wire representation transfers every field needed
to **deterministically reconstruct** the signing form, plus the algorithm identifier and
signature bytes.

This is corrected by a **dated, appended erratum to ADR-015**. It is a documentation
correction only: no encoding, canonical bytes, signature, or golden vector changes.

---

## Algorithm handling

**Authentication v1 is a fixed-algorithm protocol. There is no negotiation.**

Rationale: Ed25519 is the only implemented signature algorithm; `mw_crypto::Signature` is
already algorithm-tagged; `NodeCertificate.capabilities` already carries `AlgId`s; `Hello`
already advertises supported algorithms. A fourth mechanism would duplicate existing
structure to avoid a hypothetical wire change that the versioned label plus
`AuthTranscriptV2` already handles cleanly.

The fixed algorithm is nonetheless **explicitly bound into the signed transcript** via the
`auth_algorithm` field. There is nothing to negotiate, but there is no ambiguity about what
was used.

### v1 validation rules

1. `auth_algorithm` in the transcript **must** be the Ed25519 registry code.
2. The proof signature's algorithm **must** equal `auth_algorithm`.
3. It **must** equal the peer certificate's public-key algorithm.
4. Any other value is rejected as `UnsupportedAlgorithm`.

### Authoritative source

`NodeCertificate.capabilities` is the authoritative statement of a node's algorithm
capability, because it is issuer-signed and identity-bound (ADR-008). `Hello`'s advertisement
is **advisory** — usable for routing and diagnostics, never for a security decision.

Because `AuthTranscriptV1` covers `certificate_wire_bytes` in full, capabilities bind to the
session automatically. When a second algorithm is implemented, selection derives from the
certificates already in the transcript — still with no negotiation mechanism. If that proves
insufficient, the response is `AuthTranscriptV2` plus a `-v2` label, not a v1 amendment.

---

## Authentication flow

Three messages after TLS 1.3 handshake completion: **one round trip plus a final client
flight (~1.5 RTT)**. There is no server acknowledgement in v1.

```
  Client                                                     Server
    |   (TLS 1.3 complete; Unauthenticated<S> on both sides)   |
    |----------------- M1: AUTH_INIT -------------------------→|
    |     auth_version, client_nonce, client_certificate        |
    |←---------------- M2: AUTH_RESPONSE ----------------------|
    |     auth_version, server_nonce, server_certificate,       |
    |     signatures[]                                          |
    |----------------- M3: AUTH_CONFIRM ----------------------→|
    |     signatures[]                                          |
```

| Aspect | Detail |
|---|---|
| Initiator | The client — the TLS connection initiator |
| Mutual | Yes. Both signatures cover identical `AuthTranscriptV1` field values, differing only in `role`. |
| Signing key | The private key corresponding to the signer's own `NodeCertificate.public_key` |
| What is signed | The postcard encoding of `AuthTranscriptV1` — never a raw message, never a bare nonce, never the exporter value alone |

### Transition points

- **Server** transitions **only after** successfully validating `AUTH_CONFIRM`.
- **Client** transitions after successfully validating `AUTH_RESPONSE` **and** successfully
  writing `AUTH_CONFIRM`. No acknowledgement is awaited.

**This asymmetry is deliberate.** For roughly half a round trip the client considers the
session authenticated while the server does not. If the server rejects `AUTH_CONFIRM` it
closes, and the client observes closure. No security property depends on the client waiting:
it has already fully verified the server from `AUTH_RESPONSE`.

### Application frames after `AUTH_CONFIRM`

The client **may** write application frames immediately after `AUTH_CONFIRM`, saving half a
round trip. This is safe because TLS delivers an **ordered, reliable byte stream**.

**Server obligations (normative):**

1. Fully validate `AUTH_CONFIRM` before **dispatching, decoding beyond framing, or acting
   on** any subsequent frame.
2. Bytes coalesced into the same read chunk **may remain buffered** but must not be
   interpreted first.
3. The driver **must not read or decode another application frame** until `AUTH_CONFIRM`
   validates.
4. On validation failure: close the connection and discard all buffered bytes unprocessed.

---

## `AuthTranscriptV1`

A dedicated postcard structure — **not** a second codec. Fixed field order, no optional
fields, all variable-length fields bounded with exact runtime validation.

Per `.cursor/rules/crypto-boundary.mdc`, **no fixed-size cryptographic arrays appear in wire
or spec structures.** Fields whose length is fixed use `BoundedBytes<N>` with an
exact-length runtime check.

```rust
/// Versioned authentication transcript. Signed by both endpoints.
/// Never transmitted; reconstructed independently by each side.
struct AuthTranscriptV1 {
    /// b"MESHWARDEN-AUTH\0" — exactly 16 bytes, constant-checked
    domain: BoundedBytes<16>,
    /// 1
    auth_version: u16,
    /// Algorithm-registry wire code; ED25519 in v1
    auth_algorithm: u16,
    /// 0x01 = Client, 0x02 = Server
    role: u8,
    /// TLS exporter output; exactly 32 bytes; never transmitted
    channel_binding: BoundedBytes<32>,
    /// Canonical NodeId text: `mw:node:` + 26 Base32 = exactly 34 ASCII bytes
    client_node_id: BoundedBytes<34>,
    server_node_id: BoundedBytes<34>,
    /// Exactly 32 bytes each
    client_nonce: BoundedBytes<32>,
    server_nonce: BoundedBytes<32>,
    /// Exact octets observed on the wire, not a re-encoding
    client_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
    server_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
}
```

### Exact-length validation

`BoundedBytes<N>` enforces an **upper** bound at decode. Fields whose length is fixed carry
an **additional exact-length check** performed before use:

| Field | Required exact length |
|---|---|
| `domain` | 16, and byte-equal to the constant |
| `channel_binding` | 32 |
| `client_nonce`, `server_nonce` | 32 |
| `client_node_id`, `server_node_id` | 34, and must parse as a valid `NodeId` |

A length that is within bound but not exact is a `ProtocolViolation`.

### NodeId representation

`AuthTranscriptV1` uses the **existing canonical textual representation** — exactly 34 ASCII
bytes. **No new raw 16-byte NodeId wire representation is introduced.**

`mw-session` must verify, for each endpoint, that the transcript's node-id field:

1. parses as a valid `NodeId`, and
2. equals the `subject` of the corresponding certificate.

Either failure is a `ProtocolViolation`.

### Field rationale

| Field | Prevents |
|---|---|
| `domain` + `auth_version` | Cross-protocol signature reuse; version confusion |
| `auth_algorithm` | Algorithm ambiguity; future substitution |
| `role` | Reflection; role confusion |
| `channel_binding` | MITM relay; replay across connections |
| both node ids, fixed positions | Unknown-key-share; identity substitution |
| both nonces | Replay within a session; freshness |
| both certificate wire byte-strings | Binds capabilities, `valid_from`, `valid_until`, issuer |

### Version transition rule

- **Fields are never added to, removed from, or reordered within `AuthTranscriptV1`.**
- Any schema change defines a **new struct** `AuthTranscriptV2` **and** bumps the exporter
  label to `EXPERIMENTAL-MESHWARDEN-AUTH-v2`. The two changes are inseparable.
- Because the label change alters the binding value, cross-version proofs are
  cryptographically incapable of validating. Migration is fail-closed by construction.

A golden vector pins the encoding of `AuthTranscriptV1` and must never change.

### Relationship to `WireVersion.major`

Three independent version axes exist and must not be conflated:

| Axis | Owns | Defined by |
|---|---|---|
| `WireVersion.major` | Repository-wide wire representation compatibility | ADR-015 |
| `auth_version` | Authentication sub-protocol semantics | This ADR |
| Exporter label version (`-v1`) | Cryptographic binding domain | This ADR |

- **`WireVersion.major` owns wire compatibility.** ADR-015 is authoritative. This ADR
  introduces no competing versioning mechanism.
- `auth_version` and the exporter label version are **stricter, nested** gates inside a wire
  major. They never replace or override `WireVersion.major`.
- Introducing `AuthTranscriptV2` **alongside** V1, selected by `auth_version`, does **not**
  require a `WireVersion.major` bump.
- Changing the wire **representation** of existing messages **does** require a
  `WireVersion.major` bump, per ADR-015.
- Message codes `0x0002`–`0x0004` identify **semantic message kinds**. They are not version
  channels and are never reallocated for a schema revision. See
  `docs/spec/wire-registry.md` §*Version compatibility*.
- Unsupported `WireVersion.major`, unknown message code, and unsupported `auth_version` are
  each typed, fail-closed rejections. Validation precedence is defined in
  `docs/spec/wire-registry.md` §*Validation precedence*.

---

## Wire messages and signature lists

Message codes are allocated in `docs/spec/wire-registry.md`:

| Code | Message |
|---|---|
| `0x0002` | `AUTH_INIT` |
| `0x0003` | `AUTH_RESPONSE` |
| `0x0004` | `AUTH_CONFIRM` |

Per `.cursor/rules/crypto-boundary.mdc`, new signable protocol objects carry **signature
lists**:

```rust
struct WireSignature {
    /// Algorithm-registry wire code
    algorithm: u16,
    /// Variable-length, bounded
    signature: BoundedBytes<MAX_SIGNATURE_BYTES>,
}

struct AuthInit {
    auth_version: u16,
    client_nonce: BoundedBytes<32>,          // exactly 32
    client_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
}

struct AuthResponse {
    auth_version: u16,
    server_nonce: BoundedBytes<32>,          // exactly 32
    server_certificate: BoundedBytes<MAX_CERTIFICATE_WIRE_BYTES>,
    signatures: BoundedVec<WireSignature, MAX_PROOF_SIGNATURES>,
}

struct AuthConfirm {
    signatures: BoundedVec<WireSignature, MAX_PROOF_SIGNATURES>,
}
```

`mw-proto` converts `WireSignature.algorithm` through the **existing algorithm registry** to
`mw_crypto::AlgId`. An unmapped code is rejected.

### v1 signature-list rules

| Condition | Result |
|---|---|
| Exactly one signature, algorithm Ed25519, verifies | **Accept** |
| Empty list | Reject — `ProtocolViolation` |
| More than one signature | Reject — `ProtocolViolation` |
| Duplicate algorithm codes | Reject — `ProtocolViolation` |
| Unknown / unmapped algorithm code | Reject — `UnsupportedAlgorithm` |
| Algorithm ≠ `auth_algorithm`, or ≠ certificate key algorithm | Reject — `UnsupportedAlgorithm` |
| Signature fails verification | Reject — `AuthProofInvalid` |

The list exists for future dual-signature migration. v1 permits exactly one.

---

## Pre-authentication resource bounds

Before authentication the peer is unauthenticated. The general 16 MiB frame maximum is
**explicitly not reused**.

| Constant | v1 value |
|---|---|
| `MAX_CERTIFICATE_WIRE_BYTES` | **2 048** |
| `MAX_CERT_CAPABILITIES` | **64** |
| `MAX_SIGNATURE_BYTES` | **128** |
| `MAX_PROOF_SIGNATURES` | **4** (decode bound; v1 requires exactly 1) |
| `MAX_AUTH_INIT_BYTES` | **4 096** |
| `MAX_AUTH_RESPONSE_BYTES` | **4 096** |
| `MAX_AUTH_CONFIRM_BYTES` | **1 024** |
| `MAX_AUTH_TRANSCRIPT_BYTES` | **8 192** (derived) |
| **`MAX_PREAUTH_UNPROCESSED_BYTES`** | **16 384** |

### The single buffering rule

**Total unprocessed bytes accepted before authentication completes must never exceed
16 384.**

- Bytes trailing `AUTH_CONFIRM` in an already-read chunk **count toward this limit**.
- There is **no additional post-`AUTH_CONFIRM` allowance**.
- The driver validates `AUTH_CONFIRM` before reading or decoding another application frame.
- Exceeding the limit is `LimitExceeded`: close immediately.

**Sizing note:** if measured encoded sizes show 2 048 bytes is insufficient for a valid
certificate with up to 64 capabilities, implementation must **stop and report measured
evidence** rather than silently raising the bound.

### Bounds-before-allocation obligation (normative)

Asserting that `BoundedBytes<N>` "rejects before allocation" is insufficient. The
implementation **must** satisfy all of:

1. `BoundedBytes<N>` and `BoundedVec<T, N>` implement a **custom bounded deserialization
   path** that inspects the declared length prefix and rejects it against `N` **before**
   allocating the declared amount.
2. They **must not** delegate to `Vec<u8>::deserialize` or any path that may
   `with_capacity` from an attacker-controlled declared length.
3. A malicious postcard length prefix must not cause an oversized allocation prior to
   rejection.
4. **Tests must include a tiny input declaring an enormous vector length** and confirm prompt
   rejection.
5. Input byte-length checks alone are **insufficient** unless the decoder is demonstrated not
   to preallocate from the malicious declared length.
6. The pre-authentication framing layer applies its reduced maximum frame size against the
   length prefix **before** any postcard decode.

---

## Security invariants

| ID | Invariant | Enforcement strength |
|---|---|---|
| INV-1 | TLS 1.3 is a prerequisite; TLS ≤1.2 never reaches authentication | Configuration |
| INV-2 | The exporter value is never transmitted and never used as key material | Design + review |
| INV-3 | Issuer public keys originate only from caller-supplied trusted material, never the wire | Code + test |
| INV-4 | `now` is supplied explicitly to every time-dependent validation; no ambient clock | Code + lint |
| INV-5 | `AuthenticatedSession<S>` is constructible **only** by `mw-session::driver`, only by consuming an `Unauthenticated<S>` together with a successful `AuthOutcome` from `AuthMachine`. No public constructor. `AuthMachine` cannot construct it. | Type system |
| INV-6 | `AuthenticatedSession` is an **identity assertion, not an authorization grant** | Documented; `mw-trust` owns authorization |
| INV-7 | A valid, unexpired certificate held by a **compromised** node **will** authenticate. Authentication proves key possession, not node integrity. | By design |
| INV-8 | Official MESHWARDEN drivers transmit no application frame before authentication completes | **Driver invariant — see honesty statement** |
| INV-9 | Any authentication failure closes the channel immediately; no retry, no downgrade, no partial state | Code + test |
| INV-10 | `mw-transport` declares no **direct** dependency on `mw-crypto`, `mw-identity`, or `mw-session` | Manifest gate |
| INV-11 | No `ring` or `aws-lc*` reachable from `mw-transport` or `mw-session` | ADR-016 gate |
| INV-12 | The server processes no post-`AUTH_CONFIRM` frame until `AUTH_CONFIRM` validates | Code + test |
| INV-13 | Total unprocessed pre-authentication bytes never exceed `MAX_PREAUTH_UNPROCESSED_BYTES` | Code + test |
| INV-14 | No private key material enters `AuthMachine` | Type system |

### Honesty statement on INV-8 and `Unauthenticated<S>`

`Unauthenticated<S>` currently exposes `AsyncRead`, `AsyncWrite`, `get_ref()`, and
`into_inner()` publicly. Three strengths must not be conflated:

| Tier | Meaning | Status |
|---|---|---|
| **1. Absolute type-system enforcement** | No code path can send application data pre-authentication | **Not achieved. Not claimed.** |
| **2. Accidental-misuse resistance** | Naming and typing make misuse a deliberate act | **Achieved today** |
| **3. Driver invariant** | Official drivers never send pre-authentication application data | **Achieved by construction in `mw-session::driver`** |

**This ADR claims tiers 2 and 3 only.**

API narrowing is **deferred**. Adding `handshake_stream()` now would introduce another public
raw-stream escape hatch and churn the API before the official consumer exists. The narrowing
is revisited **after Slice 5**, when the driver's actual access pattern is proven.

---

## Crate ownership

```
mw-crypto ───┐
mw-identity ─┼──→ mw-session ──→ binaries
mw-proto ────┤
mw-transport ┘
```

| Crate | Responsibility | Must not |
|---|---|---|
| `mw-transport` | TLS 1.3, `Unauthenticated<S>`, channel-binding export | Declare a direct dependency on `mw-crypto`, `mw-identity`, or `mw-session`; know what a `NodeId` is |
| `mw-proto` | `AuthInit` / `AuthResponse` / `AuthConfirm`, `WireSignature`, `AuthTranscriptV1`, bounded types, exporter label constant, opaque certificate bytes | Depend on `mw-identity` or `mw-transport`; parse certificates |
| `mw-identity` | `NodeCertificate` verification; `to_wire_bytes` / `from_wire_bytes`; capability bound | Gain tokio or rustls dependencies |
| **`mw-session`** *(new)* | `machine` (pure `AuthMachine`) and `driver` (async integration) | Depend on `mw-trust` |
| `mw-trust` | Consumes a verified `NodeId`; decides authorization | Be depended on by `mw-transport`, `mw-proto`, or `mw-session` |

### Why a new crate

Not because four binaries need it — those binaries are skeletons. The justification is
**dependency direction and composition reuse**: `mw-transport` would require
`mw-transport → mw-identity`; `mw-identity` would require tokio and rustls; `mw-trust` would
invert the layering; a binary would make reusable protocol logic unreachable and untestable.
`mw-session` is the smallest structure expressing the ownership without inversion.

### Division of responsibility (normative)

**`mw-session::machine` — `AuthMachine` (pure)**

- Consumes validated inputs and events; produces authentication outputs or a verified
  `AuthOutcome`.
- Performs certificate validation, transcript construction, and **signature verification**
  (public-key operations only).
- Emits a **request** to sign; it never holds or receives private key material (INV-14).
- **Does not own or consume the TLS stream.**
- **Does not construct `AuthenticatedSession<S>`.**
- No I/O, no clock reads, no timers, no entropy source. `now`, channel binding, and nonces
  are supplied as inputs.

**`mw-session::driver` (async)**

- Owns `Unauthenticated<S>`; performs framed I/O under the pre-authentication bounds.
- Supplies the channel binding, explicit `now`, and CSPRNG nonces.
- Performs signing in response to the machine's request.
- Drives `AuthMachine`.
- Constructs the private `AuthenticatedSession<S>` **only** upon a successful `AuthOutcome`.
- Enforces INV-12 and INV-13.

```rust
struct AuthOutcome {
    peer_node_id: NodeId,
    peer_capabilities: Vec<AlgId>,
    authenticated_at: Timestamp,
    session_valid_until: Timestamp,
}
```

**The crate as a whole is not sans-I/O; only `machine` is.** The distinction is maintained
deliberately so tests target the pure core.

---

## Session validity and expiry

Computed once, at authentication time, from a caller-supplied `now`:

```text
session_valid_until = min(
    local_certificate.valid_until,
    peer_certificate.valid_until,
    authenticated_at + policy_max_session_duration
)
```

### Enforcement without an ambient clock

`AuthenticatedSession` **never reads a clock and never runs a timer.**

1. Every security-relevant operation takes `now` as a **required parameter** — sending an
   application frame, receiving one, and querying peer identity for an authorization
   decision.
2. Each returns `SessionExpired` if `now >= session_valid_until`, performing no work.
3. Because `now` is required, the check cannot be omitted by an ordinary caller: the API is
   unusable without supplying time.

### What this guarantees

- **Guaranteed:** no security-relevant operation succeeds after `session_valid_until`.
- **Not guaranteed:** the transport does not close at the instant of expiry. An idle expired
  session holds an open TLS connection until touched or torn down.

This is acceptable: an unused session is harmless. **Timer-driven proactive closure is
deferred to the async driver slice** and is not promised here.

No mid-session re-validation or re-authentication in v1. Re-establishing requires a fresh TLS
connection and a fresh authentication exchange.

**DDIL consequence, accepted deliberately:** a node partitioned longer than its certificate
lifetime cannot re-authenticate until it can renew. This is correct fail-safe behavior,
consistent with the offline model. Extending credentials offline requires its own ADR.

---

## Resumption and 0-RTT

**Both disabled for the PoC**, enforced in `rustls` configuration and covered by a test.

This is a **simplification, not a security finding.** It keeps the exporter-uniqueness
argument trivially auditable while the protocol is young. 0-RTT early data is separately
replayable by design and would be excluded regardless.

The spike observed only full handshakes and did not test exporter behavior under resumption.
Nothing here implies exporters are unsafe under resumed TLS 1.3; the question is unexamined
and deferred.

---

## Failure behavior

**Fail closed, always.** Every failure closes the TLS connection immediately and returns a
typed local error. No retry, no downgrade, no partial state.

**No error information is sent on the wire.** v1 defines no authentication error message; the
connection simply closes. A wire error taxonomy would be an oracle for an unauthenticated
party, and no such message type exists.

| Failure | Local error |
|---|---|
| Unsupported `auth_version` | `UnsupportedVersion` |
| Unknown message code | `UnknownMessageType` |
| Malformed / truncated message; trailing bytes | `MalformedMessage` |
| Any size or count bound exceeded | `LimitExceeded` |
| Exact-length field with wrong length | `ProtocolViolation` |
| Non-canonical certificate encoding | `MalformedCertificate` |
| Certificate subject mismatch | `PeerCertificateInvalid(SubjectKeyMismatch)` |
| Certificate issuer mismatch | `PeerCertificateInvalid(IssuerKeyMismatch)` |
| Certificate signature invalid | `PeerCertificateInvalid(BadSignature)` |
| Certificate outside `valid_from`..`valid_until` at supplied `now` | `PeerCertificateNotValidAt` |
| `capabilities` exceeding `MAX_CERT_CAPABILITIES` | `LimitExceeded` |
| Empty, multiple, or duplicate proof signatures | `ProtocolViolation` |
| Unknown or mismatched signature algorithm | `UnsupportedAlgorithm` |
| Proof signature invalid | `AuthProofInvalid` |
| Node id unparseable or ≠ certificate subject | `ProtocolViolation` |
| Exporter unavailable or wrong length | `ChannelBindingUnavailable` |
| Out-of-order message; message after completion; nonce reuse | `ProtocolViolation` |
| Operation with `now >= session_valid_until` | `SessionExpired` |

**Timeouts are out of scope.** `AuthMachine` bounds progress by message count and byte
totals, not wall-clock time. Wall-clock timeouts belong to the driver slice.

Local audit-event emission is **future work**, contingent on an audit subsystem existing.

---

## Dependency gates

The transitive path `mw-transport → mw-proto → mw-crypto` is **intentional and permitted**. A
transitive-tree grep for `mw-crypto` is therefore not a valid gate.

**The actual invariant:** `mw-transport`'s manifest declares **no direct dependency** on
`mw-crypto`, `mw-identity`, or `mw-session`, in any of `[dependencies]`,
`[dev-dependencies]`, or `[build-dependencies]`.

```bash
# Direct dependencies only
cargo tree -p mw-transport --depth 1 | grep -E 'mw-crypto|mw-identity|mw-session'   # empty

# Manifest-level, authoritative
cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name=="mw-transport") | .dependencies[].name' \
  | grep -E '^(mw-crypto|mw-identity|mw-session)$'                                   # empty
```

ADR-016's gate is unchanged and correctly **transitive**:

```bash
cargo tree -p mw-transport | grep -Ei 'aws-lc|ring'   # empty
cargo tree -p mw-session   | grep -Ei 'aws-lc|ring'   # empty
```

---

## Consequences

**Positive**

- Mesh identity is decoupled from TLS provider capability; ADR-016 and crypto agility stop
  competing.
- ADR-015 preserved: one codec, postcard, throughout.
- `.cursor/rules/crypto-boundary.mdc` satisfied for all new structures: no fixed-size crypto
  arrays, signature lists on new signable objects.
- `NodeCertificate` is the single source of identity truth; `b1911bd` becomes load-bearing.
- Capabilities bind automatically, since certificate wire bytes are signed.
- No negotiation mechanism to attack or maintain.
- `AuthMachine` is testable with zero I/O, zero timers, and zero private key material.
- Versioned label plus versioned transcript give a fail-closed migration kill-switch.

**Negative**

- MESHWARDEN owns a bespoke authentication protocol. Mitigated by mirroring TLS 1.3's own
  `CertificateVerify` shape.
- One additional crate.
- ~1.5 RTT after the TLS handshake, mitigated by long-lived sessions and immediate
  post-`AUTH_CONFIRM` frames.
- Client and server transition at different moments; consumers must understand the asymmetry.
- `mw-identity` gains a public wire format requiring version management alongside the private
  signing form.
- `NodeCertificate.signature` remains a scalar, inconsistent with the signature-list rule
  applied to new objects.
- The peer's certificate is disclosed to whoever terminated the slice-1 TLS session before
  authentication completes.

---

## Alternatives considered

**A1 — Mesh identity as X.509 with a custom rustls verifier.** Rejected. Couples mesh
identity to `rustls-rustcrypto`'s certificate-verification algorithm set, making every future
identity decision contingent on an experimental provider. Requires
`mw-transport → mw-identity`. Would duplicate or replace `NodeCertificate` and invalidate
existing golden vectors.

**A2 — RFC 7250 Raw Public Keys.** Rejected. Raw public keys carry no attributes, so an
application-layer exchange is still required for capabilities, validity window, and issuer.
Adds TLS coupling without removing the application-layer step.

**C — Both layers.** Deferred, not rejected. The natural hardening path; also resolves the
pre-authentication metadata leak. Excluded from the PoC as duplicated effort.

**Hand-rolled length-prefixed transcript.** Rejected — a second canonical codec conflicting
with ADR-015 for no benefit over a dedicated postcard struct.

**Algorithm negotiation in v1.** Rejected — see *Algorithm handling*.

**Immediate `Unauthenticated<S>` API narrowing.** Deferred — would add another public
raw-stream escape hatch and churn the API before the official consumer exists.

**Immediate `NodeCertificate.signature` migration to a list.** Deferred — a separate coupled
decision, not an ADR-017 concern.

**RFC 9266 `EXPORTER-Channel-Binding`.** Rejected — designed for sharing across protocols;
carries no version.

---

## Residual risks

| ID | Risk | Assessment |
|---|---|---|
| RSK-017-1 | Bespoke authentication protocol risk | Accepted. Mitigated by mirroring TLS `CertificateVerify`, explicit role/identity/nonce/binding/algorithm coverage, a single canonical codec, and a fail-closed versioned kill-switch. Warrants external review before operational use. |
| RSK-017-2 | A compromised node with a valid certificate authenticates | Accepted and **intended** (INV-7). |
| RSK-017-3 | Peer certificate disclosed to an active MITM pre-authentication | Accepted for PoC. Resolved later by alternative C. |
| RSK-017-4 | No revocation; a compromised certificate is usable until `valid_until` | Accepted. Short certificate lifetimes deliberately stand in for revocation in the PoC. |
| RSK-017-5 | ~~Exporter support unverified~~ | **Closed** by capability spike on the pinned stack. |
| RSK-017-6 | Certificate expiry ends sessions during long partitions | Accepted; consistent with the offline model. |
| RSK-017-7 | Unauthenticated setup is a DoS and signing-oracle surface | Partially mitigated by pre-authentication bounds. Rate limiting deferred. Lab-only. |
| RSK-017-8 | Expired sessions are not proactively closed | Accepted. Idle expired sessions are harmless. |
| RSK-017-9 | `Unauthenticated<S>` does not absolutely prevent pre-authentication traffic | Accepted and stated honestly. Tiers 2 and 3 only. Narrowing deferred to post-Slice 5. |
| RSK-017-10 | Exporter behavior under resumed TLS 1.3 untested | Accepted; resumption disabled for the PoC. |
| RSK-017-11 | `rustls-rustcrypto` is 0.0.2-alpha and unaudited | Accepted under ADR-016 for PoC only. |
| RSK-017-12 | `NodeCertificate.signature` scalar is inconsistent with the signature-list rule | Accepted as pre-existing legacy. Revisit during crypto-agility migration. |
| RSK-017-13 | `MAX_CERTIFICATE_WIRE_BYTES = 2048` is provisional | Accepted. Implementation must stop and report measured evidence if insufficient. |

---

## Coupled decisions

Changing any of these invalidates this ADR:

| Coupled to | Nature |
|---|---|
| `mw-identity` subject/public-key consistency (`b1911bd`) | Proof of possession depends entirely on `subject == NodeId(public_key)` |
| ADR-016 (pure-Rust provider) | Application-layer authentication exists largely to avoid coupling identity to this provider |
| ADR-015 + Erratum 1 (postcard) | `AuthTranscriptV1` and `certificate_wire_bytes` are postcard by mandate |
| ADR-008 (identity-bound capabilities) | The no-negotiation decision rests on certificates being authoritative |
| `.cursor/rules/crypto-boundary.mdc` | Bounded types and signature lists are mandated by it |
| `NodeCertificate.signature` scalar shape | Migrating it is a **separate** coupled decision requiring its own ADR |
| Short certificate lifetimes | Session validity is bounded by them; RSK-017-4 depends on them |
| No ambient clock | Certificate validation and session expiry both take `now` explicitly |
| `certificate_signing_bytes` stability | Existing golden vectors must not change |
| NodeId canonical textual form (34 ASCII) | `AuthTranscriptV1` encodes it directly |

---

## Revisit triggers

- **After Slice 5:** revisit `Unauthenticated<S>` API narrowing with the driver's proven
  access pattern.
- Crypto-agility migration reaches certificates → revisit the `NodeCertificate.signature`
  scalar.
- Measured certificate sizes approach `MAX_CERTIFICATE_WIRE_BYTES` → re-evaluate with
  evidence.
- A second signature algorithm is implemented → re-examine certificate-derived selection.
- A cryptographic review finds a flaw in `AuthTranscriptV1` → `AuthTranscriptV2` + `-v2`
  label.
- Resumption or 0-RTT becomes necessary → test exporter behavior under resumption first.
- Certificate lifetimes lengthen, or a compromise scenario demands faster response →
  revocation.
- Node-presence metadata leakage becomes unacceptable → alternative C.
- `rustls-rustcrypto` reaches a stable audited release, or is replaced.
- Post-quantum signature migration begins → the tagged signature list and versioned
  transcript should absorb it.
- An audit subsystem exists → add local audit events at the listed failure points.

---

## Testing obligations

**Positive**

- Mutual authentication succeeds over `tokio::io::duplex`; both endpoints reach
  `AuthenticatedSession` with the correct peer `NodeId` and capabilities.
- `AuthTranscriptV1` encoding pinned by a golden vector.
- `certificate_signing_bytes` golden vectors **unchanged**.
- `certificate_wire_bytes` round-trips; re-encode equals original.
- Exporter is 32 bytes, deterministic within a session, distinct across sessions.
- A certificate with exactly `MAX_CERT_CAPABILITIES` capabilities encodes within
  `MAX_CERTIFICATE_WIRE_BYTES`.

**Negative — each must close the channel**

| Test | Asserts |
|---|---|
| Reflection: replay a peer's proof back to it | rejected on `role` |
| Cross-session replay | rejected on `channel_binding` |
| MITM relay: proof from session A on session B | rejected on `channel_binding` |
| Role confusion | rejected |
| Unknown-key-share: substitute one identity | rejected |
| Certificate outside validity at supplied `now` | `PeerCertificateNotValidAt` |
| Wrong-but-valid issuer key | `IssuerKeyMismatch`, not `BadSignature` |
| Subject mismatch | `SubjectKeyMismatch` |
| Tampered proof signature | `AuthProofInvalid` |
| Empty signature list | `ProtocolViolation` |
| Two signatures | `ProtocolViolation` |
| Duplicate algorithm codes | `ProtocolViolation` |
| Unknown algorithm code | `UnsupportedAlgorithm` |
| Signature algorithm ≠ `auth_algorithm` | `UnsupportedAlgorithm` |
| Signature algorithm ≠ certificate key algorithm | `UnsupportedAlgorithm` |
| Node id unparseable | `ProtocolViolation` |
| Node id ≠ certificate subject | `ProtocolViolation` |
| Exact-length field with 31 or 33 bytes | `ProtocolViolation` |
| Certificate with 65 capabilities | `LimitExceeded` |
| Certificate exceeding `MAX_CERTIFICATE_WIRE_BYTES` | `LimitExceeded` |
| Each message exceeding its payload bound | `LimitExceeded` |
| **Tiny input declaring an enormous vector length** | **rejected promptly, no oversized allocation** |
| Non-canonical certificate encoding | `MalformedCertificate` |
| Trailing bytes after any message | `MalformedMessage` |
| Unknown message code | `UnknownMessageType`, no panic |
| Message code `0x0000` | rejected |
| Out-of-order message; nonce reuse | `ProtocolViolation` |
| Cumulative pre-auth bytes exceeding 16 384 | `LimitExceeded` |
| Post-`AUTH_CONFIRM` frame with invalid `AUTH_CONFIRM` | never processed |
| Operation with `now >= session_valid_until` | `SessionExpired` |
| TLS 1.2 offered | refused before authentication |
| Resumption or 0-RTT enabled | configuration rejected |

**Structural**

- `cargo tree -p mw-transport --depth 1 | grep -E 'mw-crypto|mw-identity|mw-session'` → empty
- `cargo tree -p mw-transport | grep -Ei 'aws-lc|ring'` → empty
- `cargo tree -p mw-session | grep -Ei 'aws-lc|ring'` → empty
- `cargo tree -p mw-session --depth 1 | grep mw-trust` → empty
- No clock read, socket, timer, or sleep anywhere in `mw-session::machine`
- No private key type reachable from `AuthMachine`
- No fixed-size crypto array in any `mw-proto` wire or spec structure

---

## Traceability

Repository requirement documents are currently skeletons. **No requirement IDs are invented.**
Descriptive traceability until real IDs exist.

| Type | Reference | Relationship |
|---|---|---|
| Requirement | TBD — mutual authentication between mesh nodes | implements |
| Requirement | TBD — a connection conveys no trust | implements via INV-6 |
| Threat | TBD — cloned identity | mitigates via proof of possession |
| Threat | TBD — man-in-the-middle | mitigates via channel binding |
| Threat | TBD — replay across connections | mitigates via channel binding + nonces |
| Threat | TBD — unknown-key-share | mitigates via both identities in transcript |
| Threat | TBD — pre-authentication resource exhaustion | mitigates via bounds |
| ADR | ADR-008 | depends on; no-negotiation rests on it |
| ADR | ADR-015 (+ Erratum 1) | preserves; single postcard codec |
| ADR | ADR-016 | depends on; must not weaken |
| Rule | `.cursor/rules/crypto-boundary.mdc` | complies with |
| Commit | `b1911bd` | depends on; proof of possession |
| Spike | `spike_exporter.rs` (deleted) | closed RSK-017-5 |
| Spec | `docs/spec/wire-registry.md` | allocates `0x0002`–`0x0004` |
