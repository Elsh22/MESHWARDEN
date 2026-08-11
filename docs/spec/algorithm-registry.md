# Algorithm Registry

Normative source of truth for `AlgId` wire codes. The `mw-crypto::AlgId` enum
MUST match this table exactly. Referenced by ADR-005, ADR-006, ADR-007, ADR-008.

## Encoding

- `AlgId` is a `u16` on the wire, encoded big-endian (network byte order).
- The Rust representation is `#[repr(u16)]`; the wire name is the
  SCREAMING_SNAKE form, the Rust variant is PascalCase.

## Invariants

These are load-bearing for the offline/partitioned model, where two nodes on
different builds must agree on codes without a coordinator to reconcile them.

1. **Append-only.** New algorithms take the next free code in the appropriate
   block. Codes are never renumbered.
2. **Never reuse.** A retired algorithm's code is permanently burned, not
   reassigned to a different algorithm. Reuse would let an old node and a new
   node disagree silently about what a code means.
3. **Unknown code = reject, never panic.** A decoder that reads a code not in
   this table returns an unsupported-algorithm error. It does not trap, and it
   does not guess.
4. **Reserved != usable.** A code with status *reserved* is allocated so the
   number is stable, but every crypto operation on it returns
   `Error::UnsupportedAlg` until it is promoted to *implemented*.
5. **`0x0000` is permanently invalid** and never assigned, so a zeroed field is
   always detectably wrong.

### Scope of invariant 3: acted-upon versus descriptive codes

*Maintainer decision, recorded 2026-08-10; normative. ADR-017 Revision 5,
Amendment 1 references this section rather than restating it.*

Invariant 3 is correct where a code is **acted upon** and wrong where a code is
**descriptive**. The scoping:

| Context | Policy | Rationale |
|---|---|---|
| An algorithm code that selects a cryptographic operation — e.g. a `Signature`'s algorithm, ADR-017's `auth_algorithm`, a key's algorithm tag | **Must resolve. Unknown → typed rejection** (invariant 3, unchanged). | You cannot verify a signature whose algorithm you cannot identify. Carrying it opaquely means accepting an unverifiable object. |
| A descriptive advertisement — `NodeCertificate.capabilities` | **Carried opaquely as raw `u16`. Unknown codes are non-fatal and unusable.** | Nothing is acted upon by failing to understand it. The certificate's canonical signing form already carries capabilities as raw `u16` (`CanonicalForm.capabilities: Vec<u16>` in `mw-identity`), so signature verification never requires understanding every code. |

**Security property preserved: never act on a capability you do not understand.**
Satisfied by construction — an unresolvable code cannot be matched against any
`AlgId`, so no operation can ever select it. Opaque carriage makes an unknown
code inert, not trusted.

**Availability reasoning.** Rejecting an entire certificate over one
unrecognized *descriptive* code is fail-closed for availability while buying no
security, and it fails precisely in the partition scenario ADR-017's versioning
discipline exists to survive: a newer node advertising a newly allocated
algorithm would make its certificate unacceptable to every older partition
member, turning each new algorithm into a coordinated flag-day across every
partition.

**Do not over-read this exception.** It is *not* "carry all unknown codes
opaquely." A code in an acted-upon position — anywhere a signature is verified,
a key is used, or an operation is selected — must resolve, or the object is
rejected. A decoder that carried an unknown *signature* algorithm opaquely
would produce a certificate that decodes cleanly and can never be verified. The
exception applies to descriptive advertisements only; today
`NodeCertificate.capabilities` is the only such field.

## Block layout

| Block         | Class                          |
|---------------|--------------------------------|
| `0x0000`      | Reserved-invalid (never assign)|
| `0x0001–000F` | Classical asymmetric (sig / kex)|
| `0x0010–001F` | Hash functions                 |
| `0x0020–002F` | Key-encapsulation mechanisms   |
| `0x0030–003F` | Post-quantum signatures        |

## Registry

| Code     | Wire name       | Rust variant | Class   | Status      | Notes |
|----------|-----------------|--------------|---------|-------------|-------|
| `0x0001` | `ED25519`       | `Ed25519`    | Sig     | Implemented | PoC signature algorithm (ADR-005). |
| `0x0002` | `X25519`        | `X25519`     | Kex     | Reserved    | Lands with `mw-transport`. |
| `0x0010` | `SHA256`        | `Sha256`     | Hash    | Implemented | PoC hash; audit chain, digests. |
| `0x0011` | `SHA384`        | `Sha384`     | Hash    | Reserved    | Exercises the hash-transition path. |
| `0x0020` | `ML_KEM_768`    | `MlKem768`   | KEM     | Reserved    | Benchmarking only, `mw-sim` only, never on a security path (ADR-006). |
| `0x0030` | `ML_DSA_87`     | `MlDsa87`    | PQ-Sig  | Reserved    | Hybrid/PQC signature candidate. |
| `0x0031` | `SLH_DSA_128S`  | `SlhDsa128s` | PQ-Sig  | Reserved    | Hash-based signature candidate. |

## PoC scope

Implemented and on a security path: `ED25519`, `SHA256`. Everything else is
reserved: the wire code is fixed here, but the algorithm is not available in the
PoC. `ML_KEM_768` may be exercised for benchmarking inside `mw-sim` and nowhere
else (ADR-006).