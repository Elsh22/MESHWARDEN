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