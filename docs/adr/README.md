# ADR index

## Index

- ADR-015: Wire serialization codec is postcard — Accepted, 2026-08-07. Carries Erratum 1 (2026-08-07).
- ADR-016: rustls CryptoProvider is rustls-rustcrypto (PoC) — Accepted, 2026-08-07.
- ADR-017: Mesh Identity Authentication and TLS Channel Binding — Accepted, 2026-08-07.

## Coupled decisions

- ADR-009: Ed25519 hot path <-> hours-scale cert lifetime. Neither changes without re-deriving the other.
- ADR-017 <-> `mw-identity` subject/public-key consistency (commit `b1911bd`): proof of possession depends entirely on `subject == NodeId(public_key)`. Weakening it silently breaks authentication.
- ADR-017 <-> ADR-016: application-layer authentication exists largely to avoid coupling identity to the pure-Rust provider's algorithm set.
- ADR-017 <-> ADR-015 + Erratum 1: `AuthTranscriptV1` and `certificate_wire_bytes` are postcard by mandate.
- ADR-017 <-> ADR-008: the no-negotiation decision rests on certificates being the authoritative capability source.
- ADR-017 <-> `.cursor/rules/crypto-boundary.mdc`: bounded types and signature lists are mandated by it.
- ADR-017 <-> `NodeCertificate.signature` scalar shape: migrating it to a signature list is a **separate** coupled decision requiring its own ADR.
- ADR-017 <-> short certificate lifetimes: session validity is bounded by them; RSK-017-4's acceptance depends on them.
- ADR-017 <-> no ambient clock: certificate validation and session expiry both take `now` explicitly.
- ADR-017 <-> `certificate_signing_bytes` stability: existing golden vectors must not change.
- ADR-017 <-> NodeId canonical textual form (34 ASCII): `AuthTranscriptV1` encodes it directly.
