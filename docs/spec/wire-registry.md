# MESHWARDEN Wire Registries

Two independent registries. Both are append-only.

---

## 1. Message-Type Registry

### Allocation rules

1. **Append-only.** Codes are assigned in ascending order.
2. **Retired codes are never reused.** Mark a retired code `RETIRED` and leave its row in
   place permanently. Retirement applies only when a message **kind** is removed — see
   §*Retirement*.
3. **`0x0000` is permanently invalid** and must never be allocated.
4. A decoder receiving an unknown code **must reject the message with a typed error**. It
   must not panic, must not allocate based on the unknown code, and must not attempt
   recovery.
5. Codes are `u16`, big-endian on the wire.
6. Assignment requires an ADR or an explicit maintainer decision recorded in this file.

### Version compatibility

Compatibility is owned by `WireVersion.major` (ADR-015). **This registry introduces no second
versioning mechanism.**

1. **A message code identifies a semantic message kind**, not a schema revision.
2. **Within a given `WireVersion.major`, the payload schema associated with a message code is
   immutable.**
3. **A protocol-breaking representation or schema change is carried by a new
   `WireVersion.major`**, as ADR-015 requires. It does **not** allocate a new message code.
4. **A new message code is allocated only for a genuinely new or semantically distinct message
   kind** — never automatically for a schema revision.
5. **Message-specific inner versions** — such as ADR-017's `auth_version` — may impose
   *stricter* compatibility on their own sub-protocol, but they never replace or override
   `WireVersion.major`.
6. **Unknown message codes and unsupported wire or inner protocol versions are typed,
   fail-closed rejections.** No negotiation, no downgrade, no recovery.

### Validation precedence

A decoder validates in this order and reports the **first** failure:

1. `WireVersion.major` — unsupported → typed rejection.
2. Message code — unknown, retired, or `0x0000` → typed rejection.
3. Message-specific inner version, where one exists → unsupported → typed rejection.

This ordering is **normative** so that a peer speaking an entirely different wire major is
never misreported as sending an unknown message code.

### Retirement

A code is retired **only when its message kind is removed** from the protocol — never because
its schema changed. Retired codes remain listed permanently and are never reused, so
historical captures and audit records stay interpretable.

### Assignments

| Code | Name | Status | Introduced by |
|---|---|---|---|
| `0x0000` | *(reserved — permanently invalid)* | Reserved | — |
| `0x0001` | `HELLO` | Active | pre-existing |
| `0x0002` | `AUTH_INIT` | Active | ADR-017 |
| `0x0003` | `AUTH_RESPONSE` | Active | ADR-017 |
| `0x0004` | `AUTH_CONFIRM` | Active | ADR-017 |

**Next available code:** `0x0005`

---

## 2. Algorithm Registry

`docs/spec/algorithm-registry.md` is the **normative source of truth** for algorithm codes.
`mw_crypto::AlgId` **must match it exactly**. This section is a pointer, not a definition, and
does not redefine any assignment.

- **Only the individual rows in that document's registry table are allocated.**
- `0x0001`–`0x003F` describes the current **block layout** of the code space. It is **not**
  the currently allocated set, and it is **not** an upper bound on future codes.
- The same append-only and no-reuse rules apply.

### Relationship to `MAX_CERT_CAPABILITIES`

`MAX_CERT_CAPABILITIES = 64` (ADR-017) is an **independent cardinality and resource bound** on
`NodeCertificate.capabilities: Vec<AlgId>`. Its purpose is to bound decode-time allocation and
transcript size.

It does **not** imply that 64 algorithms are allocated, it does **not** derive from the
`0x0001`–`0x003F` block layout, and it does **not** restrict future algorithm codes to
`0x003F` or below.

See `docs/spec/algorithm-registry.md` for authoritative algorithm assignments.
