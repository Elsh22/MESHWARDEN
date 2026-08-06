# MESHWARDEN — System Architecture (Phase 3)

> **Status:** Draft v0.1 — Phase 3 deliverable
> **Stack:** All-Rust. Agent: `tokio` + `rustls` (TLS 1.3) + RustCrypto (`ed25519-dalek`, `x25519-dalek`). Control plane: `axum`. Static `musl` binaries per arch.
> **Diagrams:** Mermaid (renders in Cursor preview and GitHub).

---

## 1. Coordination Architecture — Evaluation & Recommendation

Three coordination models were evaluated against the requirement criteria. Scores are 1 (poor) – 5 (excellent) for a **solo developer building a 3–6 node PoC in 12 weeks**, with an eye toward later scale.

| Criterion | (1) Fully P2P | (2) Federated + ephemeral coordinator | (3) Hybrid (federated data plane + optional admin plane) |
|---|:--:|:--:|:--:|
| Resilience | 5 | 4 | 4 |
| Scalability | 3 | 4 | 4 |
| Complexity (lower = better) | 1 | 3 | 3 |
| Latency | 3 | 4 | 4 |
| Offline operation | 5 | 4 | 4 |
| Security | 3 | 4 | 4 |
| Ease of deployment | 2 | 4 | 4 |
| Suitability for old hardware | 2 | 4 | 4 |
| Resistance to compromised coordinator | 5 (n/a) | 3 | 4 |
| Recovery from partition | 4 | 4 | 4 |
| **Fit for 12-week solo PoC** | **Low** | **High** | **High** |

**Recommendation: (3) Hybrid.** The *data plane* uses the federated-cluster pattern — nodes form a cluster with an **ephemeral, re-electable coordinator role**; the *control plane* (CA, policy, approval, dashboard) is an **optional administrative service off the critical path**. This is exactly what the PRD demands (`NFR-1`, `SEC-8`): no permanent central server for task execution, but an admin console for observability, policy, and human approval that the mesh survives without.

At PoC scale (3–6 nodes) this collapses to **a single cluster with one elected coordinator plus the admin plane**. The federation dimension (multiple clusters, cross-cluster reconciliation) is exercised in simulation (Phase 7) rather than physical hardware.

Fully-P2P was rejected for the PoC: Byzantine agreement, Sybil resistance, and CRDT conflict machinery are too much surface for one developer in 12 weeks, and consensus overhead is unkind to 1 GB nodes. Its strengths (no SPOF) are preserved anyway because the coordinator is a *role*, not infrastructure.

### The compromised-coordinator story (design crux)

The coordinator is deliberately **not a trust anchor**. It performs liveness/efficiency functions only:

- **It does:** aggregate capability/resource ads, assign work units and issue leases, aggregate results for verification, track cluster membership.
- **It does NOT:** vouch for result correctness, grant trust or privilege, approve sensitive actions, or hold any identity-signing authority.

Therefore a compromised coordinator can at worst mis-schedule, drop, or delay work (all detectable via lease timeouts and reassignment) or attempt to bias verification (defeated because verification rules are deterministic and independently recomputable by any node, and everything is hash-chain audited). It **cannot** forge node-signed results, mint identities, or authorize a sensitive action. Result integrity and authorization never depend on the coordinator.

### Evolution path
- **PoC:** 1 cluster, 1 elected coordinator, optional admin plane.
- **Scale:** many clusters (squad/platoon/company analogy), cross-cluster gossip + reconciliation, multiple admin consoles with quorum approval.
- **Hardening:** add BFT verification quorums and threshold signatures for the highest-impact tasks, moving selected functions toward the fully-P2P end of the spectrum where warranted.

---

## 2. Binary / Component Set (all Rust)

| Binary | Role | Runs where |
|---|---|---|
| `mw-agent` | Node agent; includes worker + **coordinator role** (role-activated, same binary) | Every node |
| `mw-ca` | Enrollment Authority / CA; issues short-lived certs; holds the highest-value signing key | ≥4 GB bootstrap node (management) |
| `mw-control` | Admin API (`axum`) + approval service + authoritative policy source + audit aggregator + dashboard | ≥4 GB bootstrap node (management) |
| `mw-cli` | Operator CLI (submit tasks, approve, inspect) | Operator workstation |
| `mw-sim` | Simulation harness — spins up N agents in netns/containers for scale + partition testing | Any capable node |

Control-plane binaries (`mw-ca`, `mw-control`) are **off the critical path**: the data plane keeps executing authorized, unexpired, leased work when they are unreachable.

---

## 3. Component Diagram

```mermaid
flowchart TB
    OP["Operator (human)"]
    subgraph CP["Control Plane — off critical path"]
        CA["mw-ca<br/>Enrollment Authority / CA"]
        CTRL["mw-control<br/>Admin API · Approval · Policy · Audit aggregator"]
        UI["Dashboard (web, axum-served)"]
        CTRL --- UI
    end
    subgraph DP["Data Plane — federated cluster"]
        COORD["mw-agent :: Coordinator role<br/>Scheduling · Membership · Result aggregation"]
        N1["mw-agent :: Worker"]
        N2["mw-agent :: Worker"]
        N3["mw-agent :: Worker"]
        COORD --- N1
        COORD --- N2
        COORD --- N3
        N1 <--> N2
    end
    OP --> UI
    OP --> CA
    CA -. issues short-lived certs .-> COORD
    CA -. issues short-lived certs .-> N1
    CTRL -. signed policy (cached, TTL) .-> COORD
    COORD -. audit + telemetry .-> CTRL
```

---

## 4. Node Architecture

The agent is split into a **small privileged core (the TCB)** and **sandboxed workloads with no ambient authority**. Workloads never touch keys, the network, or the filesystem except through grants named in the task manifest.

```mermaid
flowchart TB
    subgraph HOST["Host OS"]
        subgraph AGENT["mw-agent process — privileged core / small TCB"]
            ID["Identity & Keystore<br/>Ed25519; TPM-optional; software-sealed fallback"]
            TR["Transport<br/>rustls mTLS, TLS 1.3"]
            DISC["Discovery<br/>mDNS + gossip membership"]
            POL["Policy Engine<br/>cached, signed, TTL-bounded"]
            SCH["Scheduler client / Coordinator role"]
            TRUST["Trust Engine<br/>local scoring"]
            AUD["Audit Writer<br/>hash-chained, append-only"]
            OQ["Offline Queue + Sync engine"]
            SUP["Workload Supervisor"]
        end
        subgraph SB["Sandbox — namespaces + seccomp + cgroups v2"]
            WL["Signed workload<br/>no key/net/fs beyond manifest grants"]
        end
    end
    ID --> TR
    POL --> SUP
    SUP -->|spawn, resource-limited| SB
    WL -->|manifest via stdin, result via stdout| SUP
    TRUST --> SCH
    AUD -. every security event .-> AUD
```

**TCB minimization:** identity, transport, policy enforcement, and audit are the only privileged concerns. Everything computational runs in the sandbox. This keeps the attack surface that must be trusted for *integrity* small and reviewable.

---

## 5. Network Architecture

```mermaid
flowchart TB
    subgraph SEG["LAN segment — flat; partitions simulated via netem / netns"]
        COORD["Coordinator (elected)"]
        A["Worker node"]
        B["Worker node"]
        HP["Honeypot node (instrumented)"]
    end
    subgraph MGMT["Management — reachable when available"]
        CA["mw-ca"]
        CTRL["mw-control + Dashboard"]
    end
    A <-->|mTLS peer + gossip| B
    A <-->|mTLS| COORD
    B <-->|mTLS| COORD
    HP <-->|mTLS| COORD
    COORD <-->|mTLS| CTRL
    CA -.->|cert issuance| COORD
    NET["tc/netem + netns:<br/>inject latency, loss, partition"] -. shapes .-> SEG
```

All links are mutually authenticated TLS 1.3; **a valid connection conveys no trust** (`SEC-1`). Discovery is mDNS/DNS-SD on the segment for bootstrap, with gossip for membership and liveness. Degraded/partitioned conditions are produced with `tc qdisc netem` and Linux network namespaces so DDIL behavior is testable without physical distance.

---

## 6. Trust Boundaries

```mermaid
flowchart LR
    subgraph B1["Boundary A: Host vs Agent core"]
        H["Host OS / operator shell"] -. syscalls .-> AC["Agent privileged core"]
    end
    subgraph B2["Boundary B: Core vs Workload"]
        AC2["Agent core"] -->|manifest grants only| WL["Sandboxed workload"]
    end
    subgraph B3["Boundary C: Node vs Peer"]
        P1["Node"] <-->|mutual auth, never implicit| P2["Peer node"]
    end
    subgraph B4["Boundary D: Data plane vs Control plane"]
        DP["Data plane"] -. optional, non-blocking .-> CTRL["Control plane"]
    end
```

Highest-value asset: the **`mw-ca` signing key** (compromise = ability to mint identities). It lives only on the management node, is never distributed, and is the top target in the Phase 4 threat model. Node private keys are the next tier and never leave their node (TPM-sealed where available, software-sealed otherwise).

---

## 7. Identity Lifecycle

```mermaid
stateDiagram-v2
    [*] --> KeyGenerated: generate Ed25519 keypair on first boot
    KeyGenerated --> PendingEnrollment: request enrollment token
    PendingEnrollment --> Enrolled: human-approved single-use token plus CSR, CA issues short-lived cert
    Enrolled --> Rotating: cert nearing expiry
    Rotating --> Enrolled: auto-rotate to fresh short-lived cert
    Enrolled --> UnderReview: indicators lower trust score
    UnderReview --> Enrolled: cleared by evidence
    UnderReview --> Quarantined: trust below threshold
    Quarantined --> Revoked: credentials revoked, evidence preserved
    Quarantined --> ReEnroll: human review approves restoration
    ReEnroll --> KeyGenerated: fresh identity required
    Revoked --> [*]: node removed
```

Restoration never reinstates the old credential — a reviewed node re-enrolls with a fresh identity, closing the door on cloned-key reuse.

---

## 8. Task Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Submitted: signed task manifest
    Submitted --> Rejected: bad signature, policy fail, or expired
    Submitted --> Validated: checks pass
    Validated --> Split: divisible into work units
    Split --> Leased: assigned to worker with lease TTL
    Leased --> Executing: sandbox start, resource-limited
    Executing --> Failed: crash, overrun, or timeout
    Failed --> Leased: retry or reassign per policy
    Executing --> ResultSigned: node signs result plus input and output hashes
    ResultSigned --> Verifying: redundancy, replay, or audit
    Verifying --> Disputed: results disagree
    Disputed --> Leased: re-execute on other nodes
    Disputed --> HumanReview: high-impact task
    Verifying --> Accepted: agreement, plus human approval if high-impact
    Accepted --> [*]: provenance recorded to audit
    Rejected --> [*]
```

---

## 9. Data Flow

```mermaid
flowchart LR
    OP["Operator"] -->|signed task manifest| CT["mw-control / Coordinator"]
    CT -->|validate then split| WU["Work units"]
    WU -->|leased, mTLS| W1["Worker A"]
    WU -->|leased, mTLS| W2["Worker B"]
    WU -->|redundant copy| W3["Worker C"]
    W1 -->|signed result + hashes| VER["Verification"]
    W2 -->|signed result + hashes| VER
    W3 -->|signed result + hashes| VER
    VER -->|accepted + provenance| AUD[("Hash-chained audit")]
    VER -->|status + trust deltas| DASH["Dashboard"]
```

---

## 10. Enrollment Flow

```mermaid
sequenceDiagram
    participant N as New node (mw-agent)
    participant OP as Operator (human)
    participant CT as mw-control (approval)
    participant CA as mw-ca
    N->>N: generate Ed25519 keypair
    N->>CT: request enrollment (pubkey, optional attestation)
    CT->>OP: approval request (purpose, scope, evidence)
    OP-->>CT: approve, issue single-use expiring token
    CT-->>N: enrollment token
    N->>CA: CSR plus enrollment token
    CA->>CA: verify token single-use, unexpired, approved
    CA-->>N: short-lived node certificate
    N->>N: join mesh, begin mTLS with peers
```

---

## 11. Offline Workflow

```mermaid
flowchart TD
    A["Connectivity lost"] --> B{"Held leases valid and unexpired?"}
    B -- yes --> C["Continue executing leased tasks"]
    B -- no --> D["Idle: no new sensitive work"]
    C --> E["Enforce cached signed policy within TTL"]
    E --> F["Sign results, hash-chain audit, queue locally"]
    F --> G{"Needs enroll / grant / restore / human approval?"}
    G -- yes --> H["Refuse: fail safe"]
    G -- no --> I{"Lease, token, or policy TTL expired?"}
    I -- yes --> J["Stop task, mark for re-verification"]
    I -- no --> C
```

Offline permissions are strictly the intersection of what was already leased and what cached, unexpired policy allows. Nothing that grants new authority can happen without the human, and the human path fails safe.

---

## 12. Reconnection Workflow

```mermaid
sequenceDiagram
    participant N as Reconnecting node
    participant P as Peer / coordinator
    participant CT as mw-control
    N->>P: mTLS re-authentication
    P-->>N: nonce challenge; verify cert not revoked
    N->>CT: fetch revocation list and current signed policy
    CT-->>N: CRL plus policy
    N->>N: reconcile clock drift; drop actions on expired windows
    N->>CT: submit queued results and audit with local hashes
    CT->>CT: dedupe by task and unit id; verify hash chains
    CT-->>N: report conflicts if any
    N->>P: re-verify disputed results; escalate high-impact to human
```

---

## 13. Quarantine Workflow (graduated response)

```mermaid
flowchart TD
    IND["Indicators: bad signature, inconsistent results, clock anomaly,<br/>honeytoken access, impossible resource claims, repeated policy violations"] --> TE["Trust engine lowers score"]
    TE --> R1["1. Increase monitoring"]
    R1 --> R2["2. Reduce trust score"]
    R2 --> R3["3. Limit task sensitivity"]
    R3 --> R4["4. Require duplicate verification"]
    R4 --> R5["5. Revoke dataset access"]
    R5 --> R6["6. Isolate workload"]
    R6 --> TH{"Below quarantine threshold?"}
    TH -- no --> R1
    TH -- yes --> Q["7. Quarantine node"]
    Q --> RV["8. Revoke credentials"]
    RV --> EV["9. Preserve logs and evidence"]
    EV --> HR["10. Human review before restore"]
    HR --> RE["Restore via re-enrollment, or keep revoked"]
```

Quarantine isolates the offending node without disrupting the rest of the cluster (`FR-18`): its leases are reassigned, its peers drop its sessions, and unaffected work continues.

---

## 14. Update Workflow (signed, human-approved, rollback-safe)

```mermaid
sequenceDiagram
    participant DEV as Builder
    participant OP as Operator (human)
    participant CT as mw-control
    participant N as mw-agent
    DEV->>CT: signed update artifact (version, hash, signature)
    CT->>OP: release approval (risk, changelog, evidence)
    OP-->>CT: approve release, signed and expiring
    CT-->>N: update available (signed manifest)
    N->>N: verify signature and version monotonicity
    N->>N: stage update, run health check
    alt healthy
        N->>N: commit, report new version
    else unhealthy
        N->>N: rollback to previous, alert
    end
```

---

## 15. Human-Approval Workflow

```mermaid
flowchart TD
    REQ["Sensitive action requested"] --> BUILD["Build approval request:<br/>requester, purpose, scope, risk, evidence, expiry"]
    BUILD --> ROUTE["Route to authorized approver"]
    ROUTE --> DEC{"Approver decision before expiry?"}
    DEC -- approve --> SIGN["Signed approval record, logged"]
    DEC -- reject / timeout / unreachable --> SAFE["Fail safe: action blocked"]
    SIGN --> REVOKE{"Revoked before consumed?"}
    REVOKE -- yes --> SAFE
    REVOKE -- no --> PROCEED["Action proceeds within scope"]
```

Sensitive actions (`HITL-1..3`): approving a node, granting sensitive-dataset access, assigning a high-priority mission, releasing an update, restoring a quarantined node, changing policy, exporting audit evidence, and approving a simulated drone route. Every one produces a signed, expiring, revocable approval record.

---

## 16. From PoC to Proposal (architecture evolution)

| Dimension | PoC | Proposal / scale |
|---|---|---|
| Clusters | 1 (single elected coordinator) | Many, cross-cluster gossip + reconciliation |
| Coordinator | Ephemeral role, plain election | BFT quorum for high-impact scheduling |
| Verification | Redundancy + replay + audit | Threshold signatures, trusted-verifier quorums |
| Identity | Software-sealed keys, TPM-optional | TPM/attestation default, DID interop |
| Approval | Single admin | Multi-admin quorum, m-of-n |
| Audit | Hash-chained log | Merkle-chained, cross-node anchored |
| Crypto | Ed25519/X25519 | Post-quantum hybrid |

Nothing in the PoC data-plane contracts (signed manifests, node-signed results, coordinator-as-non-trust-anchor) needs to change to reach the scaled design — the scale story is additive, which is exactly the narrative the proposal wants.

---

*End of Phase 3. Phase 4 (threat model, STRIDE) builds directly on the trust boundaries and asset list above.*