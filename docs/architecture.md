# Architecture

## System Overview

```mermaid
graph TB
    subgraph "Frontend — 2birds.pages.dev"
        UI[TransactionFlow UI]
        HOOKS[useTransaction Hook]
        PRIV[privacy.ts — MiMC, notes, recovery]
        TREE[tree.ts — Client-side Merkle tree]
        HPKE[hpke.ts — Encrypted on-chain notes]
        SCAN[scanner.ts — Chain note recovery]
        AC[Anti-Correlation<br/>Soak · Cooldown · Jitter]
        FALCON[Falcon PQ Mode<br/>Optional quantum-safe signing]
    end

    subgraph "ZK Circuits — Circom + snarkjs"
        DC[Deposit ~42K constraints]
        WC[Withdraw ~23K constraints<br/>+ relayer/fee binding]
        PSC[PrivateSend ~44K constraints<br/>+ relayer/fee binding]
        SC[Split ~66K constraints]
        CC[Combine ~66K constraints]
    end

    subgraph "Algorand AVM v12 — Testnet"
        PLONK["PLONK LogicSig Verifiers<br/>4 txns per proof, 0.004 ALGO"]
        PP1["Pool 0.1 ALGO<br/>App 756478534"]
        PP5["Pool 0.5 ALGO<br/>App 756478549"]
        PP10["Pool 1.0 ALGO<br/>App 756480627"]
    end

    subgraph "Infrastructure"
        REL1[Relayer 1<br/>CF Worker + KV]
        REL2[Relayer 2<br/>CF Worker + KV]
        R2[Cloudflare R2<br/>PLONK zkeys]
        IPFS[IPFS Fallback<br/>zkey mirror]
    end

    UI --> HOOKS
    HOOKS --> PRIV & TREE & HPKE & AC
    HOOKS -.->|optional| FALCON
    HOOKS -->|snarkjs| DC & WC & PSC & SC & CC
    HOOKS -->|LogicSig group| PLONK
    HOOKS -->|app call| PP1 & PP5 & PP10
    SCAN -->|indexer| PP1 & PP5 & PP10
    HOOKS -->|fetch zkeys| R2
    R2 -.->|fallback| IPFS
    REL1 & REL2 -->|submit withdrawal| PLONK
    REL1 & REL2 -->|app call| PP1 & PP5 & PP10

    style PLONK fill:#4CAF50,color:#fff
    style AC fill:#e91e63,color:#fff
    style FALCON fill:#9C27B0,color:#fff
```

## Deposit Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant snarkjs
    participant PLONK LogicSig
    participant Pool Contract

    User->>Frontend: deposit(amount, tier)
    Frontend->>Frontend: Check cooldown (2 min) + cluster risk
    Frontend->>Frontend: Derive note (secret, nullifier) from master key
    Frontend->>Frontend: commitment = MiMC(secret, nullifier, amount)
    Frontend->>Frontend: Sync Merkle tree, compute oldRoot → newRoot
    Frontend->>snarkjs: Generate PLONK proof (deposit.wasm + zkey from R2)
    snarkjs-->>Frontend: PLONK proof
    Frontend->>PLONK LogicSig: 4 LogicSig txns (0.004 ALGO)
    Frontend->>Pool Contract: Atomic group: [4× LogicSig, payment, deposit]
    Pool Contract->>Pool Contract: Enforce denomination matches pool tier
    Pool Contract->>Pool Contract: Verify PLONK verifier ran in same group
    Pool Contract->>Pool Contract: verifyProofWithSignals — bind proof to params
    Pool Contract->>Pool Contract: Store commitment in box storage
    Pool Contract->>Pool Contract: Update root + knownRoots history
    Frontend->>Frontend: Encrypt note via HPKE, attach to txn note field
    Pool Contract-->>User: Deposit confirmed
```

## Withdraw Flow (via Relayer)

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant snarkjs
    participant Relayer (random)
    participant PLONK LogicSig
    participant Pool Contract

    User->>Frontend: withdraw(note, recipient)
    Frontend->>Frontend: Check soak time (≥3 deposits since yours)
    Frontend->>Frontend: Check cooldown + cluster risk
    Frontend->>Frontend: Sync Merkle tree, compute proof inputs
    Frontend->>snarkjs: Generate PLONK proof (withdraw.wasm)
    snarkjs-->>Frontend: PLONK proof + public signals
    Frontend->>Frontend: Random jitter delay (5-30s)
    Frontend->>Relayer (random): POST /withdraw {proof, signals, recipient}
    Note right of Relayer (random): Relayer chosen randomly.<br/>KV replay protection.<br/>IP hashed, never stored raw.
    Relayer (random)->>Relayer (random): KV claim payment txn ID (replay protection)
    Relayer (random)->>Relayer (random): Validate fee is integer, within bounds
    Relayer (random)->>PLONK LogicSig: 4 LogicSig txns
    Relayer (random)->>Pool Contract: Atomic group: [4× LogicSig, withdraw]
    Pool Contract->>Pool Contract: verifyProofWithSignals — bind relayer + fee
    Pool Contract->>Pool Contract: Verify root in knownRoots
    Pool Contract->>Pool Contract: Check nullifier not spent, record it
    Pool Contract->>Pool Contract: Send ALGO to recipient
    Pool Contract-->>Relayer (random): Withdrawal confirmed
    Relayer (random)-->>Frontend: txId
```

## PrivateSend Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant snarkjs
    participant PLONK LogicSig
    participant Pool Contract

    User->>Frontend: privateSend(destination)
    Frontend->>Frontend: Derive new note, compute insertion + withdrawal inputs
    Frontend->>snarkjs: Generate combined proof (privateSend.wasm)
    Note right of snarkjs: Single proof covers both<br/>deposit insertion AND<br/>withdrawal membership
    snarkjs-->>Frontend: PLONK proof (9 public signals)
    Frontend->>PLONK LogicSig: 4 LogicSig txns
    Frontend->>Pool Contract: Atomic group: [4× LogicSig, payment, privateSend]
    Pool Contract->>Pool Contract: verifyProofWithSignals — bind relayer + fee
    Pool Contract->>Pool Contract: Insert new commitment + mark nullifier spent
    Pool Contract->>User: Send denomination to destination
```

## PLONK LogicSig Verification

```mermaid
graph TD
    subgraph "PLONK Verification Group (4 LogicSig txns)"
        L1["LogicSig 1<br/>Program contains PLONK<br/>verifier + verification key"]
        L2["LogicSig 2<br/>Proof data chunk 1"]
        L3["LogicSig 3<br/>Proof data chunk 2"]
        L4["LogicSig 4<br/>Public signals"]
        L1 -->|"BN254 pairing check<br/>in LogicSig evaluation"| PASS[Verification passes]
    end

    subgraph "Pool App Call (same atomic group)"
        G[verifyProofWithSignals — bind all params] --> H[Check root in knownRoots]
        H --> I[Check nullifier not spent + no duplicates]
        I --> J[Enforce denomination tier]
        J --> K[Transfer denomination to recipient]
        K --> L[Record nullifier as spent]
    end

    PASS -.->|atomic group| G

    style L1 fill:#4CAF50,color:#fff
    style PASS fill:#2196F3,color:#fff
```

**Why PLONK LogicSig?** Groth16 verification required ~200 inner app calls for opcode budget (~0.2 ALGO). PLONK verification runs inside a LogicSig program — 4 txns at 0.001 ALGO each = 0.004 ALGO. Same cryptographic security, 30x cheaper.

## Merkle Tree (Incremental, Depth 20)

```mermaid
graph TB
    ROOT["Root = MiMC(H_L, H_R)"]
    ROOT --- L15["H Level 15"]
    ROOT --- R15["zero[15]"]
    L15 --- L14["H Level 14"]
    L15 --- R14["zero[14]"]
    L14 --- L13["..."]
    L14 --- R13["..."]
    L13 --- L1["H Level 1"]
    L1 --- LEAF0["Leaf 0<br/>commitment"]
    L1 --- LEAF1["Leaf 1<br/>commitment"]
    R13 --- LEAF2["Leaf 2<br/>commitment"]
    R13 --- EMPTY["zero[0]<br/>(empty)"]

    style LEAF0 fill:#4CAF50,color:#fff
    style LEAF1 fill:#4CAF50,color:#fff
    style LEAF2 fill:#4CAF50,color:#fff
    style EMPTY fill:#666,color:#fff
    style ROOT fill:#2196F3,color:#fff
```

Each leaf is `MiMC(amount, ownerPubKey, blinding, nullifier)`. Siblings are hashed up with MiMC Sponge (220 rounds, x^5 Feistel). Tree supports ~1M deposits (2^20 leaves). Zero hashes initialized on-chain via `initZeroHashes()`.

## Split/Combine Flow

```mermaid
graph LR
    subgraph "Split (1 → 2)"
        A1["Pool A: 1.0 ALGO<br/>withdraw"]
        B1["Pool B: 0.5 ALGO<br/>deposit"]
        B2["Pool B: 0.5 ALGO<br/>deposit"]
        A1 --> B1
        A1 --> B2
    end

    subgraph "Combine (2 → 1)"
        C1["Pool A: 0.5 ALGO<br/>withdraw"]
        C2["Pool A: 0.5 ALGO<br/>withdraw"]
        D1["Pool B: 1.0 ALGO<br/>deposit"]
        C1 --> D1
        C2 --> D1
    end
```
