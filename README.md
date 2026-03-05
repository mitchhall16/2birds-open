# 2birds

Private transactions on Algorand. Deposit ALGO, withdraw to any address — nobody can link the two.

**Try it**: [2birds.pages.dev](https://2birds.pages.dev) (Algorand Testnet)

---

## What is this?

2birds is a privacy pool. You deposit ALGO into a shared pool with other users, and later withdraw the same amount to a completely different address. A zero-knowledge proof guarantees you deposited without revealing *which* deposit is yours.

Think of it like putting cash into a shared jar, getting a receipt, and later redeeming that receipt at a different window. Nobody watching the jar can connect your deposit to your withdrawal.

### How to use it

1. Install [Pera Wallet](https://perawallet.app) and switch to Testnet
2. Get free testnet ALGO from the [dispenser](https://bank.testnet.algorand.network/)
3. Go to [2birds.pages.dev](https://2birds.pages.dev) and connect your wallet
4. Pick a pool tier (0.1, 0.5, or 1.0 ALGO) and deposit
5. Wait for a few other people to deposit
6. Withdraw to any address you want — it's private

### What does it cost?

| Action | You pay |
|--------|---------|
| Deposit | Pool amount + 0.057 ALGO fee |
| Withdraw | 0.05 ALGO (taken from your withdrawal) |

That's it. No subscriptions, no tokens, no hidden fees. The infrastructure runs on Cloudflare's free tier — **$0/month**.

### How private is it?

Your privacy depends on the **anonymity set** — how many people your transaction hides among. If 100 people deposit 1 ALGO and you withdraw, an observer knows you're one of those 100, but not which one. If only 2 people deposited, you're one of 2. More users = better privacy. This is true for every privacy pool, not just 2birds.

---

## For Algorand Developers

### How it works under the hood

```mermaid
graph LR
    A[User deposits ALGO<br/>fixed denomination] --> B[Pool Contract<br/>stores commitment<br/>in Merkle tree]
    B --> C[User generates<br/>withdrawal proof<br/>in browser]
    C --> D[Relayer submits tx<br/>KV replay protection]
    D --> E[Contract verifies<br/>proof signals on-chain]
    E --> F[Pool sends ALGO<br/>to any address]

    style A fill:#4CAF50,color:#fff
    style D fill:#2196F3,color:#fff
    style E fill:#FF9800,color:#fff
    style F fill:#4CAF50,color:#fff
```

- **ZK proofs** generated client-side with snarkjs (PLONK on BN254)
- **Verified on-chain** via PLONK LogicSig — 4 txns at 0.001 ALGO each (30x cheaper than Groth16 app calls)
- **Relayer** submits withdrawals so the user's wallet never touches the withdraw transaction
- **Notes encrypted on-chain** via HPKE — recoverable even if you clear your browser

### Key design decisions

| Decision | Why |
|----------|-----|
| **PLONK over Groth16** | Same security, 30x cheaper (0.007 vs 0.2 ALGO per op) |
| **Relayer** | Without it, the withdrawer submits their own tx — linkable by IP and wallet |
| **Fixed denominations** | If amounts vary, deposits and withdrawals can be matched by amount |
| **HPKE note backup** | Other mixers use localStorage only — clear browser = lose funds |
| **Dual relayers** | No single operator sees all traffic |
| **One-shot verifier lock** | `setPlonkVerifiers` can only be called once — creator can't swap verifiers |
| **Signal binding** | Proof public signals verified on-chain — prevents replay/substitution |
| **Denomination enforcement** | Contract-enforced fixed tiers — prevents commitment-amount mismatch |
| **Falcon PQ mode** | Optional Falcon-1024 post-quantum signing via AVM v12 `falcon_verify` |

### Contracts (Testnet)

| Contract | App ID |
|----------|--------|
| Pool — 0.1 ALGO | `756478534` |
| Pool — 0.5 ALGO | `756478549` |
| Pool — 1.0 ALGO | `756480627` |

PLONK verifier addresses are permanently locked on each pool via one-shot `setPlonkVerifiers`.

### Quick start

```bash
npm install
cd frontend && npm run build                                          # build frontend
cd frontend && npx wrangler pages deploy dist --project-name 2birds   # deploy
cd relayer && npm run deploy                                          # deploy relayer
```

---

## Technical Deep Dive

For Foundation reviewers, auditors, and ZK engineers. Full details in [`docs/`](docs/).

### Architecture

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

    subgraph "Algorand AVM v12"
        PLONK["PLONK LogicSig Verifiers<br/>4 txns per proof, 0.004 ALGO"]
        PP1["Pool 0.1 ALGO"]
        PP5["Pool 0.5 ALGO"]
        PP10["Pool 1.0 ALGO"]
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

### Cryptographic primitives

| Primitive | Implementation | Purpose |
|-----------|---------------|---------|
| PLONK proof system | Circom 2.1.6 + snarkjs, BN254 curve | Membership/insertion proofs |
| LogicSig verification | 4 txns, BN254 pairing check in TEAL | On-chain proof verification (0.004 ALGO) |
| MiMC Sponge | 220 rounds, x^5 Feistel, circomlib-compatible | Merkle tree hashing + commitment |
| HPKE | X25519 + HKDF-SHA256 + ChaCha20-Poly1305 | Encrypted note backup in txn notes |
| Key derivation | HKDF for view keys, MiMC for spend secrets | View/spend separation |
| Privacy addresses | Bech32 `priv1...` (66-byte payload) | Algo pubkey + X25519 view pubkey |
| Merkle tree | Incremental, depth 20, ~1M leaf capacity | Commitment storage + membership proofs |
| Falcon-1024 | NIST Level 5 post-quantum, AVM v12 `falcon_verify` | Optional quantum-safe transaction signing |
| Signal binding | On-chain `verifyProofWithSignals` | Proof replay / parameter substitution prevention |

### Anti-correlation protections

```mermaid
graph LR
    subgraph "Timing"
        BW["Batch Windows<br/>:00 :15 :30 :45"]
        CD["Cooldown<br/>2 min between ops"]
        WJ["Withdraw Jitter<br/>5-30s random delay"]
    end

    subgraph "Pattern"
        ST["Soak Time<br/>≥3 deposits after yours"]
        CL["Cluster Detection<br/>Warning at 3 ops/session"]
        FD["Fixed Denominations<br/>0.1 / 0.5 / 1.0 ALGO"]
    end

    subgraph "Infrastructure"
        DR["Dual Relayers<br/>Random per operation"]
        IH["IP Hashing<br/>SHA-256, never raw"]
        SR["SRI Integrity<br/>SHA-384 on all assets"]
    end
```

### 2birds vs HermesVault

| | 2birds | HermesVault |
|---|---|---|
| **Proof system** | PLONK (circom/snarkjs) | PLONK (gnark/AlgoPlonk) |
| **Cost per op** | ~0.007 ALGO | ~0.007 ALGO |
| **Relayer** | Yes (0.05 ALGO) | No |
| **Denomination tiers** | 0.1 / 0.5 / 1.0 ALGO | 10 / 100 / 1000 ALGO |
| **Unlinkability** | Full — relayer breaks tx graph | Partial — user submits own tx |
| **Note backup** | HPKE encrypted on-chain | localStorage only |
| **View/spend keys** | Yes | No |
| **Privacy addresses** | Yes (priv1...) | No |
| **Anti-correlation** | Soak, cooldown, jitter, cluster | None |
| **Split/combine** | Yes | No |
| **Contract trust** | Immutable (one-shot lock) | Immutable |
| **IP protection** | SHA-256 hashed | Exposed to RPC |
| **SRI integrity** | Yes | No |

### Exploitability scorecard

```mermaid
block-beta
    columns 8
    space:8
    block:2birds:8
        columns 8
        t0["2birds — 7/8 mitigated"]:8
        T1["Timing ✅"] T2["Linking ✅"] T3["IP ✅"] T4["Notes ✅"] T5["Sybil ✅"] T6["Tamper ✅"] T7["Amount ✅"] T8["Anon set ⚠️"]
    end
    space:8
    block:hermes:8
        columns 8
        h0["HermesVault — 2/8 mitigated"]:8
        H1["Timing ⚠️"] H2["Linking ⚠️"] H3["IP ⚠️"] H4["Notes ⚠️"] H5["Sybil ⚠️"] H6["Tamper ⚠️"] H7["Amount ✅"] H8["Anon set ⚠️"]
    end

    style T1 fill:#4CAF50,color:#fff
    style T2 fill:#4CAF50,color:#fff
    style T3 fill:#4CAF50,color:#fff
    style T4 fill:#4CAF50,color:#fff
    style T5 fill:#4CAF50,color:#fff
    style T6 fill:#4CAF50,color:#fff
    style T7 fill:#4CAF50,color:#fff
    style T8 fill:#FF9800,color:#fff
    style H1 fill:#FF9800,color:#fff
    style H2 fill:#FF9800,color:#fff
    style H3 fill:#FF9800,color:#fff
    style H4 fill:#FF9800,color:#fff
    style H5 fill:#FF9800,color:#fff
    style H6 fill:#FF9800,color:#fff
    style H7 fill:#4CAF50,color:#fff
    style H8 fill:#FF9800,color:#fff
    style t0 fill:none,stroke:none,color:#fff
    style h0 fill:none,stroke:none,color:#fff
```

| Attack Vector | 2birds | HermesVault |
|---|---|---|
| Timing correlation | **Mitigated** — jitter, cooldown, batch windows | Vulnerable |
| Deposit-withdraw linking | **Mitigated** — relayer breaks tx graph | Vulnerable — user submits own tx |
| IP metadata | **Mitigated** — SHA-256 hashed | Vulnerable — exposed to RPC |
| Note loss | **Mitigated** — HPKE on-chain backup | Vulnerable — localStorage only |
| Sybil / instant withdraw | **Mitigated** — soak time, cluster detection | Vulnerable |
| Frontend tampering | **Mitigated** — SRI + CSP | Vulnerable |
| Amount correlation | Mitigated — fixed tiers + split/combine | Mitigated — fixed tiers |
| Anonymity set | Depends on usage | Depends on usage |

### Detailed docs

| Doc | Contents |
|-----|----------|
| [Architecture](docs/architecture.md) | System diagrams, deposit/withdraw/privateSend flows, PLONK LogicSig verification, Merkle tree |
| [Cryptography](docs/cryptography.md) | Key derivation, HPKE envelope format, chain scanning, privacy addresses |
| [Security](docs/security.md) | Anti-correlation protections, trust model, exploitability comparison |
| [Contracts](docs/contracts.md) | App IDs, verifier addresses, MBR costs, deployment, project structure |

### Tech stack

Circom 2.1.6 + snarkjs (PLONK/Groth16, BN254) | TealScript | React + Vite | Cloudflare Pages/Workers/R2/KV | IPFS | AVM v12 | Falcon-1024 (optional PQ)

## License

MIT
