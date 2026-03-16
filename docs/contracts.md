# Contracts & Deployment

## Testnet Contracts

| Contract | App ID | Notes |
|----------|--------|-------|
| Pool — 0.1 ALGO | 756813724 | Fixed denomination, PLONK verifiers locked |
| Pool — 0.5 ALGO | 756862750 | Fixed denomination, PLONK verifiers locked |
| Pool — 1.0 ALGO | 756862851 | Fixed denomination, PLONK verifiers locked |
| Withdraw Verifier (Groth16) | 756420114 | Legacy — 6 public signals |
| Deposit Verifier (Groth16) | 756420115 | Legacy — 4 public signals |
| PrivateSend Verifier (Groth16) | 756420116 | Legacy — 9 public signals |
| Budget Helper | 756420102 | NoOp app for Groth16 opcode budget |
| Stealth Registry | 756386179 | Stealth meta-address registry |

## PLONK LogicSig Verifier Addresses (Testnet)

| Circuit | Address |
|---------|---------|
| Withdraw | `Y5EGJIAMTCQJ5VYEPPNHUXLJ2QOAQRFION77ILEOFM63V5DOURIOSLE2XE` |
| Deposit | `T7LRWUZ3PL5RPGNMFDQNU7KETGLG2KKXV2YWODJ4KZFJSN5I3IPQEH7E44` |
| PrivateSend | `ANQG655MULTMHGQVJEEBKUDISGQ7OFNG7WBQXQPHQOKH4LSO5QMNA2KLIE` |

These addresses are permanently locked via `setPlonkVerifiers` (one-shot function — cannot be changed by the creator or anyone else).

## On-Chain Storage (MBR)

| Box Type | Size | MBR Cost |
|----------|------|----------|
| Commitment (cmt) | 32 bytes | 0.0305 ALGO |
| Nullifier (null) | 1 byte | 0.0265 ALGO |
| Root history (kr) | 32 bytes | 0.0305 ALGO |

Each deposit creates ~0.087 ALGO in MBR costs (funded by the deposit transaction's inner payments).

## Infrastructure

| Resource | Provider | Cost |
|----------|----------|------|
| Frontend | Cloudflare Pages | Free |
| Relayer 1 | Cloudflare Workers | Free (100K req/day) |
| Relayer 2 | Cloudflare Workers | Free |
| PLONK zkeys | Cloudflare R2 | Free (10GB/month) |
| zkey fallback | IPFS (kubo) | Free |
| Algorand RPC | Algonode | Free |
| **Total** | | **$0/month** |

## Deployment

```bash
# Deploy contracts + verifiers
npx tsx scripts/deploy-all.ts

# Deploy PLONK-enabled pools
npx tsx scripts/deploy-plonk-pools.ts

# Fund pools + lock PLONK verifiers (one-shot, irreversible)
npx tsx scripts/fund-and-finalize.ts

# Deploy frontend
cd frontend && npm run build && npx wrangler pages deploy dist --project-name 2birds

# Deploy relayer
cd relayer && npm run deploy
```

## Project Structure

```
privacy-sdk/
├── circuits/
│   ├── deposit.circom              # Insertion proof (~42K constraints)
│   ├── withdraw.circom             # Withdrawal proof (~23K constraints)
│   ├── privateSend.circom          # Combined deposit+withdraw (~44K constraints)
│   ├── split.circom                # Split 1→2 across pools
│   ├── combine.circom              # Combine 2→1 across pools
│   ├── merkleTree.circom           # MiMC Merkle tree + commitment hasher
│   ├── build.sh                    # Circuit compilation + trusted setup
│   └── build/                      # WASM, zkeys, vkeys, ptau
├── contracts/
│   ├── privacy-pool.algo.ts        # Pool: deposit, withdraw, privateSend, split, combine
│   ├── generate-plonk-verifier.ts  # Generates PLONK LogicSig TEAL from vkey
│   ├── artifacts/                  # Compiled TealScript ARC-56 artifacts
│   └── *.teal                      # Groth16 verifiers (legacy)
├── frontend/
│   ├── src/
│   │   ├── components/             # TransactionFlow, CostBreakdown, PoolBlob
│   │   ├── hooks/
│   │   │   ├── useTransaction.ts   # Deposit, withdraw, privateSend + anti-correlation
│   │   │   └── usePoolState.ts     # Pool balance, user balance
│   │   ├── lib/
│   │   │   ├── privacy.ts          # MiMC, commitments, notes, R2/IPFS zkey fetching
│   │   │   ├── hpke.ts             # HPKE envelope encrypt/decrypt
│   │   │   ├── scanner.ts          # Chain scanner for note recovery
│   │   │   ├── keys.ts             # View/spend key derivation
│   │   │   ├── address.ts          # Bech32 priv1... privacy addresses
│   │   │   ├── tree.ts             # Client-side MiMC Merkle tree
│   │   │   ├── config.ts           # Contracts, fees, relayers, anti-correlation
│   │   │   └── plonkVerifierLsig.ts # PLONK LogicSig transaction building
│   │   └── styles/
│   ├── public/circuits/            # Groth16 wasm+zkey (PLONK zkeys on R2)
│   ├── scripts/add-sri.sh          # Post-build SRI hash injection
│   └── .env                        # VITE_USE_PLONK_LSIG=true
├── relayer/
│   ├── src/index.ts                # CF Worker — IP hashing, rate limits, pool checks
│   └── wrangler.toml               # Worker config + pool IDs
├── relayer-2/
│   ├── src/index.ts                # Second relayer (separate operator)
│   ├── wrangler.toml
│   └── setup.sh                    # One-shot setup for new relayer operators
├── scripts/
│   ├── deploy-all.ts               # Deploy contracts + verifiers
│   ├── deploy-plonk-pools.ts       # Deploy PLONK-enabled pools
│   └── fund-and-finalize.ts        # Fund pools + lock PLONK verifiers
└── packages/                       # Legacy SDK packages
```
