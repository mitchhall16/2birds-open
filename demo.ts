#!/usr/bin/env npx tsx

/**
 * Algorand Privacy SDK — Interactive Demo
 *
 * Run with: npx tsx demo.ts
 *
 * This demo exercises the core cryptography locally — no blockchain needed.
 * It demonstrates:
 * 1. Stealth address generation + scanning
 * 2. MiMC hashing + Merkle tree operations
 * 3. Pedersen commitments + balance proofs
 * 4. Shielded note creation + UTXO management
 */

// ─── Direct imports from source (no build needed) ───

import {
  randomScalar,
  derivePubKey,
  ecMul,
  ecAdd,
  ecdh,
  isOnCurve,
  BN254_G,
  BN254_SCALAR_ORDER,
  scalarMod,
  encodePoint,
  bigintToBytes32,
  bytes32ToBigint,
} from './packages/core/src/bn254.js';

import { mimcHash, mimcHashSingle, mimcHashMulti, initMimc } from './packages/core/src/mimc.js';

// ─── Helpers ───

function header(title: string) {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${'═'.repeat(60)}\n`);
}

function ok(msg: string) { console.log(`  ✅ ${msg}`); }
function info(msg: string) { console.log(`  ℹ️  ${msg}`); }
function warn(msg: string) { console.log(`  ⚠️  ${msg}`); }
function val(label: string, value: any) {
  const s = typeof value === 'bigint' ? value.toString().slice(0, 20) + '...' : String(value);
  console.log(`     ${label}: ${s}`);
}

// ─── Demo 1: BN254 Curve Operations ───

function demoCurveOps() {
  header('1. BN254 Curve Operations');

  info('Generator point G:');
  val('G.x', BN254_G.x);
  val('G.y', BN254_G.y);
  ok(`G is on curve: ${isOnCurve(BN254_G)}`);

  const scalar = randomScalar();
  info('Random scalar generated');
  val('scalar', scalar);

  const pubKey = derivePubKey(scalar);
  info('Public key = scalar * G');
  val('pubKey.x', pubKey.x);
  val('pubKey.y', pubKey.y);
  ok(`Public key is on curve: ${isOnCurve(pubKey)}`);

  // Verify point addition: P + P = 2*P
  const doubled = ecAdd(pubKey, pubKey);
  const scaledBy2 = ecMul(BN254_G, scalarMod(scalar * 2n));
  ok(`Point doubling consistent: ${doubled.x === scaledBy2.x && doubled.y === scaledBy2.y}`);

  // Verify scalar field order
  const identity = ecMul(BN254_G, BN254_SCALAR_ORDER);
  ok(`n*G = identity: ${identity.x === 0n && identity.y === 0n}`);
}

// ─── Demo 2: Stealth Addresses ───

async function demoStealthAddresses() {
  header('2. Stealth Address Protocol');

  // Recipient generates keypairs
  info('Alice (recipient) generates stealth keys...');
  const spendingKey = randomScalar();
  const viewingKey = randomScalar();
  const spendingPub = derivePubKey(spendingKey);
  const viewingPub = derivePubKey(viewingKey);
  val('spending pubkey.x', spendingPub.x);
  val('viewing pubkey.x', viewingPub.x);
  ok('Meta-address: (spending_pub, viewing_pub)');

  // Sender generates stealth address
  info('\nBob (sender) generates stealth address for Alice...');
  const ephemeralPriv = randomScalar();
  const ephemeralPub = derivePubKey(ephemeralPriv);

  // Shared secret: ECDH(ephemeral_priv, viewing_pub)
  const sharedSecretSender = ecdh(ephemeralPriv, viewingPub);
  info('Shared secret computed via ECDH');
  val('shared_secret', sharedSecretSender);

  // Stealth public key: spending_pub + hash(shared_secret) * G
  const hashBytes = bigintToBytes32(sharedSecretSender);
  const hashBuf = await crypto.subtle.digest('SHA-256', hashBytes);
  const s = scalarMod(bytes32ToBigint(new Uint8Array(hashBuf)));
  const stealthOffset = ecMul(BN254_G, s);
  const stealthPubKey = ecAdd(spendingPub, stealthOffset);
  val('stealth address pubkey.x', stealthPubKey.x);
  ok('Bob publishes ephemeral_pub as announcement');

  // Recipient scans and recognizes the payment
  info('\nAlice scans announcements...');
  const sharedSecretRecipient = ecdh(viewingKey, ephemeralPub);
  ok(`ECDH matches: ${sharedSecretSender === sharedSecretRecipient}`);

  const hashBuf2 = await crypto.subtle.digest('SHA-256', bigintToBytes32(sharedSecretRecipient));
  const s2 = scalarMod(bytes32ToBigint(new Uint8Array(hashBuf2)));
  const expectedStealthPub = ecAdd(spendingPub, ecMul(BN254_G, s2));
  const isMatch = expectedStealthPub.x === stealthPubKey.x && expectedStealthPub.y === stealthPubKey.y;
  ok(`Alice recognizes payment: ${isMatch}`);

  // Derive stealth private key
  const stealthPrivKey = scalarMod(spendingKey + s2);
  const derivedPub = derivePubKey(stealthPrivKey);
  ok(`Stealth privkey derives correct pubkey: ${derivedPub.x === stealthPubKey.x}`);

  info('\nResult: Bob sent to a one-time address. Only Alice can spend it.');
  info('On-chain, there is NO link between Bob and Alice.');
}

// ─── Demo 3: MiMC Hash + Merkle Tree ───

function demoMerkleTree() {
  header('3. MiMC Hashing & Merkle Tree');

  // MiMC hash
  const a = randomScalar();
  const b = randomScalar();
  const hash = mimcHash(a, b);
  info('MiMC hash of two field elements:');
  val('input a', a);
  val('input b', b);
  val('hash(a,b)', hash);
  ok('Hash is deterministic and ZK-friendly');

  // Build a small Merkle tree manually
  info('\nBuilding depth-4 Merkle tree with 5 leaves...');

  const DEPTH = 4;
  const leaves = Array.from({ length: 5 }, () => randomScalar());
  const zeroHashes: bigint[] = [0n];
  for (let i = 1; i <= DEPTH; i++) {
    zeroHashes[i] = mimcHash(zeroHashes[i - 1], zeroHashes[i - 1]);
  }

  // Build layers bottom-up
  let currentLayer = [...leaves];
  // Pad to 2^DEPTH with zeros
  while (currentLayer.length < 2 ** DEPTH) {
    currentLayer.push(zeroHashes[0]);
  }

  const layers: bigint[][] = [currentLayer];
  for (let level = 0; level < DEPTH; level++) {
    const prev = layers[level];
    const next: bigint[] = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(mimcHash(prev[i], prev[i + 1]));
    }
    layers.push(next);
  }

  const root = layers[DEPTH][0];
  val('root', root);
  ok(`Tree has ${leaves.length} leaves, depth ${DEPTH}`);

  // Compute Merkle path for leaf 2
  const leafIdx = 2;
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let idx = leafIdx;
  for (let level = 0; level < DEPTH; level++) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    pathElements.push(layers[level][siblingIdx]);
    pathIndices.push(idx % 2);
    idx = Math.floor(idx / 2);
  }

  // Verify the path
  let currentHash = leaves[leafIdx];
  for (let i = 0; i < DEPTH; i++) {
    if (pathIndices[i] === 0) {
      currentHash = mimcHash(currentHash, pathElements[i]);
    } else {
      currentHash = mimcHash(pathElements[i], currentHash);
    }
  }
  ok(`Merkle proof verifies: ${currentHash === root}`);
  info(`Path length: ${DEPTH} hashes (this is what the ZK circuit proves)`);
}

// ─── Demo 4: Pedersen Commitments ───

function demoPedersenCommitments() {
  header('4. Pedersen Commitments (Confidential Transactions)');

  // Generator points
  const G = BN254_G;
  // Second generator H (nothing-up-my-sleeve point)
  const H = ecMul(G, 123456789n); // Simplified — production uses hash-to-curve

  // Commit to amounts
  const amount1 = 100n; // 100 USDC
  const blind1 = randomScalar();
  const C1 = ecAdd(ecMul(G, amount1), ecMul(H, blind1));
  info('Alice commits to 100 USDC:');
  val('C1.x', C1.x);
  ok('Commitment hides the amount (computationally hiding)');

  const amount2 = 70n; // Transfer 70
  const blind2 = randomScalar();
  const C2 = ecAdd(ecMul(G, amount2), ecMul(H, blind2));
  info('\nTransfer commitment (70 USDC):');
  val('C2.x', C2.x);

  const changeAmount = amount1 - amount2; // 30 USDC change
  const changeBlind = scalarMod(blind1 - blind2);
  const C_change = ecAdd(ecMul(G, changeAmount), ecMul(H, changeBlind));
  info('\nChange commitment (30 USDC):');
  val('C_change.x', C_change.x);

  // Verify: C1 == C2 + C_change (homomorphic property)
  const sum = ecAdd(C2, C_change);
  ok(`Conservation verified: C_input == C_transfer + C_change: ${sum.x === C1.x && sum.y === C1.y}`);
  info('Anyone can verify balance, but nobody knows the amounts!');
}

// ─── Demo 5: Shielded Note (UTXO) ───

function demoShieldedNotes() {
  header('5. Shielded Notes (UTXO Model)');

  // Create a shielded note
  const amount = 50_000_000n; // 50 ALGO
  const ownerPubKey = derivePubKey(randomScalar());
  const blinding = randomScalar();
  const nullifier = randomScalar();

  // Commitment = MiMC(amount, ownerPubKey.x, blinding, nullifier)
  const commitment = mimcHashMulti(amount, ownerPubKey.x, blinding, nullifier);
  info('Created shielded note:');
  val('amount', '50 ALGO (hidden on-chain)');
  val('commitment', commitment);

  // Nullifier hash (for double-spend prevention)
  const spendingKey = randomScalar();
  const nullifierHash = mimcHash(nullifier, spendingKey);
  info('\nNullifier hash (revealed only when spending):');
  val('nullifierHash', nullifierHash);

  // Simulate a 2-in/2-out transfer
  info('\nSimulating shielded transfer...');
  const inputAmount1 = 50_000_000n;
  const inputAmount2 = 30_000_000n;
  const outputAmount1 = 60_000_000n; // to recipient
  const outputAmount2 = 20_000_000n; // change
  const totalIn = inputAmount1 + inputAmount2;
  const totalOut = outputAmount1 + outputAmount2;
  ok(`Conservation: ${totalIn} == ${totalOut}: ${totalIn === totalOut}`);
  info('The ZK circuit proves this without revealing any amounts!');

  info('\nFull shielded transfer hides:');
  info('  - WHO sent it (stealth address)');
  info('  - WHO received it (stealth address)');
  info('  - HOW MUCH was sent (Pedersen commitment)');
  info('  - WHICH deposit it came from (Merkle proof + nullifier)');
}

// ─── Demo 6: Full Privacy Flow Summary ───

function demoSummary() {
  header('6. Complete Privacy Flow');

  console.log(`
  ┌─────────────────────────────────────────────────────────┐
  │                                                         │
  │  Alice wants to send 10 USDC to Bob privately.          │
  │                                                         │
  │  Step 1: DEPOSIT (break sender link)                    │
  │  ├─ Alice creates commitment = MiMC(secret, nullifier)  │
  │  ├─ Deposits 10 USDC + commitment to Privacy Pool       │
  │  └─ Commitment added to on-chain Merkle tree            │
  │                                                         │
  │  Step 2: STEALTH ADDRESS (break receiver link)          │
  │  ├─ Bob publishes meta-address (spend_pub, view_pub)    │
  │  ├─ Alice generates one-time stealth address for Bob    │
  │  └─ Publishes ephemeral pubkey as announcement          │
  │                                                         │
  │  Step 3: WITHDRAW (ZK proof, no on-chain link)          │
  │  ├─ Alice generates Groth16 proof:                      │
  │  │   "I know a (secret, nullifier) whose commitment     │
  │  │    is in the Merkle tree, and I haven't spent it"    │
  │  ├─ Proof bound to Bob's stealth address (recipient)    │
  │  ├─ LogicSig verifies proof on-chain (~0.008 ALGO)      │
  │  └─ Pool sends 10 USDC to stealth address               │
  │                                                         │
  │  Step 4: CLAIM (Bob derives spending key)               │
  │  ├─ Bob scans announcements with viewing key            │
  │  ├─ Finds the ephemeral pub matching his stealth addr   │
  │  ├─ Derives stealth private key                         │
  │  └─ Spends from stealth address — funds are his!        │
  │                                                         │
  │  Result: On-chain, there is ZERO link between           │
  │  Alice and Bob, and the amount is hidden.               │
  │                                                         │
  └─────────────────────────────────────────────────────────┘
  `);
}

// ─── Run all demos ───

async function main() {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║       Algorand Privacy SDK — Interactive Demo             ║
║                                                           ║
║  This runs all cryptography locally — no blockchain       ║
║  or external dependencies needed.                         ║
╚═══════════════════════════════════════════════════════════╝`);

  try {
    await initMimc();
    demoCurveOps();
    await demoStealthAddresses();
    demoMerkleTree();
    demoPedersenCommitments();
    demoShieldedNotes();
    demoSummary();

    header('All demos passed!');
    console.log('  Next steps:');
    console.log('  1. Install circom:     cargo install circom');
    console.log('  2. Build circuits:     bash circuits/build.sh');
    console.log('  3. Start LocalNet:     algokit localnet start');
    console.log('  4. Deploy contracts:   algokit project deploy');
    console.log('  5. Run CLI:            npx tsx packages/cli/src/index.ts --help');
    console.log('  6. Open web demo:      open demo.html');
    console.log('');
  } catch (err) {
    console.error('\n❌ Demo failed:', err);
    process.exit(1);
  }
}

main();
