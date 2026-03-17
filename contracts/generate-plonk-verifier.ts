#!/usr/bin/env npx tsx

/**
 * PLONK LogicSig Verifier Generator for Algorand AVM v11
 *
 * Generates a TEAL LogicSig that verifies snarkjs PLONK proofs using BN254 opcodes.
 * Budget: 2 LogicSig txns in a 16-txn group (16K byte budget, ~15.1K used).
 * Proof/inverses in Note fields (not LogicSig args) to minimize LogicSig size.
 *
 * Group structure:
 *   [0] Payment $0 (LogicSig) — verifier, Note=proof
 *   [1] Payment $0 (relayer)  — Note=VK
 *   [2] Payment $0 (relayer)  — Note=inverses
 *   [3] Payment $0 (LogicSig) — signals carrier, Note=signals (pool reads this)
 *   [4] Withdraw app call (pool checks prevTxn=[3] sender==verifier)
 *   [5-15] Padding txns (relayer)
 *
 * Usage: npx tsx generate-plonk-verifier.ts <plonk_vkey.json> [output.teal]
 */

import fs from 'fs';
import crypto from 'crypto';

interface PlonkVKey {
  protocol: string;
  curve: string;
  nPublic: number;
  power: number;
  k1: string;
  k2: string;
  Qm: string[];
  Ql: string[];
  Qr: string[];
  Qo: string[];
  Qc: string[];
  S1: string[];
  S2: string[];
  S3: string[];
  X_2: string[][];
  w: string;
}

// BN254 field orders
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function toBE32(n: bigint): string {
  return `0x${n.toString(16).padStart(64, '0')}`;
}

const R_HEX = `pushbytes ${toBE32(BN254_R)}`;

// ── TEAL helper generators ──

/** Emit: (a * b) mod r. Leaves result on stack. */
function emitModMul(lines: string[]) {
  lines.push('b*');
  lines.push(R_HEX);
  lines.push('b%');
}

/** Emit: (a + b) mod r. Leaves result on stack. */
function emitModAdd(lines: string[]) {
  lines.push('b+');
  lines.push(R_HEX);
  lines.push('b%');
}

/** Emit: (a - b) mod r = (a + r - b) mod r. Stack: ..., a, b → ..., result */
function emitModSub(lines: string[]) {
  // Compute r - b (safe since b < r), then add a, then mod r
  lines.push(R_HEX);
  lines.push('swap');
  lines.push('b-');  // r - b
  lines.push('b+');  // a + (r - b)
  lines.push(R_HEX);
  lines.push('b%');
}

/** Pad top-of-stack to exactly 32 bytes (left-zero-pad). */
function emitPad32(lines: string[]) {
  lines.push('dup');
  lines.push('len');
  lines.push('pushint 32');
  lines.push('swap');
  lines.push('-');
  lines.push('bzero');
  lines.push('swap');
  lines.push('concat');
}

// ── VK serialization (unchanged) ──

function serializeVK(vkey: PlonkVKey): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(8);
  header.writeUInt32BE(vkey.nPublic, 0);
  header.writeUInt32BE(vkey.power, 4);
  parts.push(header);

  for (const s of [vkey.k1, vkey.k2, vkey.w]) {
    const buf = Buffer.alloc(32);
    const val = BigInt(s);
    for (let i = 31; i >= 0; i--) {
      buf[i] = Number(val >> BigInt((31 - i) * 8) & 0xffn);
    }
    parts.push(buf);
  }

  for (const p of [vkey.Qm, vkey.Ql, vkey.Qr, vkey.Qo, vkey.Qc, vkey.S1, vkey.S2, vkey.S3]) {
    const buf = Buffer.alloc(64);
    const x = BigInt(p[0]);
    const y = BigInt(p[1]);
    for (let i = 31; i >= 0; i--) {
      buf[i] = Number(x >> BigInt((31 - i) * 8) & 0xffn);
      buf[32 + i] = Number(y >> BigInt((31 - i) * 8) & 0xffn);
    }
    parts.push(buf);
  }

  const g2buf = Buffer.alloc(128);
  const coords = [
    BigInt(vkey.X_2[0][0]), BigInt(vkey.X_2[0][1]),
    BigInt(vkey.X_2[1][0]), BigInt(vkey.X_2[1][1]),
  ];
  for (let c = 0; c < 4; c++) {
    for (let i = 31; i >= 0; i--) {
      g2buf[c * 32 + i] = Number(coords[c] >> BigInt((31 - i) * 8) & 0xffn);
    }
  }
  parts.push(g2buf);

  return Buffer.concat(parts);
}

function computeVKHash(vkey: PlonkVKey): Buffer {
  return crypto.createHash('sha256').update(serializeVK(vkey)).digest();
}

function splitVKChunks(vkey: PlonkVKey): Buffer[] {
  const serialized = serializeVK(vkey);
  const chunks: Buffer[] = [];
  for (let i = 0; i < serialized.length; i += 1024) {
    chunks.push(serialized.subarray(i, Math.min(i + 1024, serialized.length)));
  }
  while (chunks.length < 3) chunks.push(Buffer.alloc(0));
  return chunks;
}

// ── Scratch space layout ──
// Proof:     0=A, 1=B, 2=C, 3=Z, 4=T1, 5=T2, 6=T3
//            7=eval_a, 8=eval_b, 9=eval_c, 10=eval_s1, 11=eval_s2, 12=eval_zw
//            13=Wxi, 14=Wxiw
// VK:        20=k1, 21=k2, 22=w, 23=Qm, 24=Ql, 25=Qr, 26=Qo, 27=Qc
//            28=S1_vk, 29=S2_vk, 30=S3_vk, 31=X_2
// Challenges: 32=beta, 33=gamma, 34=alpha, 35=xi, 36=v1, 37=u
// Computed:  38=zh, 39=xin, 40=alpha2, 41=L1, 42=pi_xi
//            43=r0, 44=betaxi
//            45=v2, 46=v3, 47=v4, 48=v5
// Buffers:   50=vk_bytes, 51=signals_bytes, 52=inverses_bytes
// G1 points: 60=D, 61=F, 62=A1, 63=B1
// Temps:     70-79

/**
 * Generate complete PLONK verifier LogicSig TEAL.
 *
 * Fixes from previous version:
 * - Uses `arg 0/1` (LogicSig args) instead of `txna ApplicationArgs`
 * - Correct Fiat-Shamir: beta includes VK points per snarkjs transcript
 * - Complete PI(xi) via Lagrange basis with precomputed inverses
 * - Complete D with gate + permutation + quotient terms
 * - Complete F with all v-batched commitments
 * - E commitment via G1 generator
 * - Correct pairing check
 */
function generatePlonkLsigTeal(vkey: PlonkVKey): string {
  const nPublic = vkey.nPublic;
  const vkHash = computeVKHash(vkey);
  const n = 1 << vkey.power;
  const lines: string[] = [];

  function L(s: string) { lines.push(s); }
  function comment(s: string) { L(`// ${s}`); }
  function blank() { L(''); }

  L('#pragma version 11');
  comment(`PLONK LogicSig Verifier — nPublic=${nPublic}, domain=${n}`);
  blank();

  // ═══ Rekey protection ═══
  // Ensure no transaction in the group can rekey the verifier account.
  // Without this, an attacker could include a txn that rekeys the LogicSig
  // to an attacker-controlled address, then drain all funds.
  comment('=== Rekey protection: no txn in group may rekey ===');
  L('global GroupSize');
  L('store 80 // group_size');
  L('pushint 0');
  L('store 81 // rekey_check_idx');
  L('rekey_check_loop:');
  L('load 81 // idx');
  L('load 80 // group_size');
  L('==');
  L('bnz rekey_check_done');
  L('load 81');
  L('gtxns RekeyTo');
  L('global ZeroAddress');
  L('==');
  L('assert // no transaction may rekey');
  L('load 81');
  L('pushint 1');
  L('+');
  L('store 81');
  L('b rekey_check_loop');
  L('rekey_check_done:');
  blank();

  // ═══ Group index gate ═══
  comment('=== Group structure validation ===');
  comment('Index 0: full verification. Index 3: signals carrier (budget padding).');
  L('txn GroupIndex');
  L('pushint 0');
  L('!=');
  L('bnz budget_padding');
  blank();

  comment('Index 0: verify group has >= 5 txns and index 3 sender matches');
  L('global GroupSize');
  L('pushint 5');
  L('>=');
  L('assert // group must have >= 5 txns');
  L('gtxn 3 Sender');
  L('txn Sender');
  L('==');
  L('assert // gtxn 3 sender must match verifier');
  blank();

  // ═══ Step 1: VK from gtxn 1 Note, verify SHA256 hash ═══
  comment('=== Step 1: Load VK from gtxn 1 Note, verify SHA256 ===');
  L('gtxn 1 Note');
  L('dup');
  L('sha256');
  L(`pushbytes 0x${vkHash.toString('hex')}`);
  L('==');
  L('assert // VK hash mismatch');
  L('store 50 // vk_bytes');
  blank();

  // ═══ Step 2: Parse proof from arg 0 (LogicSig arg, NOT ApplicationArgs) ═══
  comment('=== Step 2: Parse proof (768 bytes) from txn Note ===');
  L('txn Note');
  L('dup');
  L('len');
  L('pushint 768');
  L('==');
  L('assert // proof must be 768 bytes');
  L('store 15 // proof_raw');
  blank();

  const proofSlots: [string, number, number, number][] = [
    ['A', 0, 64, 0], ['B', 64, 64, 1], ['C', 128, 64, 2],
    ['Z', 192, 64, 3], ['T1', 256, 64, 4], ['T2', 320, 64, 5], ['T3', 384, 64, 6],
    ['eval_a', 448, 32, 7], ['eval_b', 480, 32, 8], ['eval_c', 512, 32, 9],
    ['eval_s1', 544, 32, 10], ['eval_s2', 576, 32, 11], ['eval_zw', 608, 32, 12],
    ['Wxi', 640, 64, 13], ['Wxiw', 704, 64, 14],
  ];

  for (const [name, offset, len, slot] of proofSlots) {
    L('load 15');
    if (offset <= 255 && len <= 255) {
      L(`extract ${offset} ${len} // ${name}`);
    } else {
      L(`pushint ${offset}`);
      L(`pushint ${len}`);
      L(`extract3 // ${name}`);
    }
    L(`store ${slot}`);
  }
  blank();

  // ═══ Step 3: Parse signals from gtxn 3 Note ═══
  comment(`=== Step 3: Parse ${nPublic} signals from gtxn 3 Note ===`);
  L('gtxn 3 Note');
  L('dup');
  L('len');
  L(`pushint ${nPublic * 32}`);
  L('==');
  L('assert // signals must be nPublic*32 bytes');
  L('store 51 // signals_bytes');
  blank();

  // ═══ Step 4: Parse precomputed inverses from gtxn 2 Note ═══
  comment(`=== Step 4: Parse ${nPublic} precomputed inverses from gtxn 2 Note ===`);
  L('gtxn 2 Note');
  L('dup');
  L('len');
  L(`pushint ${nPublic * 32}`);
  L('==');
  L('assert // inverses must be nPublic*32 bytes');
  L('store 52 // inverses_bytes');
  blank();

  // ═══ Step 5: Parse VK fields ═══
  comment('=== Step 5: Parse VK fields ===');
  const vkSlots: [string, number, number, number][] = [
    ['k1', 8, 32, 20], ['k2', 40, 32, 21], ['w', 72, 32, 22],
    ['Qm', 104, 64, 23], ['Ql', 168, 64, 24], ['Qr', 232, 64, 25],
    ['Qo', 296, 64, 26], ['Qc', 360, 64, 27],
    ['S1', 424, 64, 28], ['S2', 488, 64, 29], ['S3', 552, 64, 30],
    ['X_2', 616, 128, 31],
  ];

  for (const [name, offset, len, slot] of vkSlots) {
    L('load 50');
    if (offset <= 255 && len <= 255) {
      L(`extract ${offset} ${len}`);
    } else {
      L(`pushint ${offset}`);
      L(`pushint ${len}`);
      L('extract3');
    }
    L(`store ${slot} // ${name}`);
  }
  blank();

  // ═══ Step 6: Fiat-Shamir challenges (matching snarkjs transcript) ═══
  comment('=== Step 6: Fiat-Shamir challenges ===');

  // beta = keccak256(Qm||Ql||Qr||Qo||Qc||S1||S2||S3||signals||A||B||C) mod r
  comment('beta = keccak256(Qm||Ql||Qr||Qo||Qc||S1||S2||S3||signals||A||B||C) mod r');
  L('load 23 // Qm');
  L('load 24 // Ql'); L('concat');
  L('load 25 // Qr'); L('concat');
  L('load 26 // Qo'); L('concat');
  L('load 27 // Qc'); L('concat');
  L('load 28 // S1'); L('concat');
  L('load 29 // S2'); L('concat');
  L('load 30 // S3'); L('concat');
  L('load 51 // signals'); L('concat');
  L('load 0 // A'); L('concat');
  L('load 1 // B'); L('concat');
  L('load 2 // C'); L('concat');
  L('keccak256');
  L(R_HEX); L('b%');
  emitPad32(lines);
  L('store 32 // beta');
  blank();

  // gamma = keccak256(beta) mod r
  comment('gamma = keccak256(beta) mod r');
  L('load 32'); L('keccak256'); L(R_HEX); L('b%');
  emitPad32(lines);
  L('store 33 // gamma');
  blank();

  // alpha = keccak256(beta||gamma||Z) mod r
  comment('alpha = keccak256(beta||gamma||Z) mod r');
  L('load 32'); L('load 33'); L('concat');
  L('load 3 // Z'); L('concat');
  L('keccak256'); L(R_HEX); L('b%');
  emitPad32(lines);
  L('store 34 // alpha');
  blank();

  // xi = keccak256(alpha||T1||T2||T3) mod r
  comment('xi = keccak256(alpha||T1||T2||T3) mod r');
  L('load 34');
  L('load 4 // T1'); L('concat');
  L('load 5 // T2'); L('concat');
  L('load 6 // T3'); L('concat');
  L('keccak256'); L(R_HEX); L('b%');
  emitPad32(lines);
  L('store 35 // xi');
  blank();

  // v1 = keccak256(xi||eval_a||eval_b||eval_c||eval_s1||eval_s2||eval_zw) mod r
  comment('v1 = keccak256(xi||evals) mod r');
  L('load 35');
  for (let i = 7; i <= 12; i++) { L(`load ${i}`); L('concat'); }
  L('keccak256'); L(R_HEX); L('b%');
  emitPad32(lines);
  L('store 36 // v1');
  blank();

  // u = keccak256(Wxi||Wxiw) mod r
  comment('u = keccak256(Wxi||Wxiw) mod r');
  L('load 13'); L('load 14'); L('concat');
  L('keccak256'); L(R_HEX); L('b%');
  emitPad32(lines);
  L('store 37 // u');
  blank();

  // ═══ Step 7: ZH(xi) = xi^n - 1, save xin = xi^n ═══
  comment(`=== Step 7: xin = xi^${n}, zh = xin - 1 ===`);
  L('load 35 // xi');
  for (let i = 0; i < vkey.power; i++) {
    L('dup');
    emitModMul(lines);
  }
  L('dup');
  L('store 39 // xin = xi^n');
  // zh = xin - 1  →  (xin + r - 1) mod r
  L(`pushbytes ${toBE32(1n)}`);
  emitModSub(lines);
  L('store 38 // zh');
  blank();

  // ═══ Step 8: Lagrange basis L_i(xi) with verified precomputed inverses ═══
  // L[i+1](xi) = w^i * zh / (n * (xi - w^i))
  // Frontend passes inv[i] = 1/(n * (xi - w^i)) as arg 1
  // We verify: inv[i] * n * (xi - w^i) ≡ 1 (mod r)
  comment('=== Step 8: Lagrange evaluations with precomputed inverses ===');

  const n_const = toBE32(BigInt(n));

  for (let i = 0; i < nPublic; i++) {
    comment(`L[${i + 1}](xi): w^${i} * zh * inv[${i}]`);

    // Compute w^i
    if (i === 0) {
      L(`pushbytes ${toBE32(1n)} // w^0 = 1`);
    } else if (i === 1) {
      L('load 22 // w^1 = omega');
    } else {
      // w^i = w^(i-1) * w
      L('load 22 // w');
      L(`load 70 // w^${i - 1}`);
      emitModMul(lines);
    }
    L(`store 70 // w^${i}`);

    // Verify inverse: inv[i] * n * (xi - w^i) mod r == 1
    comment(`verify inv[${i}]: inv * n * (xi - w^${i}) mod r == 1`);
    L('load 52 // inverses_bytes');
    const invOff = i * 32;
    if (invOff <= 255) {
      L(`extract ${invOff} 32 // inv[${i}]`);
    } else {
      L(`pushint ${invOff}`); L('pushint 32'); L(`extract3 // inv[${i}]`);
    }
    L(`dup`);
    L(`store 71 // inv[${i}]`);
    // n * (xi - w^i)
    L('load 35 // xi');
    L(`load 70 // w^${i}`);
    emitModSub(lines);
    L(`pushbytes ${n_const} // n`);
    emitModMul(lines);
    // inv * (n * (xi - w^i))
    emitModMul(lines);
    emitPad32(lines);
    L(`pushbytes ${toBE32(1n)}`);
    L('==');
    L(`assert // inv[${i}] verification failed`);

    // L[i+1] = w^i * zh * inv[i]
    L(`load 70 // w^${i}`);
    L('load 38 // zh');
    emitModMul(lines);
    L('load 71 // inv[i]');
    emitModMul(lines);
    emitPad32(lines);
    L(`store ${73 + i} // L[${i + 1}]`);
    blank();
  }

  // ═══ Step 9: PI(xi) = -sum(signal_i * L[i+1]) ═══
  comment('=== Step 9: PI(xi) ===');
  L(`pushbytes ${toBE32(0n)} // accumulator`);
  for (let i = 0; i < nPublic; i++) {
    L('load 51 // signals_bytes');
    const sigOff = i * 32;
    if (sigOff <= 255) {
      L(`extract ${sigOff} 32 // signal[${i}]`);
    } else {
      L(`pushint ${sigOff}`); L('pushint 32'); L(`extract3 // signal[${i}]`);
    }
    L(`load ${73 + i} // L[${i + 1}]`);
    emitModMul(lines);
    // Subtract from accumulator: acc = acc - (signal * L)  →  (acc + r - val) mod r
    emitModSub(lines);
  }
  emitPad32(lines);
  L('store 42 // pi_xi');
  blank();

  // ═══ Step 10: alpha^2 ═══
  comment('=== Step 10: Precompute alpha^2 ===');
  L('load 34 // alpha');
  L('dup');
  emitModMul(lines);
  emitPad32(lines);
  L('store 40 // alpha2');
  blank();

  // ═══ Step 11: r0 scalar ═══
  // r0 = pi - alpha^2*L1 - (eval_a+beta*eval_s1+gamma)*(eval_b+beta*eval_s2+gamma)*(eval_c+gamma)*eval_zw*alpha
  comment('=== Step 11: r0 scalar ===');

  // e2 = alpha^2 * L1
  comment('e2 = alpha2 * L1');
  L('load 40 // alpha2');
  L('load 73 // L[1]');
  emitModMul(lines);
  L('store 70 // e2');

  // e3a = eval_a + beta*eval_s1 + gamma
  comment('e3 = (eval_a+beta*eval_s1+gamma)*(eval_b+beta*eval_s2+gamma)*(eval_c+gamma)*eval_zw*alpha');
  L('load 32 // beta');
  L('load 10 // eval_s1');
  emitModMul(lines);
  L('load 7 // eval_a');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);
  L('store 71 // e3a');

  // e3b = eval_b + beta*eval_s2 + gamma
  L('load 32 // beta');
  L('load 11 // eval_s2');
  emitModMul(lines);
  L('load 8 // eval_b');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);
  L('store 72 // e3b');

  // e3c = eval_c + gamma
  L('load 9 // eval_c');
  L('load 33 // gamma');
  emitModAdd(lines);

  // e3 = e3a * e3b * e3c * eval_zw * alpha
  L('load 71 // e3a');
  emitModMul(lines);
  L('load 72 // e3b');
  emitModMul(lines);
  L('load 12 // eval_zw');
  emitModMul(lines);
  L('load 34 // alpha');
  emitModMul(lines);
  emitPad32(lines);
  L('store 71 // e3');

  // r0 = pi - e2 - e3
  L('load 42 // pi');
  L('load 70 // e2');
  emitModSub(lines);
  L('load 71 // e3');
  emitModSub(lines);
  emitPad32(lines);
  L('store 43 // r0');
  blank();

  // ═══ Step 12: D commitment (linearisation) ═══
  comment('=== Step 12: D commitment ===');

  // --- Gate scalar: eval_ab = eval_a * eval_b ---
  comment('eval_ab = eval_a * eval_b');
  L('load 7'); L('load 8');
  emitModMul(lines);
  emitPad32(lines);
  L('store 70 // eval_ab');

  // --- Z coefficient (permutation + L1 + u) ---
  // betaxi = beta * xi
  comment('z_coeff = alpha*(eval_a+betaxi+gamma)*(eval_b+betaxi*k1+gamma)*(eval_c+betaxi*k2+gamma) + alpha2*L1 + u');
  L('load 32 // beta');
  L('load 35 // xi');
  emitModMul(lines);
  emitPad32(lines);
  L('store 44 // betaxi');

  // z_a = eval_a + betaxi + gamma
  L('load 7 // eval_a');
  L('load 44 // betaxi');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);
  L('store 71 // z_a');

  // z_b = eval_b + betaxi*k1 + gamma
  L('load 44 // betaxi');
  L('load 20 // k1');
  emitModMul(lines);
  L('load 8 // eval_b');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);
  L('store 72 // z_b');

  // z_c = eval_c + betaxi*k2 + gamma
  L('load 44 // betaxi');
  L('load 21 // k2');
  emitModMul(lines);
  L('load 9 // eval_c');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);

  // z_perm = z_a * z_b * z_c * alpha
  L('load 71 // z_a');
  emitModMul(lines);
  L('load 72 // z_b');
  emitModMul(lines);
  L('load 34 // alpha');
  emitModMul(lines);

  // z_coeff = z_perm + alpha2*L1 + u
  L('load 40 // alpha2');
  L('load 73 // L1');
  emitModMul(lines);
  emitModAdd(lines);
  L('load 37 // u');
  emitModAdd(lines);
  emitPad32(lines);
  L('store 71 // z_coeff');

  // --- S3 coefficient (negated) ---
  // s3_coeff = (eval_a+beta*eval_s1+gamma)*(eval_b+beta*eval_s2+gamma)*alpha*beta*eval_zw
  comment('s3_coeff (negated for subtraction)');
  // Reuse e3a, e3b pattern but different formula
  L('load 32 // beta');
  L('load 10 // eval_s1');
  emitModMul(lines);
  L('load 7 // eval_a');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);
  L('store 72 // s3_a');

  L('load 32 // beta');
  L('load 11 // eval_s2');
  emitModMul(lines);
  L('load 8 // eval_b');
  emitModAdd(lines);
  L('load 33 // gamma');
  emitModAdd(lines);

  // s3_coeff = s3_a * s3_b * alpha * beta * eval_zw
  L('load 72 // s3_a');
  emitModMul(lines);
  L('load 34 // alpha');
  emitModMul(lines);
  L('load 32 // beta');
  emitModMul(lines);
  L('load 12 // eval_zw');
  emitModMul(lines);

  // Negate: neg_s3 = r - s3_coeff
  L(R_HEX);
  L('swap');
  L('b-');
  emitPad32(lines);
  L('store 72 // neg_s3_coeff');
  blank();

  // --- Quotient term scalars ---
  // d4 = zh * (T1 + xin*T2 + xin^2*T3), we want neg: neg_zh, neg_zh*xin, neg_zh*xin^2
  comment('quotient scalars: neg_zh, neg_zh*xin, neg_zh*xin^2');
  L('load 38 // zh');
  L(R_HEX);
  L('swap');
  L('b-');
  emitPad32(lines);
  L('store 75 // neg_zh');

  L('load 75 // neg_zh');
  L('load 39 // xin');
  emitModMul(lines);
  emitPad32(lines);
  L('store 76 // neg_zh_xin');

  L('load 39 // xin');
  L('load 39 // xin');
  emitModMul(lines);
  L('store 77 // xin2');
  L('load 75 // neg_zh');
  L('load 77 // xin2');
  emitModMul(lines);
  emitPad32(lines);
  L('store 78 // neg_zh_xin2');
  blank();

  // --- Build D via ec_multi_scalar_mul (10 points) ---
  // D = eval_ab*Qm + eval_a*Ql + eval_b*Qr + eval_c*Qo + z_coeff*Z + neg_s3*S3
  //   + 1*Qc + neg_zh*T1 + neg_zh_xin*T2 + neg_zh_xin2*T3
  comment('D = 10-point MSM (gate + perm + quotient)');

  // Build G1 points buffer: Qm||Ql||Qr||Qo||Z||S3||Qc||T1||T2||T3
  L('load 23 // Qm');
  L('load 24 // Ql'); L('concat');
  L('load 25 // Qr'); L('concat');
  L('load 26 // Qo'); L('concat');
  L('load 3 // Z'); L('concat');
  L('load 30 // S3'); L('concat');
  L('load 27 // Qc'); L('concat');
  L('load 4 // T1'); L('concat');
  L('load 5 // T2'); L('concat');
  L('load 6 // T3'); L('concat');

  // Build scalars buffer: eval_ab||eval_a||eval_b||eval_c||z_coeff||neg_s3||1||neg_zh||neg_zh_xin||neg_zh_xin2
  L('load 70 // eval_ab');
  L('load 7 // eval_a'); L('concat');
  L('load 8 // eval_b'); L('concat');
  L('load 9 // eval_c'); L('concat');
  L('load 71 // z_coeff'); L('concat');
  L('load 72 // neg_s3'); L('concat');
  L(`pushbytes ${toBE32(1n)} // 1 for Qc`); L('concat');
  L('load 75 // neg_zh'); L('concat');
  L('load 76 // neg_zh_xin'); L('concat');
  L('load 78 // neg_zh_xin2'); L('concat');

  L('ec_multi_scalar_mul BN254g1');
  L('store 60 // D');
  blank();

  // ═══ Step 13: F = D + v*A + v^2*B + v^3*C + v^4*S1 + v^5*S2 ═══
  comment('=== Step 13: F commitment ===');

  // Powers of v
  comment('powers of v');
  L('load 36 // v1'); L('dup');
  emitModMul(lines); emitPad32(lines);
  L('store 45 // v2');

  L('load 45 // v2'); L('load 36 // v1');
  emitModMul(lines); emitPad32(lines);
  L('store 46 // v3');

  L('load 46 // v3'); L('load 36 // v1');
  emitModMul(lines); emitPad32(lines);
  L('store 47 // v4');

  L('load 47 // v4'); L('load 36 // v1');
  emitModMul(lines); emitPad32(lines);
  L('store 48 // v5');

  // F = D + 6-point MSM(A,B,C,S1,S2 with v powers, plus D with scalar 1)
  // Actually: F = 1*D + v1*A + v2*B + v3*C + v4*S1 + v5*S2
  comment('F = 6-point MSM: D + v*A + v^2*B + v^3*C + v^4*S1 + v^5*S2');
  // Points: D||A||B||C||S1||S2
  L('load 60 // D');
  L('load 0 // A'); L('concat');
  L('load 1 // B'); L('concat');
  L('load 2 // C'); L('concat');
  L('load 28 // S1'); L('concat');
  L('load 29 // S2'); L('concat');
  // Scalars: 1||v1||v2||v3||v4||v5
  L(`pushbytes ${toBE32(1n)}`);
  L('load 36 // v1'); L('concat');
  L('load 45 // v2'); L('concat');
  L('load 46 // v3'); L('concat');
  L('load 47 // v4'); L('concat');
  L('load 48 // v5'); L('concat');
  L('ec_multi_scalar_mul BN254g1');
  L('store 61 // F');
  blank();

  // ═══ Step 14: E scalar and B1 computation ═══
  // e_val = -r0 + v*eval_a + v^2*eval_b + v^3*eval_c + v^4*eval_s1 + v^5*eval_s2 + u*eval_zw
  comment('=== Step 14: E scalar ===');

  // neg_r0 = r - r0
  L(R_HEX);
  L('load 43 // r0');
  L('b-');
  emitPad32(lines);

  // + v*eval_a
  L('load 36 // v1'); L('load 7 // eval_a');
  emitModMul(lines);
  emitModAdd(lines);

  // + v2*eval_b
  L('load 45 // v2'); L('load 8 // eval_b');
  emitModMul(lines);
  emitModAdd(lines);

  // + v3*eval_c
  L('load 46 // v3'); L('load 9 // eval_c');
  emitModMul(lines);
  emitModAdd(lines);

  // + v4*eval_s1
  L('load 47 // v4'); L('load 10 // eval_s1');
  emitModMul(lines);
  emitModAdd(lines);

  // + v5*eval_s2
  L('load 48 // v5'); L('load 11 // eval_s2');
  emitModMul(lines);
  emitModAdd(lines);

  // + u*eval_zw
  L('load 37 // u'); L('load 12 // eval_zw');
  emitModMul(lines);
  emitModAdd(lines);

  emitPad32(lines);
  L('store 70 // e_val');
  blank();

  // ═══ Step 15: Pairing check ═══
  // A1 = Wxi + u*Wxiw
  // B1 = xi*Wxi + u*xi*w*Wxiw + F - E
  //    = xi*Wxi + u_xi_w*Wxiw + F + neg_e_val*G1_gen
  // Check: e(-A1, X_2) * e(B1, [1]_2) == 1
  comment('=== Step 15: Pairing check ===');

  // A1 = Wxi + u*Wxiw
  comment('A1 = Wxi + u*Wxiw');
  L('load 14 // Wxiw');
  L('load 37 // u');
  L('ec_scalar_mul BN254g1');
  L('load 13 // Wxi');
  L('ec_add BN254g1');
  L('store 62 // A1');

  // Negate A1 (flip y coordinate: y' = p - y)
  comment('negate A1');
  L('load 62 // A1');
  L('extract 0 32 // x');
  L('load 62');
  L('extract 32 32 // y');
  L(`pushbytes ${toBE32(BN254_P)} // field prime p`);
  L('swap');
  L('b-');
  emitPad32(lines);
  L('concat // neg_A1');
  L('store 62 // neg_A1');

  // B1 via 4-point MSM: xi*Wxi + u_xi_w*Wxiw + 1*F + neg_e_val*G1_gen
  comment('B1 = xi*Wxi + u*xi*w*Wxiw + F - E');

  // u_xi_w = u * xi * w
  L('load 37 // u');
  L('load 35 // xi');
  emitModMul(lines);
  L('load 22 // w');
  emitModMul(lines);
  emitPad32(lines);
  L('store 70 // u_xi_w');

  // Fix: u_xi_w was stored to slot 70, but e_val is already in slot 70.
  // Pop the store and use slot 79 for u_xi_w instead.
  lines.pop(); // remove 'store 70 // u_xi_w'
  L('store 79 // u_xi_w');

  // neg_e_val = r - e_val
  L(R_HEX);
  L('load 70 // e_val');
  L('b-');
  emitPad32(lines);
  L('store 78 // neg_e_val');

  // BN254 G1 generator = (1, 2)
  const G1_GEN = '0x' + '00'.repeat(31) + '01' + '00'.repeat(31) + '02';

  // Points (A, second on stack): Wxi || Wxiw || F || G1_gen
  L('load 13 // Wxi');
  L('load 14 // Wxiw'); L('concat');
  L('load 61 // F'); L('concat');
  L(`pushbytes ${G1_GEN} // G1 generator`); L('concat');

  // Scalars (B, top of stack): xi || u_xi_w || 1 || neg_e_val
  L('load 35 // xi');
  L('load 79 // u_xi_w'); L('concat');
  L(`pushbytes ${toBE32(1n)}`); L('concat');
  L('load 78 // neg_e_val'); L('concat');

  L('ec_multi_scalar_mul BN254g1');
  L('store 63 // B1');
  blank();

  // ═══ Final pairing: e(neg_A1, X_2) * e(B1, [1]_2) == 1 ═══
  comment('=== Final pairing check ===');

  // G1 array: neg_A1 || B1
  L('load 62 // neg_A1');
  L('load 63 // B1');
  L('concat');

  // G2 array: X_2 || [1]_2
  // BN254 G2 generator (x_a0, x_a1, y_a0, y_a1) per AVM encoding
  const G2_GEN = '0x' +
    '1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed' +
    '198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2' +
    '12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa' +
    '090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b';

  L('load 31 // X_2');
  L(`pushbytes ${G2_GEN} // G2 generator`);
  L('concat');

  L('ec_pairing_check BN254g1');
  L('assert // PLONK pairing check failed');
  blank();

  L('pushint 1');
  L('return');
  blank();

  // ═══ Budget padding (index 3): signals carrier ═══
  comment('Budget padding txn (index 3): approve if index 0 is same program');
  L('budget_padding:');
  L('gtxn 0 Sender');
  L('txn Sender');
  L('==');
  L('assert // must be grouped with verifier at index 0');
  L('txn Amount');
  L('pushint 0');
  L('==');
  L('assert // must be zero amount');
  L('txn Receiver');
  L('txn Sender');
  L('==');
  L('assert // must be self-payment');
  L('pushint 1');
  L('return');

  return lines.join('\n');
}

// ── Main ──

const args = process.argv.slice(2);
if (args.length < 1) {
  console.log('Usage: npx tsx generate-plonk-verifier.ts <plonk_vkey.json> [output.teal]');
  process.exit(1);
}

const vkeyPath = args[0];
const outputPath = args[1] || vkeyPath.replace('_plonk_vkey.json', '_plonk_verifier.teal');

const vkey: PlonkVKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

if (vkey.protocol !== 'plonk') {
  console.error(`Error: Expected plonk protocol, got ${vkey.protocol}`);
  process.exit(1);
}
if (vkey.curve !== 'bn128') {
  console.error(`Error: Expected bn128 curve, got ${vkey.curve}`);
  process.exit(1);
}

const teal = generatePlonkLsigTeal(vkey);
fs.writeFileSync(outputPath, teal);

const vkHash = computeVKHash(vkey);
const chunks = splitVKChunks(vkey);

console.log(`Generated PLONK LogicSig verifier:`);
console.log(`  Input:     ${vkeyPath}`);
console.log(`  Output:    ${outputPath}`);
console.log(`  VK Hash:   0x${vkHash.toString('hex')}`);
console.log(`  VK Size:   ${serializeVK(vkey).length} bytes`);
console.log(`  Chunks:    ${chunks.length} (${chunks.map(c => c.length).join(', ')} bytes)`);
console.log(`  nPublic:   ${vkey.nPublic}`);
console.log(`  Domain:    ${1 << vkey.power}`);

const chunksPath = outputPath.replace('.teal', '_vk_chunks.json');
fs.writeFileSync(chunksPath, JSON.stringify({
  hash: vkHash.toString('hex'),
  chunks: chunks.map(c => c.toString('hex')),
  nPublic: vkey.nPublic,
  power: vkey.power,
}));
console.log(`  Chunks:    ${chunksPath}`);
