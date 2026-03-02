#!/usr/bin/env npx tsx

/**
 * Groth16 Application Verifier Generator for Algorand AVM
 *
 * Takes a snarkjs verification key (vkey.json) and generates a TEAL Application
 * (approval program) that verifies Groth16 proofs using AVM v11+ BN254 opcodes.
 *
 * Deployed as an Application (not a LogicSig) so opcode budget can be pooled
 * via inner transactions. Each inner NoOp call to self adds 700 to the shared
 * budget. A BN254 verifier needs ~145,000 opcodes (scalar muls + ec_pairing_check
 * with 4 BN254 pairs), so ~220 inner calls are created dynamically.
 *
 * Verification equation:
 *   e(A, B) == e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
 *
 * Equivalently (pairing product check):
 *   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
 *
 * Where vk_x = IC[0] + sum(publicSignals[i] * IC[i+1]) for i in 0..nPublic
 *
 * AVM opcodes used:
 *   - ec_scalar_mul BN254g1    (G1 scalar multiplication)
 *   - ec_add BN254g1           (G1 point addition)
 *   - ec_pairing_check BN254g1 (bilinear pairing verification)
 *   - itxn_begin/itxn_submit   (inner txns for budget padding)
 *
 * Usage:
 *   npx tsx generate-verifier.ts <vkey.json> [output.teal]
 *
 * Cost: ~220 inner transaction fees (~0.222 ALGO) for ~150K additional opcode budget
 */

import fs from 'fs';
import path from 'path';

interface VKey {
  protocol: string;
  curve: string;
  nPublic: number;
  vk_alpha_1: string[];
  vk_beta_2: string[][];
  vk_gamma_2: string[][];
  vk_delta_2: string[][];
  IC: string[][];
}

/**
 * Encode a BN254 G1 point (affine) as 64 bytes: x (32 BE) || y (32 BE)
 */
function encodeG1(point: string[]): string {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  return `0x${x.toString(16).padStart(64, '0')}${y.toString(16).padStart(64, '0')}`;
}

/**
 * Encode a BN254 G2 point (affine) as 128 bytes:
 * x_imag (32 BE) || x_real (32 BE) || y_imag (32 BE) || y_real (32 BE)
 *
 * AVM expects: x1 (imaginary), x0 (real), y1 (imaginary), y0 (real)
 * snarkjs vkey gives: [x0, x1], [y0, y1]
 */
function encodeG2(point: string[][]): string {
  const x0 = BigInt(point[0][0]); // real (A0)
  const x1 = BigInt(point[0][1]); // imaginary (A1)
  const y0 = BigInt(point[1][0]); // real (A0)
  const y1 = BigInt(point[1][1]); // imaginary (A1)
  // gnark-crypto / AVM format: A0||A1 = real||imaginary
  return `0x${x0.toString(16).padStart(64, '0')}${x1.toString(16).padStart(64, '0')}${y0.toString(16).padStart(64, '0')}${y1.toString(16).padStart(64, '0')}`;
}

/**
 * Encode a scalar as 32-byte big-endian
 */
function encodeScalar(s: bigint): string {
  return `0x${s.toString(16).padStart(64, '0')}`;
}

/**
 * BN254 G1 field prime for point negation: negate y coordinate
 */
const BN254_FIELD_PRIME = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

function negateG1Y(yStr: string): string {
  const y = BigInt(yStr);
  const negY = BN254_FIELD_PRIME - y;
  return negY.toString();
}

function generateTeal(vkey: VKey): string {
  const nPublic = vkey.nPublic;

  // Pre-encode verification key points
  const alpha_g1 = encodeG1(vkey.vk_alpha_1);
  const beta_g2 = encodeG2(vkey.vk_beta_2);
  const gamma_g2 = encodeG2(vkey.vk_gamma_2);
  const delta_g2 = encodeG2(vkey.vk_delta_2);
  const IC: string[] = vkey.IC.map(p => encodeG1(p));

  const lines: string[] = [];

  lines.push('#pragma version 11');
  lines.push('// Groth16 Verifier Application for Algorand AVM');
  lines.push(`// nPublic: ${nPublic}`);
  lines.push(`// Generated from verification key`);
  lines.push('');

  // ═══════════════════════════════════════════════════════
  // Budget padding: if called with no args, just approve (inner call to self)
  // ═══════════════════════════════════════════════════════
  lines.push('// === Budget padding: approve immediately if no args (inner call) ===');
  lines.push('txn NumAppArgs');
  lines.push('pushint 0');
  lines.push('==');
  lines.push('bnz budget_pad_approve');
  lines.push('');

  // ═══════════════════════════════════════════════════════
  // Step 1: Extract proof points from arg[0]
  // Proof layout in arg[0]: pi_a (64B) || pi_b (128B) || pi_c (64B) = 256 bytes
  // ═══════════════════════════════════════════════════════
  lines.push('// === Step 1: Extract proof from arg[0] (256 bytes) ===');
  lines.push('txna ApplicationArgs 0');
  lines.push('len');
  lines.push('pushint 256');
  lines.push('==');
  lines.push('assert // proof must be 256 bytes');
  lines.push('');

  // Extract pi_a (bytes 0..63)
  lines.push('// pi_a = arg[0][0:64] (G1 point)');
  lines.push('txna ApplicationArgs 0');
  lines.push('extract 0 64');
  lines.push('store 0 // pi_a');
  lines.push('');

  // Extract pi_b (bytes 64..191)
  lines.push('// pi_b = arg[0][64:192] (G2 point)');
  lines.push('txna ApplicationArgs 0');
  lines.push('extract 64 128');
  lines.push('store 1 // pi_b');
  lines.push('');

  // Extract pi_c (bytes 192..255)
  lines.push('// pi_c = arg[0][192:256] (G1 point)');
  lines.push('txna ApplicationArgs 0');
  lines.push('extract 192 64');
  lines.push('store 2 // pi_c');
  lines.push('');

  // ═══════════════════════════════════════════════════════
  // Step 2: Extract public signals from arg[1]
  // Public signals layout in arg[1]: nPublic * 32 bytes (scalars)
  // ═══════════════════════════════════════════════════════
  lines.push(`// === Step 2: Extract ${nPublic} public signals from arg[1] (${nPublic * 32} bytes) ===`);
  lines.push('txna ApplicationArgs 1');
  lines.push('len');
  lines.push(`pushint ${nPublic * 32}`);
  lines.push('==');
  lines.push('assert // public signals must be nPublic * 32 bytes');
  lines.push('');

  // ═══════════════════════════════════════════════════════
  // Step 3: Pad opcode budget via inner NoOp calls to self
  // Must happen BEFORE any EC operations (ec_scalar_mul, ec_add, ec_pairing_check).
  // Each inner app call adds 700 to shared budget.
  // Loop until budget >= 150,000 (typically ~220 inner calls).
  // ═══════════════════════════════════════════════════════
  // The budget helper app ID is passed as foreign app (Applications[1]).
  // Self-calls are not allowed on AVM, so we call a separate tiny app.
  lines.push('// === Step 3: Pad opcode budget via inner calls to budget helper ===');
  lines.push('budget_pad_loop:');
  lines.push('global OpcodeBudget');
  lines.push('pushint 150000');
  lines.push('>');
  lines.push('bnz budget_pad_done');
  lines.push('itxn_begin');
  lines.push('pushint 6 // appl');
  lines.push('itxn_field TypeEnum');
  lines.push('txna Applications 1 // budget helper app from foreign apps');
  lines.push('itxn_field ApplicationID');
  lines.push('pushint 0');
  lines.push('itxn_field Fee');
  lines.push('itxn_submit');
  lines.push('b budget_pad_loop');
  lines.push('budget_pad_done:');
  lines.push('');

  // ═══════════════════════════════════════════════════════
  // Step 4: Compute vk_x = IC[0] + sum(publicSignals[i] * IC[i+1])
  // ═══════════════════════════════════════════════════════
  lines.push('// === Step 4: Compute vk_x = IC[0] + sum(signals[i] * IC[i+1]) ===');
  lines.push('');

  // Start with IC[0]
  lines.push(`// vk_x = IC[0]`);
  lines.push(`pushbytes ${IC[0]}`);
  lines.push('store 10 // vk_x = IC[0]');
  lines.push('');

  // For each public signal: vk_x += signal[i] * IC[i+1]
  for (let i = 0; i < nPublic; i++) {
    lines.push(`// vk_x += signal[${i}] * IC[${i + 1}]`);
    // Push IC point first (A = point, 64 bytes), then signal scalar (B = scalar, 32 bytes)
    lines.push(`pushbytes ${IC[i + 1]}`);
    lines.push('txna ApplicationArgs 1');
    lines.push(`extract ${i * 32} 32`);
    lines.push('ec_scalar_mul BN254g1');
    // Add to vk_x
    lines.push('load 10');
    lines.push('swap');
    lines.push('ec_add BN254g1');
    lines.push('store 10 // vk_x updated');
    lines.push('');
  }

  // ═══════════════════════════════════════════════════════
  // Step 5: Negate pi_a for pairing product check
  // -A = (A.x, field_prime - A.y)
  // ═══════════════════════════════════════════════════════
  lines.push('// === Step 5: Negate pi_a (flip y coordinate) ===');
  lines.push('load 0 // pi_a');
  lines.push('extract 0 32 // A.x');
  lines.push('load 0 // pi_a');
  lines.push('extract 32 32 // A.y');
  // Compute field_prime - A.y using byte math
  // We push the field prime and subtract
  lines.push(`pushbytes 0x${BN254_FIELD_PRIME.toString(16).padStart(64, '0')} // field prime`);
  lines.push('swap');
  lines.push('b- // field_prime - A.y');
  // Pad result back to 32 bytes
  lines.push('dup');
  lines.push('len');
  lines.push('pushint 32');
  lines.push('swap');
  lines.push('-');
  lines.push('bzero');
  lines.push('swap');
  lines.push('concat // left-pad to 32 bytes');
  lines.push('// Stack: A.x, neg_A.y');
  lines.push('concat // -A = A.x || neg_A.y');
  lines.push('store 3 // -pi_a (negated)');
  lines.push('');

  // ═══════════════════════════════════════════════════════
  // Step 6: Build pairing input arrays and verify
  // Pairing check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
  //
  // G1 array (4 points, 64 bytes each = 256 bytes): -A || alpha || vk_x || C
  // G2 array (4 points, 128 bytes each = 512 bytes): B || beta || gamma || delta
  // ═══════════════════════════════════════════════════════
  lines.push('// === Step 6: Pairing check ===');
  lines.push('// G1 array: -A || alpha || vk_x || C');
  lines.push('load 3 // -A');
  lines.push(`pushbytes ${alpha_g1} // alpha`);
  lines.push('concat');
  lines.push('load 10 // vk_x');
  lines.push('concat');
  lines.push('load 2 // C');
  lines.push('concat');
  lines.push('');

  lines.push('// G2 array: B || beta || gamma || delta');
  lines.push('load 1 // B');
  lines.push(`pushbytes ${beta_g2} // beta`);
  lines.push('concat');
  lines.push(`pushbytes ${gamma_g2} // gamma`);
  lines.push('concat');
  lines.push(`pushbytes ${delta_g2} // delta`);
  lines.push('concat');
  lines.push('');

  lines.push('// Verify: e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1');
  lines.push('ec_pairing_check BN254g1');
  lines.push('assert // pairing check must pass');
  lines.push('');
  lines.push('pushint 1 // approve');
  lines.push('return');
  lines.push('');
  lines.push('// Budget padding entry point — approve immediately');
  lines.push('budget_pad_approve:');
  lines.push('pushint 1');
  lines.push('return');

  return lines.join('\n');
}

function generateClearProgram(): string {
  return '#pragma version 11\npushint 1\nreturn';
}

// ═══════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════
const args = process.argv.slice(2);
if (args.length < 1) {
  console.log('Usage: npx tsx generate-verifier.ts <vkey.json> [output.teal]');
  console.log('');
  console.log('Generates a TEAL Application (approval program) that verifies Groth16 proofs on Algorand AVM.');
  process.exit(1);
}

const vkeyPath = args[0];
const outputPath = args[1] || vkeyPath.replace('_vkey.json', '_verifier.teal');
const clearOutputPath = outputPath.replace('.teal', '_clear.teal');

const vkey: VKey = JSON.parse(fs.readFileSync(vkeyPath, 'utf-8'));

if (vkey.protocol !== 'groth16') {
  console.error(`Error: Expected groth16 protocol, got ${vkey.protocol}`);
  process.exit(1);
}

if (vkey.curve !== 'bn128') {
  console.error(`Error: Expected bn128 curve, got ${vkey.curve}`);
  process.exit(1);
}

const teal = generateTeal(vkey);
fs.writeFileSync(outputPath, teal);

const clearTeal = generateClearProgram();
fs.writeFileSync(clearOutputPath, clearTeal);

console.log(`Generated Groth16 verifier Application:`);
console.log(`  Input:    ${vkeyPath}`);
console.log(`  Approval: ${outputPath}`);
console.log(`  Clear:    ${clearOutputPath}`);
console.log(`  Public signals: ${vkey.nPublic}`);
console.log(`  IC points: ${vkey.IC.length}`);
console.log(`  TEAL version: 11`);
console.log(`  Budget padding: dynamic (target 70,000 opcodes)`);
