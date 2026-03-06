/**
 * @2birds/circuits — Circuit artifact paths and metadata
 *
 * Provides paths to compiled circuit artifacts (WASM, zKey, vKey)
 * and metadata about each circuit (constraint count, public inputs, etc.).
 *
 * After building circuits with `npm run build:circuits`, the artifacts
 * are copied to the `artifacts/` directory and can be referenced here.
 */

import { fileURLToPath } from 'url';
import path from 'path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ARTIFACTS_DIR = path.resolve(__dirname, '..', 'artifacts');

/** Circuit metadata */
export interface CircuitInfo {
  name: string;
  description: string;
  constraintEstimate: number;
  publicInputs: string[];
  wasmPath: string;
  zkeyPath: string;
  vkeyPath: string;
}

/** Withdrawal circuit — privacy pool mixer */
export const WITHDRAW_CIRCUIT: CircuitInfo = {
  name: 'withdraw',
  description: 'Privacy pool withdrawal — proves Merkle membership without revealing which deposit',
  constraintEstimate: 30_000,
  publicInputs: ['root', 'nullifierHash', 'recipient', 'relayer', 'fee'],
  wasmPath: path.join(ARTIFACTS_DIR, 'withdraw_js', 'withdraw.wasm'),
  zkeyPath: path.join(ARTIFACTS_DIR, 'withdraw_final.zkey'),
  vkeyPath: path.join(ARTIFACTS_DIR, 'withdraw_vkey.json'),
};

/** Range proof circuit — confidential transactions */
export const RANGE_PROOF_CIRCUIT: CircuitInfo = {
  name: 'range_proof',
  description: 'Confidential transfer — proves amounts are non-negative and conserved',
  constraintEstimate: 50_000,
  publicInputs: ['inputCommitmentHash', 'outputCommitmentHash', 'feeCommitmentHash'],
  wasmPath: path.join(ARTIFACTS_DIR, 'range_proof_js', 'range_proof.wasm'),
  zkeyPath: path.join(ARTIFACTS_DIR, 'range_proof_final.zkey'),
  vkeyPath: path.join(ARTIFACTS_DIR, 'range_proof_vkey.json'),
};

/** Shielded transfer circuit — full privacy UTXO */
export const SHIELDED_TRANSFER_CIRCUIT: CircuitInfo = {
  name: 'shielded_transfer',
  description: 'Full shielded transfer — 2-in/2-out UTXO with membership, nullifiers, conservation, range proofs',
  constraintEstimate: 150_000,
  publicInputs: ['root', 'nullifierHashes', 'outputCommitments'],
  wasmPath: path.join(ARTIFACTS_DIR, 'shielded_transfer_js', 'shielded_transfer.wasm'),
  zkeyPath: path.join(ARTIFACTS_DIR, 'shielded_transfer_final.zkey'),
  vkeyPath: path.join(ARTIFACTS_DIR, 'shielded_transfer_vkey.json'),
};

/** All available circuits */
export const ALL_CIRCUITS: CircuitInfo[] = [
  WITHDRAW_CIRCUIT,
  RANGE_PROOF_CIRCUIT,
  SHIELDED_TRANSFER_CIRCUIT,
];

/** Get circuit by name */
export function getCircuit(name: string): CircuitInfo | undefined {
  return ALL_CIRCUITS.find(c => c.name === name);
}

/** Check if circuit artifacts exist (have been built) */
export function isCircuitBuilt(circuit: CircuitInfo): boolean {
  const fs = require('fs');
  return fs.existsSync(circuit.wasmPath) &&
         fs.existsSync(circuit.zkeyPath) &&
         fs.existsSync(circuit.vkeyPath);
}
