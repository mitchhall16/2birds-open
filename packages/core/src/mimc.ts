/**
 * @2birds/core — MiMC Sponge hash function
 *
 * Uses circomlibjs to ensure exact compatibility with circomlib's MiMCSponge circuit.
 * MiMCSponge: Feistel construction, x^5 S-box, 220 rounds, keccak256-derived constants.
 *
 * IMPORTANT: Call initMimc() once before using any hash functions.
 * All hash functions are synchronous after initialization.
 */

import type { Scalar } from './types.js';

// Cached MiMC sponge instance (initialized via WASM)
let mimcSponge: any = null;
let F: any = null;

/**
 * Initialize the MiMC sponge. Must be called once before using hash functions.
 * Loads the circomlibjs WASM implementation (exact match with circomlib circuits).
 */
export async function initMimc(): Promise<void> {
  if (mimcSponge) return; // Already initialized
  const { buildMimcSponge } = await import('circomlibjs');
  mimcSponge = await buildMimcSponge();
  F = mimcSponge.F;
}

function ensureInit(): void {
  if (!mimcSponge) {
    throw new Error('MiMC not initialized. Call await initMimc() first.');
  }
}

/**
 * MiMC sponge hash — hashes arbitrary number of field elements.
 * MiMCSponge(nInputs, 220 rounds, nOutputs=1), key=0.
 *
 * This matches circomlib's MiMCSponge circuit exactly.
 */
export function mimcSpongeHash(inputs: Scalar[], key: Scalar = 0n, nOutputs: number = 1): Scalar {
  ensureInit();
  return F.toObject(mimcSponge.multiHash(inputs.map(BigInt), Number(key), nOutputs));
}

/**
 * MiMC hash of two field elements — primary use case for Merkle trees.
 * hash(left, right) = MiMCSponge([left, right], k=0, nOutputs=1)
 */
export function mimcHash(left: Scalar, right: Scalar): Scalar {
  ensureInit();
  return F.toObject(mimcSponge.multiHash([left, right], 0, 1));
}

/**
 * MiMC hash of a single field element — used for nullifier hashing.
 * hash(x) = MiMCSponge([x], k=0, nOutputs=1)
 */
export function mimcHashSingle(x: Scalar): Scalar {
  ensureInit();
  return F.toObject(mimcSponge.multiHash([x], 0, 1));
}

/**
 * Multi-input MiMC hash — used for commitments with multiple components.
 * hash(a, b, c, ...) = MiMCSponge([a, b, c, ...], k=0, nOutputs=1)
 */
export function mimcHashMulti(...inputs: Scalar[]): Scalar {
  ensureInit();
  return F.toObject(mimcSponge.multiHash(inputs, 0, 1));
}
