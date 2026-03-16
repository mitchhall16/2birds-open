/**
 * Algorand Deterministic Falcon-1024 WASM module.
 * Built from github.com/algorand/falcon via Emscripten.
 */

/** Generate a keypair from a seed (deterministic). */
export function keyPairFromSeed(seed: Uint8Array): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
}>

/** Generate a keypair with a random seed. */
export function keyPair(): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
}>

/** Sign a message (detached signature, compressed format). */
export function signDetached(
  message: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array>

/** Verify a detached signature. */
export function verifyDetached(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean>

/** Public key size in bytes (1793 for Falcon-1024). */
export function publicKeyBytes(): Promise<number>

/** Private key size in bytes. */
export function privateKeyBytes(): Promise<number>

/** Maximum signature size in bytes. */
export function signatureMaxBytes(): Promise<number>
