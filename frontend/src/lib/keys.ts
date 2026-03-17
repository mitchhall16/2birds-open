/**
 * View key derivation for HPKE note encryption/scanning.
 *
 * WARNING: These are X25519 keys (Curve25519 ECDH), which are NOT post-quantum
 * secure. Even when Falcon-1024 signing is enabled, the view key layer remains
 * classically secure only. See hpke.ts for the full security analysis.
 *
 * To make this PQ-secure, view keys would need to be ML-KEM (Kyber) keypairs
 * instead of X25519, which would require a new envelope format in hpke.ts.
 */

import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { scalarToBytes } from './privacy'

const VIEW_KEY_INFO = 'privacy-pool-view-key-v1'

/**
 * Derive an X25519 view keypair from the existing master key.
 * masterKey -> HKDF-SHA256(scalarToBytes(masterKey), info="privacy-pool-view-key-v1") -> 32 bytes -> X25519 private key
 * The spend key remains the masterKey itself (used for secret/nullifier derivation).
 *
 * NOT POST-QUANTUM: X25519 is vulnerable to Shor's algorithm.
 */
export function deriveViewKeypair(masterKey: bigint): {
  privateKey: Uint8Array
  publicKey: Uint8Array
} {
  const ikm = scalarToBytes(masterKey)
  const privateKey = hkdf(sha256, ikm, undefined, new TextEncoder().encode(VIEW_KEY_INFO), 32)
  const publicKey = x25519.getPublicKey(privateKey)
  return { privateKey, publicKey }
}

/**
 * Get just the view public key from a master key (convenience wrapper).
 */
export function getViewPublicKey(masterKey: bigint): Uint8Array {
  return deriveViewKeypair(masterKey).publicKey
}
