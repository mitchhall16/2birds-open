import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { scalarToBytes } from './privacy'

const VIEW_KEY_INFO = 'privacy-pool-view-key-v1'

/**
 * Derive an X25519 view keypair from the existing master key.
 * masterKey -> HKDF-SHA256(scalarToBytes(masterKey), info="privacy-pool-view-key-v1") -> 32 bytes -> X25519 private key
 * The spend key remains the masterKey itself (used for secret/nullifier derivation).
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
