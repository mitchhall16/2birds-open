/**
 * HPKE Note Encryption — encrypts deposit notes for recipient scanning.
 *
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║  NOT POST-QUANTUM SECURE                                           ║
 * ║                                                                    ║
 * ║  This module uses DHKEM(X25519, HKDF-SHA256) for key encapsulation.║
 * ║  X25519 (Curve25519 ECDH) is vulnerable to Shor's algorithm on a  ║
 * ║  cryptographically relevant quantum computer.                       ║
 * ║                                                                    ║
 * ║  Risk: "Harvest now, decrypt later" — encrypted note envelopes are ║
 * ║  stored on-chain permanently. An adversary could record them today  ║
 * ║  and decrypt them once a quantum computer is available, revealing   ║
 * ║  deposit secrets, nullifiers, and amounts.                          ║
 * ║                                                                    ║
 * ║  To make this PQ-secure, replace DHKEM(X25519) with a PQ KEM such ║
 * ║  as ML-KEM-768 (FIPS 203, formerly Kyber). This would require:     ║
 * ║    - New envelope format (ML-KEM encapsulated keys are ~1088 bytes ║
 * ║      vs. 32 bytes for X25519)                                      ║
 * ║    - Updated view key derivation (keys.ts) to use ML-KEM keygen   ║
 * ║    - Larger on-chain note storage (app box or note field)          ║
 * ║    - A hybrid KEM (X25519 + ML-KEM) could be used for transition  ║
 * ║                                                                    ║
 * ║  Even with Falcon-1024 signing enabled, note CONFIDENTIALITY is    ║
 * ║  only classically secure (~128-bit) due to this X25519 dependency. ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 */

import { x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core'
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305'
import { scalarToBytes, bytesToScalar, uint64ToBytes, type DepositNote } from './privacy'

// HPKE suite: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
// WARNING: X25519 is NOT post-quantum secure. See module-level comment above.
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
})

// Envelope constants
const ENVELOPE_VERSION = 0x01
const ENVELOPE_SUITE = 0x01 // X25519 + HKDF-SHA256 + ChaCha20Poly1305
const ENCAP_KEY_LEN = 32
const PLAINTEXT_LEN = 76 // secret(32) + nullifier(32) + denomination(8) + leafIndex(4)
const AEAD_TAG_LEN = 16
const CIPHERTEXT_LEN = PLAINTEXT_LEN + AEAD_TAG_LEN // 92
const VIEW_TAG_LEN = 32
const VIEW_EPHEMERAL_LEN = 32
const ENVELOPE_LEN = 1 + 1 + ENCAP_KEY_LEN + CIPHERTEXT_LEN + VIEW_TAG_LEN + VIEW_EPHEMERAL_LEN // 190

const VIEW_TAG_DOMAIN = 'privacy-pool-view-tag'

/**
 * Serialize a deposit note's plaintext fields into 76 bytes.
 */
function serializePlaintext(note: DepositNote): Uint8Array {
  const buf = new Uint8Array(PLAINTEXT_LEN)
  buf.set(scalarToBytes(note.secret), 0)
  buf.set(scalarToBytes(note.nullifier), 32)
  buf.set(uint64ToBytes(note.denomination), 64)
  // leafIndex as 4-byte big-endian
  const li = note.leafIndex
  buf[72] = (li >> 24) & 0xff
  buf[73] = (li >> 16) & 0xff
  buf[74] = (li >> 8) & 0xff
  buf[75] = li & 0xff
  return buf
}

/**
 * Deserialize 76 bytes of plaintext back into deposit note fields.
 */
function deserializePlaintext(buf: Uint8Array): Pick<DepositNote, 'secret' | 'nullifier' | 'denomination' | 'leafIndex'> {
  return {
    secret: bytesToScalar(buf.slice(0, 32)),
    nullifier: bytesToScalar(buf.slice(32, 64)),
    denomination: bytesToScalar(buf.slice(64, 72)),
    leafIndex: ((buf[72] << 24) | (buf[73] << 16) | (buf[74] << 8) | buf[75]) >>> 0,
  }
}

/**
 * Compute a view tag for fast scanning.
 *
 * viewTag = SHA256("privacy-pool-view-tag" || sharedSecret)
 *
 * The shared secret is unique per envelope (ephemeral ECDH), so no additional
 * binding to sender/round params is needed. Previous versions included
 * senderPubkey/firstValid/lastValid which broke relayed deposits (the on-chain
 * sender is the relayer, not the user).
 */
function computeViewTag(sharedSecret: Uint8Array): Uint8Array {
  const encoder = new TextEncoder()
  const domain = encoder.encode(VIEW_TAG_DOMAIN)
  const preimage = new Uint8Array(domain.length + sharedSecret.length)
  preimage.set(domain, 0)
  preimage.set(sharedSecret, domain.length)
  return sha256(preimage)
}

/**
 * Encrypt a deposit note with HPKE using the recipient's X25519 view public key.
 *
 * Envelope format (190 bytes):
 * | version (1B) | suite (1B) | encapsulatedKey (32B) | ciphertext (92B) | viewTag (32B) | viewEphemeral (32B) |
 */
export async function encryptNote(
  note: DepositNote,
  recipientViewPubkey: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = serializePlaintext(note)

  // Import the recipient's view public key for HPKE
  const recipientKey = await suite.kem.deserializePublicKey(recipientViewPubkey.buffer as ArrayBuffer)

  // HPKE seal (single-shot mode)
  const sender = await suite.createSenderContext({ recipientPublicKey: recipientKey })
  const ciphertext = new Uint8Array(await sender.seal(plaintext.buffer as ArrayBuffer))
  const encapsulatedKey = new Uint8Array(sender.enc)

  // Generate ephemeral X25519 keypair for view tag
  const ephemeralPriv = x25519.utils.randomSecretKey()
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv)

  // ECDH for view tag: shared = ephemeralPriv * recipientViewPubkey
  const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientViewPubkey)
  const viewTag = computeViewTag(sharedSecret)

  // Assemble envelope
  const envelope = new Uint8Array(ENVELOPE_LEN)
  let offset = 0
  envelope[offset++] = ENVELOPE_VERSION
  envelope[offset++] = ENVELOPE_SUITE
  envelope.set(encapsulatedKey, offset); offset += ENCAP_KEY_LEN
  envelope.set(ciphertext, offset); offset += CIPHERTEXT_LEN
  envelope.set(viewTag, offset); offset += VIEW_TAG_LEN
  envelope.set(ephemeralPub, offset)

  return envelope
}

/**
 * Fast view tag check — avoids full HPKE decryption.
 * Returns true if this envelope was likely encrypted for the given view key.
 */
export function checkViewTag(
  envelope: Uint8Array,
  viewPrivateKey: Uint8Array,
): boolean {
  if (envelope.length < ENVELOPE_LEN) return false
  if (envelope[0] !== ENVELOPE_VERSION) return false
  if (envelope[1] !== ENVELOPE_SUITE) return false

  // Extract viewTag and viewEphemeral from envelope
  const storedTag = envelope.slice(2 + ENCAP_KEY_LEN + CIPHERTEXT_LEN, 2 + ENCAP_KEY_LEN + CIPHERTEXT_LEN + VIEW_TAG_LEN)
  const ephemeralPub = envelope.slice(2 + ENCAP_KEY_LEN + CIPHERTEXT_LEN + VIEW_TAG_LEN, ENVELOPE_LEN)

  // Recompute: shared = viewPrivate * ephemeralPub
  let sharedSecret: Uint8Array
  try {
    sharedSecret = x25519.getSharedSecret(viewPrivateKey, ephemeralPub)
  } catch {
    return false
  }

  const computedTag = computeViewTag(sharedSecret)

  // Constant-time comparison
  if (computedTag.length !== storedTag.length) return false
  let diff = 0
  for (let i = 0; i < computedTag.length; i++) {
    diff |= computedTag[i] ^ storedTag[i]
  }
  return diff === 0
}

/**
 * Decrypt an HPKE envelope using the recipient's view private key.
 * Returns the deposit note fields or null if decryption fails.
 */
export async function decryptNote(
  envelope: Uint8Array,
  viewPrivateKey: Uint8Array,
): Promise<Pick<DepositNote, 'secret' | 'nullifier' | 'denomination' | 'leafIndex'> | null> {
  if (envelope.length < ENVELOPE_LEN) return null
  if (envelope[0] !== ENVELOPE_VERSION) return null
  if (envelope[1] !== ENVELOPE_SUITE) return null

  const encapsulatedKey = envelope.slice(2, 2 + ENCAP_KEY_LEN)
  const ciphertext = envelope.slice(2 + ENCAP_KEY_LEN, 2 + ENCAP_KEY_LEN + CIPHERTEXT_LEN)

  try {
    // Import the view private key for HPKE
    const recipientKey = await suite.kem.deserializePrivateKey(viewPrivateKey.buffer as ArrayBuffer)

    // HPKE open (single-shot mode)
    const encBuf = new Uint8Array(encapsulatedKey).buffer as ArrayBuffer
    const recipient = await suite.createRecipientContext({
      recipientKey,
      enc: encBuf,
    })
    const plaintext = new Uint8Array(await recipient.open(ciphertext.buffer as ArrayBuffer))

    if (plaintext.length !== PLAINTEXT_LEN) return null
    return deserializePlaintext(plaintext)
  } catch {
    return null
  }
}

/** The expected byte length of an HPKE envelope */
export const HPKE_ENVELOPE_LEN = ENVELOPE_LEN
