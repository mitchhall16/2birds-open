import { x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from '@hpke/core'
import { Chacha20Poly1305 } from '@hpke/chacha20poly1305'
import { scalarToBytes, bytesToScalar, uint64ToBytes, type DepositNote } from './privacy'

// HPKE suite: X25519 + HKDF-SHA256 + ChaCha20-Poly1305
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
 * Transaction metadata used for binding the HPKE envelope to a specific transaction.
 * Used in view tag computation to prevent replay attacks.
 */
export interface TxnMetadata {
  senderPubkey: Uint8Array // 32 bytes — sender's Algorand public key
  firstValid: number
  lastValid: number
}

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
    leafIndex: (buf[72] << 24) | (buf[73] << 16) | (buf[74] << 8) | buf[75],
  }
}

/**
 * Compute a view tag for fast scanning.
 *
 * 1. Sender generates ephemeral X25519 keypair (r, R)
 * 2. Shared secret T = r * recipientViewPubkey (ECDH)
 * 3. viewTag = SHA256("privacy-pool-view-tag" || T || senderPubkey || firstValid || lastValid)
 *
 * Scanner: T' = viewPrivate * R, compare tags
 */
function computeViewTag(
  sharedSecret: Uint8Array,
  txnMeta: TxnMetadata,
): Uint8Array {
  const encoder = new TextEncoder()
  const domain = encoder.encode(VIEW_TAG_DOMAIN)
  const fv = uint64ToBytes(txnMeta.firstValid)
  const lv = uint64ToBytes(txnMeta.lastValid)

  const preimage = new Uint8Array(domain.length + sharedSecret.length + txnMeta.senderPubkey.length + 8 + 8)
  let offset = 0
  preimage.set(domain, offset); offset += domain.length
  preimage.set(sharedSecret, offset); offset += sharedSecret.length
  preimage.set(txnMeta.senderPubkey, offset); offset += txnMeta.senderPubkey.length
  preimage.set(fv, offset); offset += 8
  preimage.set(lv, offset)

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
  txnMeta: TxnMetadata,
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
  const viewTag = computeViewTag(sharedSecret, txnMeta)

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
  txnMeta: TxnMetadata,
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

  const computedTag = computeViewTag(sharedSecret, txnMeta)

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
  txnMeta: TxnMetadata,
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
