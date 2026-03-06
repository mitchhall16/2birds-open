/**
 * @2birds/stealth — Key generation and stealth address derivation
 *
 * Implements ERC-5564-style stealth addresses adapted for Algorand using BN254 curve.
 *
 * Protocol:
 * 1. Recipient publishes meta-address: (spending_pub, viewing_pub) on-chain
 * 2. Sender generates ephemeral keypair (r, R = r*G)
 * 3. Sender computes shared secret: s = hash(r * viewing_pub)
 * 4. Sender computes stealth public key: P = spending_pub + s*G
 * 5. Sender publishes R (ephemeral pub) as announcement
 * 6. Recipient scans: for each R, compute s = hash(viewing_priv * R)
 * 7. If spending_pub + s*G matches a known stealth address, it's theirs
 * 8. Recipient derives stealth private key: p = spending_priv + s
 */

import nacl from 'tweetnacl';
import algosdk from 'algosdk';
import {
  type BN254Point,
  type Scalar,
  type StealthMetaAddress,
  type StealthKeys,
  randomScalar,
  derivePubKey,
  ecMul,
  ecAdd,
  scalarMod,
  BN254_G,
  BN254_SCALAR_ORDER,
  encodePoint,
  bigintToBytes32,
  bytes32ToBigint,
} from '@2birds/core';

/** Generate a new stealth keypair (spending + viewing) */
export function generateStealthKeys(): StealthKeys & { metaAddress: StealthMetaAddress } {
  const spendingKey = randomScalar();
  const viewingKey = randomScalar();

  return {
    spendingKey,
    viewingKey,
    metaAddress: {
      spendingPubKey: derivePubKey(spendingKey),
      viewingPubKey: derivePubKey(viewingKey),
    },
  };
}

/** Encode a meta-address to a portable string format: "st:algo:<hex spending pub><hex viewing pub>" */
export function encodeMetaAddress(meta: StealthMetaAddress): string {
  const spendBytes = encodePoint(meta.spendingPubKey);
  const viewBytes = encodePoint(meta.viewingPubKey);
  const combined = new Uint8Array(128);
  combined.set(spendBytes, 0);
  combined.set(viewBytes, 64);
  const hex = Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
  return `st:algo:${hex}`;
}

/** Decode a meta-address from its string representation */
export function decodeMetaAddress(encoded: string): StealthMetaAddress {
  if (!encoded.startsWith('st:algo:')) {
    throw new Error('Invalid stealth meta-address format');
  }
  const hex = encoded.slice(8);
  if (hex.length !== 256) {
    throw new Error('Invalid meta-address length');
  }
  const bytes = new Uint8Array(128);
  for (let i = 0; i < 128; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return {
    spendingPubKey: {
      x: bytes32ToBigint(bytes.slice(0, 32)),
      y: bytes32ToBigint(bytes.slice(32, 64)),
    },
    viewingPubKey: {
      x: bytes32ToBigint(bytes.slice(64, 96)),
      y: bytes32ToBigint(bytes.slice(96, 128)),
    },
  };
}

/**
 * Sender: Generate a stealth address for a recipient.
 * Returns the stealth public key and the ephemeral public key (to publish as announcement).
 */
export async function generateStealthAddress(recipientMeta: StealthMetaAddress): Promise<{
  stealthPubKey: BN254Point;
  ephemeralPubKey: BN254Point;
  viewTag: number;
}> {
  // Generate ephemeral keypair
  const ephemeralPriv = randomScalar();
  const ephemeralPub = derivePubKey(ephemeralPriv);

  // Shared secret via ECDH: s = hash(ephemeral_priv * viewing_pub)
  const dhPoint = ecMul(recipientMeta.viewingPubKey, ephemeralPriv);
  const sharedSecret = await hashSharedSecret(dhPoint);

  // Stealth public key: P = spending_pub + s*G
  const stealthOffset = ecMul(BN254_G, sharedSecret);
  const stealthPubKey = ecAdd(recipientMeta.spendingPubKey, stealthOffset);

  // View tag: first byte of the shared secret (for fast scanning optimization)
  const viewTag = Number(sharedSecret & 0xffn);

  return { stealthPubKey, ephemeralPubKey: ephemeralPub, viewTag };
}

/**
 * Recipient: Check if a stealth address belongs to them.
 * If it does, return the stealth private key for spending.
 */
export async function checkStealthAddress(
  ephemeralPubKey: BN254Point,
  stealthPubKey: BN254Point,
  viewingKey: Scalar,
  spendingKey: Scalar,
  viewTag?: number,
): Promise<{ isOwner: boolean; stealthPrivKey?: Scalar }> {
  // Compute shared secret: s = hash(viewing_priv * ephemeral_pub)
  const dhPoint = ecMul(ephemeralPubKey, viewingKey);
  const sharedSecret = await hashSharedSecret(dhPoint);

  // Quick check using view tag (optimization — avoids expensive EC ops for non-matching)
  if (viewTag !== undefined) {
    const computedTag = Number(sharedSecret & 0xffn);
    if (computedTag !== viewTag) {
      return { isOwner: false };
    }
  }

  // Compute expected stealth public key: P = spending_pub + s*G
  const spendingPub = derivePubKey(spendingKey);
  const stealthOffset = ecMul(BN254_G, sharedSecret);
  const expectedPub = ecAdd(spendingPub, stealthOffset);

  // Check if it matches
  if (expectedPub.x === stealthPubKey.x && expectedPub.y === stealthPubKey.y) {
    // Derive stealth private key: p = spending_priv + s
    const stealthPrivKey = scalarMod(spendingKey + sharedSecret);
    return { isOwner: true, stealthPrivKey };
  }

  return { isOwner: false };
}

/** Hash a DH point to produce a shared secret scalar */
async function hashSharedSecret(dhPoint: BN254Point): Promise<Scalar> {
  const pointBytes = encodePoint(dhPoint);
  // Domain separation: prepend "algo-stealth-v1"
  const domain = new TextEncoder().encode('algo-stealth-v1');
  const input = new Uint8Array(domain.length + pointBytes.length);
  input.set(domain, 0);
  input.set(pointBytes, domain.length);

  const hash = await crypto.subtle.digest('SHA-256', input);
  return scalarMod(bytes32ToBigint(new Uint8Array(hash)));
}

/** Domain separator for BN254→Ed25519 bridge derivation */
const ED25519_BRIDGE_DOMAIN = 'algo-stealth-ed25519';

/**
 * Derive an Ed25519 seed from a BN254 stealth public key.
 * Both sender and recipient can compute the same stealthPubKey via ECDH,
 * so both arrive at the same Algorand address. Third parties cannot
 * compute the stealthPubKey because they lack the ECDH shared secret.
 */
async function deriveEd25519Seed(stealthPubKey: BN254Point): Promise<Uint8Array> {
  const pubBytes = encodePoint(stealthPubKey);
  const domain = new TextEncoder().encode(ED25519_BRIDGE_DOMAIN);
  const input = new Uint8Array(domain.length + pubBytes.length);
  input.set(domain, 0);
  input.set(pubBytes, domain.length);
  const hash = await crypto.subtle.digest('SHA-256', input);
  return new Uint8Array(hash);
}

/**
 * Sender-side: Derive the Algorand address for a stealth public key.
 * The sender knows the stealthPubKey (computed during generateStealthAddress)
 * but not the private key. This returns just the address to send funds to.
 */
export async function stealthPubKeyToAddress(stealthPubKey: BN254Point): Promise<string> {
  const seed = await deriveEd25519Seed(stealthPubKey);
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  return algosdk.encodeAddress(keyPair.publicKey);
}

/**
 * Recipient-side: Derive an Algorand account (address + secret key) from a BN254 stealth private key.
 * The recipient knows the stealthPrivKey (derived during checkStealthAddress)
 * and can compute the corresponding stealthPubKey to get the same Ed25519 keypair.
 *
 * The returned address matches what stealthPubKeyToAddress would return for
 * the corresponding stealth public key, so both parties agree on the address.
 */
export async function stealthKeyToAlgorandAccount(stealthPrivKey: Scalar): Promise<{
  address: string;
  sk: Uint8Array;
}> {
  // Derive stealthPubKey = stealthPrivKey * G on BN254
  const stealthPubKey = derivePubKey(stealthPrivKey);
  // Same derivation as stealthPubKeyToAddress — produces matching address
  const seed = await deriveEd25519Seed(stealthPubKey);
  const keyPair = nacl.sign.keyPair.fromSeed(seed);
  return {
    address: algosdk.encodeAddress(keyPair.publicKey),
    sk: keyPair.secretKey,
  };
}
