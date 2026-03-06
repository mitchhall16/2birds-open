/**
 * @2birds/core — BN254 curve operations
 *
 * BN254 (alt_bn128) curve used by Ethereum ZK precompiles and Algorand AVM v10+.
 * Field prime p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * Scalar order r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */

import type { BN254Point, Scalar } from './types.js';

/** BN254 field prime */
export const BN254_FIELD_PRIME = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/** BN254 scalar field order */
export const BN254_SCALAR_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/** Generator point G of BN254 */
export const BN254_G: BN254Point = {
  x: 1n,
  y: 2n,
};

/**
 * Second generator H for Pedersen commitments.
 * H = hash_to_curve("algo-privacy-pedersen-H")
 * This must be a nothing-up-my-sleeve point — no one knows the discrete log of H w.r.t. G.
 * We derive it by hashing a fixed string and mapping to the curve.
 */
export const BN254_H: BN254Point = {
  x: 8340928774442273902908347751489507964166141328072847253454757992770507913253n,
  y: 11143726253790265847967383906565924103729394639149334440692154862797666155995n,
};

/** The identity (point at infinity) */
export const BN254_IDENTITY: BN254Point = { x: 0n, y: 0n };

/** Modular arithmetic helpers */
export function fieldMod(a: bigint): bigint {
  return ((a % BN254_FIELD_PRIME) + BN254_FIELD_PRIME) % BN254_FIELD_PRIME;
}

export function scalarMod(a: bigint): bigint {
  return ((a % BN254_SCALAR_ORDER) + BN254_SCALAR_ORDER) % BN254_SCALAR_ORDER;
}

/** Modular inverse using extended Euclidean algorithm */
export function modInverse(a: bigint, m: bigint): bigint {
  if (a === 0n) throw new Error('Cannot invert zero');
  a = ((a % m) + m) % m;
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

/** Modular exponentiation */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = ((base % m) + m) % m;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    exp >>= 1n;
    base = (base * base) % m;
  }
  return result;
}

/**
 * Elliptic curve point addition on BN254 (affine coordinates).
 * For on-chain use, this maps to AVM opcode `ec_add BN254g1`.
 */
export function ecAdd(p1: BN254Point, p2: BN254Point): BN254Point {
  // Handle identity
  if (p1.x === 0n && p1.y === 0n) return p2;
  if (p2.x === 0n && p2.y === 0n) return p1;

  const p = BN254_FIELD_PRIME;

  if (p1.x === p2.x) {
    if (p1.y === p2.y) {
      // Point doubling
      return ecDouble(p1);
    }
    // P + (-P) = O (identity)
    return BN254_IDENTITY;
  }

  // Standard addition
  const dx = fieldMod(p2.x - p1.x);
  const dy = fieldMod(p2.y - p1.y);
  const slope = (dy * modInverse(dx, p)) % p;
  const x3 = fieldMod(slope * slope - p1.x - p2.x);
  const y3 = fieldMod(slope * (p1.x - x3) - p1.y);
  return { x: x3, y: y3 };
}

/** Point doubling on BN254 */
export function ecDouble(p: BN254Point): BN254Point {
  if (p.x === 0n && p.y === 0n) return BN254_IDENTITY;
  if (p.y === 0n) return BN254_IDENTITY;

  const fp = BN254_FIELD_PRIME;
  // BN254: y^2 = x^3 + 3, so a = 0
  const num = fieldMod(3n * p.x * p.x); // 3x^2 + a, a=0
  const den = fieldMod(2n * p.y);
  const slope = (num * modInverse(den, fp)) % fp;
  const x3 = fieldMod(slope * slope - 2n * p.x);
  const y3 = fieldMod(slope * (p.x - x3) - p.y);
  return { x: x3, y: y3 };
}

/**
 * Scalar multiplication on BN254 (double-and-add).
 * For on-chain use, this maps to AVM opcode `ec_scalar_mul BN254g1`.
 */
export function ecMul(point: BN254Point, scalar: Scalar): BN254Point {
  scalar = scalarMod(scalar);
  if (scalar === 0n) return BN254_IDENTITY;

  let result = BN254_IDENTITY;
  let current = point;

  while (scalar > 0n) {
    if (scalar & 1n) {
      result = ecAdd(result, current);
    }
    current = ecDouble(current);
    scalar >>= 1n;
  }
  return result;
}

/** Negate a point (reflect over x-axis) */
export function ecNeg(p: BN254Point): BN254Point {
  if (p.x === 0n && p.y === 0n) return BN254_IDENTITY;
  return { x: p.x, y: fieldMod(-p.y) };
}

/** Check if a point is on the BN254 curve (y^2 = x^3 + 3) */
export function isOnCurve(p: BN254Point): boolean {
  if (p.x === 0n && p.y === 0n) return true; // identity
  const fp = BN254_FIELD_PRIME;
  const lhs = fieldMod(p.y * p.y);
  const rhs = fieldMod(p.x * p.x * p.x + 3n);
  return lhs === rhs;
}

/** Encode a BN254 point to 64 bytes (32 bytes x + 32 bytes y, big-endian) */
export function encodePoint(p: BN254Point): Uint8Array {
  const buf = new Uint8Array(64);
  const xBytes = bigintToBytes32(p.x);
  const yBytes = bigintToBytes32(p.y);
  buf.set(xBytes, 0);
  buf.set(yBytes, 32);
  return buf;
}

/** Decode a BN254 point from 64 bytes */
export function decodePoint(buf: Uint8Array): BN254Point {
  if (buf.length !== 64) throw new Error('Point encoding must be 64 bytes');
  return {
    x: bytes32ToBigint(buf.slice(0, 32)),
    y: bytes32ToBigint(buf.slice(32, 64)),
  };
}

/** Convert bigint to 32-byte big-endian Uint8Array */
export function bigintToBytes32(n: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  let val = n;
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return buf;
}

/** Convert 32-byte big-endian Uint8Array to bigint */
export function bytes32ToBigint(buf: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < 32; i++) {
    result = (result << 8n) | BigInt(buf[i]);
  }
  return result;
}

/** Generate a random scalar in the BN254 scalar field */
export function randomScalar(): Scalar {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return scalarMod(bytes32ToBigint(buf));
}

/** Derive a public key from a private key: pubKey = privKey * G */
export function derivePubKey(privKey: Scalar): BN254Point {
  return ecMul(BN254_G, privKey);
}

/**
 * ECDH shared secret: sharedSecret = myPrivKey * theirPubKey
 * Returns the x-coordinate (standard ECDH)
 */
export function ecdh(myPrivKey: Scalar, theirPubKey: BN254Point): bigint {
  const shared = ecMul(theirPubKey, myPrivKey);
  return shared.x;
}
