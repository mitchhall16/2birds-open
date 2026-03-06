/**
 * @2birds/core — Utility functions
 */

import algosdk from 'algosdk';
import { bigintToBytes32, bytes32ToBigint, BN254_SCALAR_ORDER, scalarMod } from './bn254.js';
import type { Scalar, AlgorandAddress, NetworkConfig } from './types.js';

/** Create an algod client from config */
export function createAlgodClient(config: NetworkConfig): algosdk.Algodv2 {
  return new algosdk.Algodv2(config.algodToken, config.algodUrl);
}

/** Create an indexer client from config */
export function createIndexerClient(config: NetworkConfig): algosdk.Indexer | null {
  if (!config.indexerUrl) return null;
  return new algosdk.Indexer(config.indexerToken || '', config.indexerUrl);
}

/** Convert an Algorand address to a field element (mod R) */
export function addressToScalar(addr: AlgorandAddress): Scalar {
  const decoded = algosdk.decodeAddress(addr);
  // Take the first 32 bytes of the public key and reduce mod scalar order
  return scalarMod(bytes32ToBigint(decoded.publicKey));
}

/** Convert a scalar to bytes for use in transactions */
export function scalarToBytes(s: Scalar): Uint8Array {
  return bigintToBytes32(s);
}

/** Convert bytes to a scalar */
export function bytesToScalar(buf: Uint8Array): Scalar {
  if (buf.length > 32) throw new Error('Input too long for scalar');
  const padded = new Uint8Array(32);
  padded.set(buf, 32 - buf.length);
  return scalarMod(bytes32ToBigint(padded));
}

/** Generate a random 32-byte buffer */
export function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/** Hash bytes to a scalar using SHA-256 then reduce mod R */
export async function hashToScalar(data: Uint8Array): Promise<Scalar> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return scalarMod(bytes32ToBigint(new Uint8Array(hash)));
}

/** Concatenate multiple Uint8Arrays */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** Encode a bigint as a variable-length byte array (no zero padding) */
export function bigintToVarBytes(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array([0]);
  const hex = n.toString(16);
  const padded = hex.length % 2 ? '0' + hex : hex;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/** Serialize a deposit note to JSON-safe format */
export function serializeNote(note: { secret: Scalar; nullifier: Scalar; commitment: Scalar; leafIndex: number; denomination: bigint; assetId: number; timestamp: number }): string {
  return JSON.stringify({
    secret: note.secret.toString(),
    nullifier: note.nullifier.toString(),
    commitment: note.commitment.toString(),
    leafIndex: note.leafIndex,
    denomination: note.denomination.toString(),
    assetId: note.assetId,
    timestamp: note.timestamp,
  });
}

/** Deserialize a deposit note from JSON */
export function deserializeNote(json: string): { secret: Scalar; nullifier: Scalar; commitment: Scalar; leafIndex: number; denomination: bigint; assetId: number; timestamp: number } {
  const obj = JSON.parse(json);
  return {
    secret: BigInt(obj.secret),
    nullifier: BigInt(obj.nullifier),
    commitment: BigInt(obj.commitment),
    leafIndex: obj.leafIndex,
    denomination: BigInt(obj.denomination),
    assetId: obj.assetId,
    timestamp: obj.timestamp,
  };
}

/** Sleep for ms milliseconds */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Retry an async operation with exponential backoff */
export async function retry<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelayMs: number = 1000,
): Promise<T> {
  let lastError: Error | undefined;
  for (let i = 0; i <= maxRetries; i++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err as Error;
      if (i < maxRetries) {
        await sleep(baseDelayMs * Math.pow(2, i));
      }
    }
  }
  throw lastError;
}
