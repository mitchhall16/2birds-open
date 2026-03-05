/**
 * Falcon-1024 Post-Quantum Signing for Algorand LogicSig
 *
 * Provides deterministic Falcon keypair derivation from master key,
 * TEAL LogicSig compilation (AVM v12), and transaction signing.
 *
 * The Falcon public key is embedded in a small TEAL program → LogicSig contract account.
 * That address becomes the user's quantum-safe address. All pool operations are signed
 * by Falcon locally — no wallet popup needed.
 */

import algosdk from 'algosdk'
import { scalarToBytes } from './privacy'

// ── Types ──

export interface FalconAccount {
  publicKey: Uint8Array
  privateKey: Uint8Array
  program: Uint8Array
  address: string
}

// ── Cache (module-level, survives re-renders) ──

let _cachedKeypair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null
let _cachedProgram: Uint8Array | null = null
let _cachedAddress: string | null = null
let _cachedMasterKey: bigint | null = null
let _cachedPubkeyHex: string | null = null

// ── Utilities ──

/** Base32 (RFC 4648) decoder for converting txn.txID() to raw 32-byte hash */
function base32Decode(s: string): Uint8Array {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0, value = 0, idx = 0
  const out = new Uint8Array(Math.ceil(s.length * 5 / 8))
  for (const c of s) {
    const v = A.indexOf(c)
    if (v === -1) continue
    value = (value << 5) | v
    bits += 5
    if (bits >= 8) {
      out[idx++] = (value >>> (bits - 8)) & 0xff
      bits -= 8
    }
  }
  return out.slice(0, idx)
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Lazy-load falcon-crypto (WASM, ~500KB). Only loaded when Falcon mode is enabled. */
async function loadFalcon() {
  const mod = await import('falcon-crypto')
  return (mod as any).default ?? (mod as any).falcon ?? mod
}

// ── Key Derivation ──

/**
 * Derive a deterministic Falcon-1024 keypair from a master key.
 *
 * Uses HKDF(SHA-256) to derive a seed, then AES-CTR to expand it into a
 * deterministic byte stream that replaces crypto.getRandomValues during keygen.
 * Same master key → same keypair → same LogicSig address on any device.
 */
export async function deriveFalconKeypair(masterKey: bigint): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
}> {
  if (_cachedKeypair && _cachedMasterKey === masterKey) return _cachedKeypair

  const masterKeyBytes = scalarToBytes(masterKey)

  // Derive 48-byte seed via HKDF: 32 for AES key + 16 for IV
  // Use a proper domain-specific salt (SHA-256 of a fixed string)
  const hkdfSalt = new Uint8Array(await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode('privacy-pool-falcon-salt-v1'),
  ))
  const baseKey = await crypto.subtle.importKey('raw', masterKeyBytes.buffer as ArrayBuffer, 'HKDF', false, ['deriveBits'])
  const seedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: hkdfSalt,
      info: new TextEncoder().encode('falcon-1024-keypair'),
    },
    baseKey,
    48 * 8,
  )
  const seed = new Uint8Array(seedBits)

  // Pre-generate deterministic random bytes using AES-CTR
  // Falcon-1024 keygen needs ~10KB of randomness; allocate 100KB to be safe
  const aesKey = await crypto.subtle.importKey(
    'raw', seed.slice(0, 32), { name: 'AES-CTR' }, false, ['encrypt'],
  )
  const iv = new Uint8Array(16)
  iv.set(seed.slice(32, 48))
  const randomPool = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: iv, length: 128 },
      aesKey,
      new Uint8Array(100_000),
    ),
  )

  // Pre-load Falcon WASM before overriding crypto.getRandomValues
  // This prevents the dynamic import's await from yielding to the microtask queue
  // while crypto is monkey-patched (which would give concurrent code deterministic bytes)
  const falcon = await loadFalcon()

  // Temporarily replace crypto.getRandomValues with seeded deterministic version
  // Window is now minimal: only the synchronous keyPair() call runs under the override
  let poolOffset = 0
  const originalGRV = crypto.getRandomValues.bind(crypto)

  Object.defineProperty(crypto, 'getRandomValues', {
    value: <T extends ArrayBufferView>(array: T): T => {
      const u8 = new Uint8Array(array.buffer, array.byteOffset, array.byteLength)
      if (poolOffset + u8.length > randomPool.length) {
        throw new Error('Seeded RNG exhausted during Falcon keygen')
      }
      u8.set(randomPool.subarray(poolOffset, poolOffset + u8.length))
      poolOffset += u8.length
      return array
    },
    writable: true,
    configurable: true,
  })

  try {
    const keypair = await falcon.keyPair()
    _cachedKeypair = keypair
    _cachedMasterKey = masterKey
    return keypair
  } finally {
    Object.defineProperty(crypto, 'getRandomValues', {
      value: originalGRV,
      writable: true,
      configurable: true,
    })
  }
}

// ── TEAL Compilation ──

/**
 * Compile a Falcon-1024 LogicSig TEAL program with embedded public key.
 *
 * The TEAL program verifies that arg[0] is a valid Falcon-1024 signature
 * of `txn TxID` under the embedded public key. Requires AVM v12.
 *
 * Program size: ~1813 bytes (1793 pubkey + 20 TEAL opcodes)
 * LogicSig with signature: ~3093 bytes (program + ~1280 byte Falcon sig)
 * falcon_verify cost: 1700 opcodes out of 20,000 budget
 */
export async function compileFalconProgram(
  client: algosdk.Algodv2,
  pubkey: Uint8Array,
): Promise<{ program: Uint8Array; address: string }> {
  // Validate cache matches the provided pubkey (prevents stale program after wallet switch)
  if (_cachedProgram && _cachedAddress && _cachedPubkeyHex === bytesToHex(pubkey)) {
    return { program: _cachedProgram, address: _cachedAddress }
  }

  const pubkeyHex = bytesToHex(pubkey)

  // AVM v12 TEAL: verify Falcon-1024 signature over transaction ID
  // Stack: [txn TxID (data), arg 0 (sig), pushbytes (pubkey)] → falcon_verify → bool
  const tealSource = [
    '#pragma version 12',
    'txn TxID',
    'arg 0',
    `pushbytes 0x${pubkeyHex}`,
    'falcon_verify',
  ].join('\n')

  try {
    const compiled = await client.compile(Buffer.from(tealSource)).do()
    const program = new Uint8Array(Buffer.from(compiled.result, 'base64'))
    const lsig = new algosdk.LogicSigAccount(program)
    const address = lsig.address() as unknown as string

    _cachedProgram = program
    _cachedAddress = address
    _cachedPubkeyHex = bytesToHex(pubkey)
    return { program, address }
  } catch (err) {
    const msg = String(err)
    if (msg.includes('version') || msg.includes('unsupported') || msg.includes('falcon')) {
      throw new Error('AVM v12 not supported on this network — Falcon mode requires an AVM v12-compatible node')
    }
    throw err
  }
}

// ── Transaction Signing ──

/**
 * Create a transaction signer using a Falcon LogicSig.
 * Drop-in replacement for wallet transactionSigner.
 *
 * Signs each transaction's TxID with Falcon-1024 and wraps in a LogicSig.
 * Signing is instant — no wallet popup or user interaction needed.
 */
export function createFalconSigner(
  program: Uint8Array,
  privateKey: Uint8Array,
): (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]> {
  return async (txns, indices) => {
    const falcon = await loadFalcon()
    const result: Uint8Array[] = new Array(txns.length).fill(new Uint8Array(0))

    for (const idx of indices) {
      // Get raw 32-byte transaction ID (matches what `txn TxID` pushes in TEAL)
      const rawTxId = base32Decode(txns[idx].txID())
      // Sign with Falcon-1024
      const sig = await falcon.signDetached(rawTxId, privateKey)
      // Wrap in LogicSig with signature as arg[0]
      const lsig = new algosdk.LogicSigAccount(program, [sig])
      result[idx] = algosdk.signLogicSigTransaction(txns[idx], lsig).blob
    }

    return result
  }
}

/**
 * Sweep all funds from the Falcon address back to the wallet address.
 * Uses closeRemainderTo to reclaim the full balance including min balance.
 */
export async function sweepFalconToWallet(
  client: algosdk.Algodv2,
  account: FalconAccount,
  walletAddress: string,
): Promise<string> {
  const falcon = await loadFalcon()
  const params = await client.getTransactionParams().do()

  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: account.address,
    receiver: walletAddress,
    amount: 0,
    suggestedParams: params,
    closeRemainderTo: walletAddress,
  })

  const rawTxId = base32Decode(txn.txID())
  const sig = await falcon.signDetached(rawTxId, account.privateKey)
  const lsig = new algosdk.LogicSigAccount(account.program, [sig])
  const signed = algosdk.signLogicSigTransaction(txn, lsig)

  await client.sendRawTransaction(signed.blob).do()
  await algosdk.waitForConfirmation(client, signed.txID, 4)
  return signed.txID
}

/** Clear cached Falcon state (called on wallet disconnect). */
export function clearFalconCache(): void {
  _cachedKeypair = null
  _cachedProgram = null
  _cachedAddress = null
  _cachedMasterKey = null
  _cachedPubkeyHex = null
}
