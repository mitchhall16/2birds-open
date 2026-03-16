/**
 * Falcon-1024 Post-Quantum Signing for Algorand LogicSig
 *
 * Uses Algorand's Deterministic Falcon-1024 (algorand/falcon) — NOT the
 * standard PQClean Falcon. The AVM's falcon_verify opcode only accepts
 * deterministic-mode signatures (header 0xBA, 1-byte salt version, no nonce).
 *
 * The Falcon public key is embedded in a small TEAL program → LogicSig contract account.
 * That address becomes the user's quantum-safe address. All pool operations are signed
 * by Falcon locally — no wallet popup needed.
 *
 * LogicSig size (~3KB) exceeds the per-txn 1000-byte limit, so every Falcon-signed
 * transaction must be in an atomic group with 3 dummy "int 1" LogicSig txns to pool
 * the budget (4 × 1000 = 4000 bytes).
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

/**
 * Lazy-load Algorand's Deterministic Falcon-1024 WASM.
 * Built from github.com/algorand/falcon via Emscripten.
 */
async function loadFalcon() {
  const mod = await import('./falcon-det/index.js')
  return mod
}

// ── Key Derivation ──

/**
 * Derive a deterministic Falcon-1024 keypair from a master key.
 *
 * Uses HKDF(SHA-256) to derive a 48-byte seed, which is passed to
 * the deterministic Falcon keygen (SHAKE256-seeded PRNG).
 * Same master key → same keypair → same LogicSig address on any device.
 */
export async function deriveFalconKeypair(masterKey: bigint): Promise<{
  publicKey: Uint8Array
  privateKey: Uint8Array
}> {
  if (_cachedKeypair && _cachedMasterKey === masterKey) return _cachedKeypair

  const masterKeyBytes = scalarToBytes(masterKey)

  // Derive 48-byte seed via HKDF
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

  // Deterministic Falcon keygen uses the seed directly (SHAKE256-seeded PRNG internally)
  const falcon = await loadFalcon()
  const keypair = await falcon.keyPairFromSeed(seed)

  _cachedKeypair = keypair
  _cachedMasterKey = masterKey
  return keypair
}

// ── TEAL Compilation ──

/**
 * Compile a Falcon-1024 LogicSig TEAL program with embedded public key.
 *
 * The TEAL program verifies that arg[0] is a valid deterministic Falcon-1024
 * signature of `txn TxID` under the embedded public key. Requires AVM v12.
 *
 * Program size: ~1801 bytes (1793 pubkey + ~8 TEAL opcodes)
 * LogicSig with arg: ~3030 bytes (program + ~1230 byte Falcon sig in arg[0])
 * Requires atomic group of 4 txns for LogicSig pool budget (4 × 1000 = 4000).
 */
export async function compileFalconProgram(
  client: algosdk.Algodv2,
  pubkey: Uint8Array,
): Promise<{ program: Uint8Array; address: string }> {
  if (_cachedProgram && _cachedAddress && _cachedPubkeyHex === bytesToHex(pubkey)) {
    return { program: _cachedProgram, address: _cachedAddress }
  }

  const pubkeyHex = bytesToHex(pubkey)

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
 * Signs each transaction's TxID with deterministic Falcon-1024.
 * When used within PLONK groups (16 txns), the LogicSig pool budget
 * is already sufficient. For smaller groups, the caller should add
 * padding txns (see signFalconTransaction).
 */
export function createFalconSigner(
  program: Uint8Array,
  privateKey: Uint8Array,
): (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]> {
  return async (txns, indices) => {
    const falcon = await loadFalcon()
    const result: Uint8Array[] = new Array(txns.length).fill(new Uint8Array(0))

    for (const idx of indices) {
      const rawTxId = base32Decode(txns[idx].txID())
      const sig = await falcon.signDetached(rawTxId, privateKey)
      const lsig = new algosdk.LogicSigAccount(program, [sig])
      result[idx] = algosdk.signLogicSigTransaction(txns[idx], lsig).blob
    }

    return result
  }
}

/**
 * Wrap a Falcon-signed transaction in an atomic group with 3 padding txns.
 * Required because the Falcon LogicSig (~3KB) exceeds the per-txn 1000-byte limit.
 * The pool budget is 1000 × groupSize, so 4 txns = 4000 byte budget.
 *
 * Padding txns are zero-amount self-payments from the Falcon address itself
 * (no separate dummy address needed). The main txn covers all fees (fee = 4000).
 *
 * Returns the full signed group ready for sendRawTransaction.
 */
export async function signFalconTransaction(
  client: algosdk.Algodv2,
  mainTxn: algosdk.Transaction,
  account: FalconAccount,
): Promise<{ signedGroup: Uint8Array[]; txId: string }> {
  const falcon = await loadFalcon()
  const params = await client.getTransactionParams().do()

  // Override main txn fee to cover all 4 txns
  mainTxn.fee = BigInt(4000)

  // Create 3 padding self-payments from the Falcon address (fee=0)
  const padding: algosdk.Transaction[] = []
  for (let i = 0; i < 3; i++) {
    padding.push(algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: account.address,
      receiver: account.address,
      amount: 0,
      suggestedParams: { ...params, fee: BigInt(0), flatFee: true },
      note: new TextEncoder().encode(`pad-${i}`),
    }))
  }

  // Assign group
  const group = [mainTxn, ...padding]
  algosdk.assignGroupID(group)

  // Sign all txns with Falcon (after group assignment — TxIDs change)
  const signedTxns: Uint8Array[] = []
  for (const txn of group) {
    const rawTxId = base32Decode(txn.txID())
    const sig = await falcon.signDetached(rawTxId, account.privateKey)
    const lsig = new algosdk.LogicSigAccount(account.program, [sig])
    signedTxns.push(algosdk.signLogicSigTransaction(txn, lsig).blob)
  }

  return {
    signedGroup: signedTxns,
    txId: group[0].txID(),
  }
}

/**
 * Sweep all funds from the Falcon address back to the wallet address.
 * Uses closeRemainderTo to reclaim the full balance including min balance.
 * Wraps in atomic group with dummy txns for LogicSig budget.
 */
export async function sweepFalconToWallet(
  client: algosdk.Algodv2,
  account: FalconAccount,
  walletAddress: string,
): Promise<string> {
  const params = await client.getTransactionParams().do()

  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: account.address,
    receiver: walletAddress,
    amount: 0,
    suggestedParams: { ...params, fee: BigInt(4000), flatFee: true },
    closeRemainderTo: walletAddress,
  })

  const { signedGroup, txId } = await signFalconTransaction(client, txn, account)
  await client.sendRawTransaction(signedGroup).do()
  await algosdk.waitForConfirmation(client, txId, 4)
  return txId
}

/** Clear cached Falcon state (called on wallet disconnect). */
export function clearFalconCache(): void {
  _cachedKeypair = null
  _cachedProgram = null
  _cachedAddress = null
  _cachedMasterKey = null
  _cachedPubkeyHex = null
}
