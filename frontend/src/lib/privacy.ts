import { buildMimcSponge } from 'circomlibjs'
import algosdk from 'algosdk'
import { CONTRACTS, POOL_DENOMINATION } from './config'

// BN254 scalar field modulus
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

// MiMC sponge instance (initialized async)
let mimcSponge: any = null
let mimcF: any = null

/** Initialize MiMC WASM — must be called before any hash operations */
export async function initMimc(): Promise<void> {
  if (mimcSponge) return
  mimcSponge = await buildMimcSponge()
  mimcF = mimcSponge.F
}

/** MiMC hash of two field elements (used for commitments) */
export function mimcHash(left: bigint, right: bigint): bigint {
  if (!mimcSponge) throw new Error('MiMC not initialized — call initMimc() first')
  return mimcF.toObject(mimcSponge.multiHash([left, right], 0, 1))
}

/** MiMC hash of a single field element (used for nullifier hash) */
export function mimcHashSingle(x: bigint): bigint {
  if (!mimcSponge) throw new Error('MiMC not initialized — call initMimc() first')
  return mimcF.toObject(mimcSponge.multiHash([x], 0, 1))
}

/** Generate a random scalar in the BN254 field */
function randomScalar(): bigint {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let n = 0n
  for (let i = 0; i < 32; i++) {
    n = (n << 8n) | BigInt(bytes[i])
  }
  return n % BN254_R
}

/** Convert a bigint to 32-byte big-endian Uint8Array */
export function scalarToBytes(s: bigint): Uint8Array {
  const buf = new Uint8Array(32)
  let val = s
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return buf
}

/** Convert 32 bytes (big-endian) to bigint */
export function bytesToScalar(buf: Uint8Array): bigint {
  let n = 0n
  for (let i = 0; i < buf.length; i++) {
    n = (n << 8n) | BigInt(buf[i])
  }
  return n
}

/** Convert a uint64 to 8-byte big-endian Uint8Array */
export function uint64ToBytes(n: bigint | number): Uint8Array {
  const buf = new Uint8Array(8)
  let val = typeof n === 'number' ? BigInt(n) : n
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return buf
}

// ── Deposit Note ─────────────────────────

export interface DepositNote {
  secret: bigint
  nullifier: bigint
  commitment: bigint
  leafIndex: number
  denomination: bigint
  assetId: number
  timestamp: number
  appId?: number
}

/** Create a new deposit note (generates commitment off-chain) */
export async function createDeposit(
  denomination: bigint = POOL_DENOMINATION,
  assetId: number = 0,
): Promise<DepositNote> {
  await initMimc()
  const secret = randomScalar()
  const nullifier = randomScalar()
  const commitment = mimcHash(secret, nullifier)

  return {
    secret,
    nullifier,
    commitment,
    leafIndex: -1,
    denomination,
    assetId,
    timestamp: Date.now(),
  }
}

/** Compute nullifier hash for withdrawal */
export function computeNullifierHash(nullifier: bigint): bigint {
  return mimcHashSingle(nullifier)
}

// ── ARC-4 Method Selectors ──────────────

// Pre-computed from SHA-512/256 of method signatures (first 4 bytes, per ARC-4)
export const METHOD_SELECTORS = {
  deposit: new Uint8Array([0xfc, 0x1b, 0xba, 0xae]),   // deposit(byte[],byte[])void
  withdraw: new Uint8Array([0x91, 0xca, 0x46, 0x52]),   // withdraw(byte[],address,address,uint64,byte[],uint64)void
} as const

/** ABI-encode a byte[] value (2-byte length prefix + data) */
export function abiEncodeBytes(data: Uint8Array): Uint8Array {
  const result = new Uint8Array(2 + data.length)
  result[0] = (data.length >> 8) & 0xff
  result[1] = data.length & 0xff
  result.set(data, 2)
  return result
}

// ── Box References ──────────────────────

const TEXT_ENCODER = new TextEncoder()

/** Build box reference for tree frontier at a given level */
export function treeBox(appId: number, level: number) {
  const name = new Uint8Array(12) // "tree" (4) + uint64 (8)
  name.set(TEXT_ENCODER.encode('tree'), 0)
  name.set(uint64ToBytes(BigInt(level)), 4)
  return { appIndex: appId, name }
}

/** Build box reference for root history at a given index */
export function rootBox(appId: number, index: number) {
  const name = new Uint8Array(12) // "root" (4) + uint64 (8)
  name.set(TEXT_ENCODER.encode('root'), 0)
  name.set(uint64ToBytes(BigInt(index)), 4)
  return { appIndex: appId, name }
}

/** Build box reference for nullifier */
export function nullifierBox(appId: number, nullifierHash: Uint8Array) {
  const name = new Uint8Array(4 + nullifierHash.length) // "null" (4) + hash
  name.set(TEXT_ENCODER.encode('null'), 0)
  name.set(nullifierHash, 4)
  return { appIndex: appId, name }
}

/** Build box reference for deposit amount at a given leaf index */
export function amountBox(appId: number, leafIndex: number) {
  const name = new Uint8Array(11) // "amt" (3) + uint64 (8)
  name.set(TEXT_ENCODER.encode('amt'), 0)
  name.set(uint64ToBytes(BigInt(leafIndex)), 3)
  return { appIndex: appId, name }
}

/** Build box reference for commitment at a given leaf index */
export function commitmentBox(appId: number, leafIndex: number) {
  const name = new Uint8Array(11) // "cmt" (3) + uint64 (8)
  name.set(TEXT_ENCODER.encode('cmt'), 0)
  name.set(uint64ToBytes(BigInt(leafIndex)), 3)
  return { appIndex: appId, name }
}

/** Build all box references needed for a deposit (3 boxes — no on-chain tree) */
export function depositBoxRefs(appId: number, rootHistoryIndex: number, leafIndex: number) {
  return [
    rootBox(appId, rootHistoryIndex % 100),
    amountBox(appId, leafIndex),
    commitmentBox(appId, leafIndex),
  ]
}

/** Build all box references needed for a withdrawal */
export function withdrawBoxRefs(appId: number, nullifierHash: Uint8Array, root: Uint8Array) {
  return [nullifierBox(appId, nullifierHash)]
}

// ── Note Serialization ──────────────────

export function encodeNote(note: DepositNote): string {
  return JSON.stringify({
    ...note,
    secret: note.secret.toString(),
    nullifier: note.nullifier.toString(),
    commitment: note.commitment.toString(),
    denomination: note.denomination.toString(),
    appId: note.appId,
  })
}

export function decodeNote(json: string): DepositNote {
  const obj = JSON.parse(json)
  return {
    ...obj,
    secret: BigInt(obj.secret),
    nullifier: BigInt(obj.nullifier),
    commitment: BigInt(obj.commitment),
    denomination: BigInt(obj.denomination),
    appId: obj.appId,
  }
}

const NOTES_KEY = 'privacy_pool_notes'

export function saveNote(note: DepositNote): void {
  const existing = loadAllNotes()
  existing.push({ ...note, appId: CONTRACTS.PrivacyPool.appId })
  localStorage.setItem(NOTES_KEY, JSON.stringify(existing.map(encodeNote)))
}

/** Load all notes regardless of contract */
function loadAllNotes(): DepositNote[] {
  try {
    const raw = localStorage.getItem(NOTES_KEY)
    if (!raw) return []
    return JSON.parse(raw).map((s: string) => decodeNote(s))
  } catch {
    return []
  }
}

/** Load notes for the current contract only */
export function loadNotes(): DepositNote[] {
  const appId = CONTRACTS.PrivacyPool.appId
  return loadAllNotes().filter(n => !n.appId || n.appId === appId)
}

/** Remove a note by index (from filtered list) */
export function removeNote(noteIndex: number): void {
  const appId = CONTRACTS.PrivacyPool.appId
  const all = loadAllNotes()
  // Find the actual index in the full list
  let matchCount = 0
  for (let i = 0; i < all.length; i++) {
    if (!all[i].appId || all[i].appId === appId) {
      if (matchCount === noteIndex) {
        all.splice(i, 1)
        break
      }
      matchCount++
    }
  }
  localStorage.setItem(NOTES_KEY, JSON.stringify(all.map(encodeNote)))
}

// ── ZK Proof Encoding ───────────────────

/** Convert an Algorand address to a BN254 field element (for circuit inputs) */
export function addressToScalar(addr: string): bigint {
  const decoded = algosdk.decodeAddress(addr)
  let n = 0n
  for (let i = 0; i < decoded.publicKey.length; i++) {
    n = (n << 8n) | BigInt(decoded.publicKey[i])
  }
  return n % BN254_R
}

/** Encode a Groth16 proof as 256 bytes for the LogicSig verifier (arg 0) */
export function encodeProofForVerifier(proof: {
  pi_a: [bigint, bigint]
  pi_b: [[bigint, bigint], [bigint, bigint]]
  pi_c: [bigint, bigint]
}): Uint8Array {
  const result = new Uint8Array(256)
  result.set(scalarToBytes(proof.pi_a[0]), 0)
  result.set(scalarToBytes(proof.pi_a[1]), 32)
  result.set(scalarToBytes(proof.pi_b[0][0]), 64)
  result.set(scalarToBytes(proof.pi_b[0][1]), 96)
  result.set(scalarToBytes(proof.pi_b[1][0]), 128)
  result.set(scalarToBytes(proof.pi_b[1][1]), 160)
  result.set(scalarToBytes(proof.pi_c[0]), 192)
  result.set(scalarToBytes(proof.pi_c[1]), 224)
  return result
}

/** Encode 5 public signals as 160 bytes for the LogicSig verifier (arg 1) */
export function encodePublicSignals(
  root: bigint,
  nullifierHash: bigint,
  recipient: string,
  relayer: string,
  fee: bigint,
): Uint8Array {
  const result = new Uint8Array(160)
  result.set(scalarToBytes(root), 0)
  result.set(scalarToBytes(nullifierHash), 32)
  result.set(scalarToBytes(addressToScalar(recipient)), 64)
  result.set(scalarToBytes(addressToScalar(relayer)), 96)
  result.set(scalarToBytes(fee), 128)
  return result
}

// ── Utilities ───────────────────────────

export function getPoolConfig() {
  return {
    appId: BigInt(CONTRACTS.PrivacyPool.appId),
    assetId: 0,
    denomination: POOL_DENOMINATION,
    merkleDepth: 20,
  }
}

export function formatAlgo(microAlgos: bigint | number): string {
  const n = typeof microAlgos === 'bigint' ? microAlgos : BigInt(microAlgos)
  const whole = n / 1_000_000n
  const frac = n % 1_000_000n
  const fracStr = frac.toString().padStart(6, '0').replace(/0+$/, '')
  return fracStr ? `${whole}.${fracStr}` : whole.toString()
}
