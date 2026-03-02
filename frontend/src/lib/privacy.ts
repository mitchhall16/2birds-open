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
  // AVM (gnark-crypto) expects G2 as: x_real || x_imag || y_real || y_imag
  // snarkjs gives pi_b as: [[x_real, x_imag], [y_real, y_imag]] — same order
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

// ── Deterministic Note Derivation ────────
// Derives deposit secrets from a wallet signature so notes survive cache clears.
// Same wallet → same signature → same master key → same notes on any device.

const MASTER_KEY_SESSION = 'privacy_pool_master_key'
const MASTER_KEY_MESSAGE = 'privacy-pool-master-key-v1'

/** Cached master key for this session */
let cachedMasterKey: bigint | null = null

/** Get the master key, loading from sessionStorage cache if available */
export function getCachedMasterKey(): bigint | null {
  if (cachedMasterKey) return cachedMasterKey
  const stored = sessionStorage.getItem(MASTER_KEY_SESSION)
  if (stored) {
    cachedMasterKey = BigInt(stored)
    return cachedMasterKey
  }
  return null
}

/**
 * Derive a master key from a wallet signature (ARC-0047 signData).
 * Ed25519 signatures are deterministic — same message + same wallet = same signature every time.
 * Falls back to a random key (cached per session) if wallet doesn't support signData.
 */
export async function deriveMasterKey(
  signData?: ((data: string, metadata: { scope: number; encoding: string }) => Promise<{ signature: Uint8Array }>) | null,
): Promise<bigint> {
  // Check cache first
  const cached = getCachedMasterKey()
  if (cached) return cached

  await initMimc()

  let masterKey: bigint

  if (signData) {
    try {
      const result = await signData(MASTER_KEY_MESSAGE, {
        scope: 1, // ScopeType.AUTH
        encoding: 'utf-8',
      })

      // Hash the signature into a BN254 scalar to use as master key
      const sigScalar = bytesToScalar(result.signature.slice(0, 32))
      masterKey = mimcHash(sigScalar, bytesToScalar(result.signature.slice(32, 64)))
    } catch {
      // Wallet doesn't support signData — use random key for this session
      const bytes = new Uint8Array(32)
      crypto.getRandomValues(bytes)
      masterKey = bytesToScalar(bytes) % BN254_R
    }
  } else {
    // No signData available — use random key for this session
    const bytes = new Uint8Array(32)
    crypto.getRandomValues(bytes)
    masterKey = bytesToScalar(bytes) % BN254_R
  }

  // Cache in memory and sessionStorage
  cachedMasterKey = masterKey
  sessionStorage.setItem(MASTER_KEY_SESSION, masterKey.toString())

  return masterKey
}

/**
 * Derive a deterministic deposit note from the master key and an index.
 * secret_i = MiMC(masterKey, 2*i)
 * nullifier_i = MiMC(masterKey, 2*i + 1)
 */
export function deriveDeposit(
  masterKey: bigint,
  depositIndex: number,
  denomination: bigint = POOL_DENOMINATION,
  assetId: number = 0,
): DepositNote {
  const secret = mimcHash(masterKey, BigInt(depositIndex * 2))
  const nullifier = mimcHash(masterKey, BigInt(depositIndex * 2 + 1))
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

/** Get the next deposit index for this wallet (how many deterministic deposits exist) */
export function getNextDepositIndex(): number {
  const key = `privacy_pool_deposit_counter_${CONTRACTS.PrivacyPool.appId}`
  return parseInt(localStorage.getItem(key) || '0', 10)
}

/** Increment the deposit counter after a successful deposit */
export function incrementDepositIndex(): void {
  const key = `privacy_pool_deposit_counter_${CONTRACTS.PrivacyPool.appId}`
  const current = getNextDepositIndex()
  localStorage.setItem(key, (current + 1).toString())
}

/**
 * Recover notes by scanning the chain for matching commitments.
 * Iterates deposit indices 0, 1, 2, ... checking if each commitment exists on-chain.
 * Skips notes whose nullifiers have already been spent.
 */
export async function recoverNotes(
  masterKey: bigint,
  client: algosdk.Algodv2,
  appId?: number,
): Promise<{ recovered: DepositNote[]; total: number; spent: number }> {
  await initMimc()

  const id = appId ?? CONTRACTS.PrivacyPool.appId
  const recovered: DepositNote[] = []
  let total = 0
  let spent = 0

  // Read nextIndex from global state to know how many deposits exist
  const appInfo = await client.getApplicationByID(id).do()
  const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
  let onChainNextIndex = 0
  for (const kv of globalState) {
    const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
    if (key === 'next_idx') onChainNextIndex = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
  }

  // Try deposit indices until we find 5 consecutive misses
  let consecutiveMisses = 0
  for (let i = 0; consecutiveMisses < 5; i++) {
    const note = deriveDeposit(masterKey, i)
    const commitBytes = scalarToBytes(note.commitment)

    // Check if this commitment exists on-chain
    const boxName = new Uint8Array(11)
    boxName.set(TEXT_ENCODER.encode('cmt'), 0)

    // We need to find which leaf index has this commitment
    let foundLeafIndex = -1
    for (let leaf = 0; leaf < onChainNextIndex; leaf++) {
      const leafBoxName = new Uint8Array(11)
      leafBoxName.set(TEXT_ENCODER.encode('cmt'), 0)
      leafBoxName.set(uint64ToBytes(BigInt(leaf)), 3)
      try {
        const boxResult = await client.getApplicationBoxByName(id, leafBoxName).do()
        if (arraysEqual(boxResult.value, commitBytes)) {
          foundLeafIndex = leaf
          break
        }
      } catch {
        continue
      }
    }

    if (foundLeafIndex === -1) {
      consecutiveMisses++
      continue
    }

    consecutiveMisses = 0
    total++
    note.leafIndex = foundLeafIndex
    note.appId = id

    // Read the deposited amount
    const amtBoxName = new Uint8Array(11)
    amtBoxName.set(TEXT_ENCODER.encode('amt'), 0)
    amtBoxName.set(uint64ToBytes(BigInt(foundLeafIndex)), 3)
    try {
      const amtBox = await client.getApplicationBoxByName(id, amtBoxName).do()
      note.denomination = bytesToScalar(amtBox.value)
    } catch {
      // Default to pool denomination
    }

    // Check if nullifier has been spent
    const nullHash = computeNullifierHash(note.nullifier)
    const nullBytes = scalarToBytes(nullHash)
    const nullBoxName = new Uint8Array(4 + nullBytes.length)
    nullBoxName.set(TEXT_ENCODER.encode('null'), 0)
    nullBoxName.set(nullBytes, 4)
    try {
      await client.getApplicationBoxByName(id, nullBoxName).do()
      // Box exists — nullifier spent, skip this note
      spent++
      continue
    } catch {
      // Box doesn't exist — not spent, note is recoverable
    }

    recovered.push(note)
  }

  // Save recovered notes and update counter
  const existingNotes = loadNotes()
  for (const note of recovered) {
    const alreadyExists = existingNotes.some(n =>
      n.commitment === note.commitment && n.appId === note.appId
    )
    if (!alreadyExists) {
      saveNote(note)
    }
  }

  // Update deposit counter to highest index found
  if (total > 0) {
    const key = `privacy_pool_deposit_counter_${id}`
    const current = getNextDepositIndex()
    if (total > current) {
      localStorage.setItem(key, total.toString())
    }
  }

  return { recovered, total, spent }
}

/** Compare two Uint8Arrays */
function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/** Clear master key cache (on wallet disconnect) */
export function clearMasterKey(): void {
  cachedMasterKey = null
  sessionStorage.removeItem(MASTER_KEY_SESSION)
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
