import { buildMimcSponge } from 'circomlibjs'
import algosdk from 'algosdk'
import { POOL_DENOMINATION, POOL_CONTRACTS, getPoolForTier } from './config'
import { deriveViewKeypair } from './keys'
import { scanChainForNotes } from './scanner'

// BN254 scalar field modulus
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** Thrown when signData fails and a password is needed to derive the master key */
export class PasswordRequiredError extends Error {
  constructor() {
    super('Password required to derive master key')
    this.name = 'PasswordRequiredError'
  }
}

// MiMC sponge instance (initialized async)
let mimcSponge: any = null
let mimcF: any = null
let mimcInitPromise: Promise<void> | null = null

/** Initialize MiMC WASM — must be called before any hash operations */
export async function initMimc(): Promise<void> {
  if (mimcSponge) return
  if (mimcInitPromise) return mimcInitPromise
  mimcInitPromise = (async () => {
    mimcSponge = await buildMimcSponge()
    mimcF = mimcSponge.F
  })()
  return mimcInitPromise
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

/** MiMC hash of three field elements (used for commitment = MiMC(secret, nullifier, amount)) */
export function mimcHashTriple(a: bigint, b: bigint, c: bigint): bigint {
  if (!mimcSponge) throw new Error('MiMC not initialized — call initMimc() first')
  return mimcF.toObject(mimcSponge.multiHash([a, b, c], 0, 1))
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
  return buf.length >= 32 ? n % BN254_R : n
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
  // commitment = MiMC(secret, nullifier, amount) — binds proof to deposited amount
  const commitment = mimcHashTriple(secret, nullifier, denomination)

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
  // withdraw(byte[],address,address,uint64,byte[],byte[],byte[])void
  withdraw: new Uint8Array([0x1b, 0xd9, 0xeb, 0x9c]),
  // privateSend(byte[],byte[],byte[],address,address,uint64,byte[],byte[])void
  privateSend: new Uint8Array([0xbb, 0xf9, 0x96, 0x55]),
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
/** Build box reference for commitment at a given leaf index */
export function commitmentBox(appId: number, leafIndex: number) {
  const name = new Uint8Array(11) // "cmt" (3) + uint64 (8)
  name.set(TEXT_ENCODER.encode('cmt'), 0)
  name.set(uint64ToBytes(BigInt(leafIndex)), 3)
  return { appIndex: appId, name }
}

/** Build all box references needed for a deposit (3-4 boxes — includes evicted root if ring buffer wraps) */
export function depositBoxRefs(appId: number, rootHistoryIndex: number, leafIndex: number, mimcRoot: Uint8Array, evictedRoot?: Uint8Array) {
  const refs = [
    rootBox(appId, rootHistoryIndex % 10000),
    commitmentBox(appId, leafIndex),
    knownRootBox(appId, mimcRoot),
  ]
  // When ring buffer wraps (>=10000 deposits), include the old root's knownRoots box for eviction
  if (evictedRoot) {
    refs.push(knownRootBox(appId, evictedRoot))
  }
  return refs
}

/** Read the root stored at a ring buffer slot (for eviction). Returns undefined if slot is empty. */
export async function readEvictedRoot(client: algosdk.Algodv2, appId: number, rootHistoryIndex: number): Promise<Uint8Array | undefined> {
  if (rootHistoryIndex < 10000) return undefined // ring buffer hasn't wrapped yet
  const slot = rootHistoryIndex % 10000
  const boxName = new Uint8Array(12)
  boxName.set(TEXT_ENCODER.encode('root'), 0)
  boxName.set(uint64ToBytes(BigInt(slot)), 4)
  try {
    const box = await client.getApplicationBoxByName(appId, boxName).do()
    return box.value as Uint8Array
  } catch {
    return undefined
  }
}

/** Build box reference for knownRoots lookup */
export function knownRootBox(appId: number, root: Uint8Array) {
  const name = new Uint8Array(2 + root.length) // "kr" (2) + root hash
  name.set(TEXT_ENCODER.encode('kr'), 0)
  name.set(root, 2)
  return { appIndex: appId, name }
}

/** Build all box references needed for a withdrawal */
export function withdrawBoxRefs(appId: number, nullifierHash: Uint8Array, root: Uint8Array) {
  return [nullifierBox(appId, nullifierHash), knownRootBox(appId, root)]
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

// ── Encrypted Note Storage (v2) ─────────

const NOTES_KEY = 'privacy_pool_notes'
const NOTES_V2_KEY = 'privacy_pool_notes_v2'
const HKDF_SALT_KEY = 'privacy_pool_hkdf_salt'

/** Get or create a persistent random HKDF salt */
function getHkdfSalt(): Uint8Array {
  const stored = localStorage.getItem(HKDF_SALT_KEY)
  if (stored) {
    return Uint8Array.from(stored.match(/.{2}/g)!.map(b => parseInt(b, 16)))
  }
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const hex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  localStorage.setItem(HKDF_SALT_KEY, hex)
  return salt
}

/** Derive an AES-256-GCM key from the master key via HKDF (only when deterministic) */
async function deriveEncryptionKey(): Promise<CryptoKey | null> {
  if (!masterKeyDeterministic) return null
  const mk = await getCachedMasterKey()
  if (!mk) return null
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    scalarToBytes(mk) as ArrayBufferView<ArrayBuffer>,
    'HKDF',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: getHkdfSalt() as ArrayBufferView<ArrayBuffer>, info: new TextEncoder().encode('privacy-pool-notes-v2') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Convert Uint8Array to base64 without spread operator (avoids stack overflow on large payloads) */
function uint8ToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

/** Encrypt a string with AES-256-GCM, return base64(iv || ciphertext) */
async function encryptData(key: CryptoKey, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(plaintext),
  )
  const combined = new Uint8Array(12 + ct.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ct), 12)
  return uint8ToBase64(combined)
}

/** Decrypt base64(iv || ciphertext) with AES-256-GCM */
async function decryptData(key: CryptoKey, encoded: string): Promise<string> {
  const combined = Uint8Array.from(atob(encoded), c => c.charCodeAt(0))
  const iv = combined.slice(0, 12)
  const ct = combined.slice(12)
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ct,
  )
  return new TextDecoder().decode(pt)
}

/** Migrate v1 plaintext notes to v2 encrypted format */
async function migrateV1ToV2(encKey: CryptoKey): Promise<void> {
  const raw = localStorage.getItem(NOTES_KEY)
  if (!raw) return
  try {
    // v1 format: JSON array of encoded note strings
    const notes: DepositNote[] = JSON.parse(raw).map((s: string) => decodeNote(s))
    if (notes.length > 0) {
      const plaintext = JSON.stringify(notes.map(encodeNote))
      const encrypted = await encryptData(encKey, plaintext)
      localStorage.setItem(NOTES_V2_KEY, encrypted)
    }
    localStorage.removeItem(NOTES_KEY)
  } catch {
    // Corrupted v1 data, just remove it
    localStorage.removeItem(NOTES_KEY)
  }
}

/** Load all notes regardless of contract (async, decrypted) */
async function loadAllNotesAsync(): Promise<DepositNote[]> {
  const encKey = await deriveEncryptionKey()

  // Migrate v1 → v2 if needed
  if (encKey && localStorage.getItem(NOTES_KEY)) {
    await migrateV1ToV2(encKey)
  }

  // Try v2 encrypted format
  if (encKey) {
    const encrypted = localStorage.getItem(NOTES_V2_KEY)
    if (!encrypted) return []
    try {
      const plaintext = await decryptData(encKey, encrypted)
      return JSON.parse(plaintext).map((s: string) => decodeNote(s))
    } catch {
      return []
    }
  }

  // No encryption key available — return empty (notes require master key)
  // Any v1 plaintext notes will be migrated when master key becomes available
  return []
}

/** Cross-tab async mutex — prevents concurrent load→modify→save from clobbering each other.
 *  Uses navigator.locks for cross-tab safety, falls back to in-process mutex. */
let notesMutex: Promise<void> = Promise.resolve()
function withNotesMutex<T>(fn: () => Promise<T>): Promise<T> {
  if (navigator.locks) {
    return navigator.locks.request('privacy_notes_mutex', () => fn()) as Promise<T>
  }
  // Fallback: in-process mutex for browsers without Web Locks API
  const prev = notesMutex
  let resolve: () => void
  notesMutex = new Promise<void>(r => { resolve = r })
  return prev.then(fn).finally(() => resolve!())
}

/** Save all notes (encrypted — requires master key) */
async function saveAllNotesAsync(notes: DepositNote[]): Promise<void> {
  const plaintext = JSON.stringify(notes.map(encodeNote))
  const encKey = await deriveEncryptionKey()
  if (encKey) {
    const encrypted = await encryptData(encKey, plaintext)
    localStorage.setItem(NOTES_V2_KEY, encrypted)
    localStorage.removeItem(NOTES_KEY)
  } else {
    // No encryption key — store nothing. Notes will be re-derived from master key on next login.
    console.warn('Cannot save notes: no encryption key available (master key not yet derived)')
  }
}

export async function saveNote(note: DepositNote): Promise<void> {
  return withNotesMutex(async () => {
    const pool = getPoolForTier(note.denomination)
    const existing = await loadAllNotesAsync()
    existing.push({ ...note, appId: pool.appId })
    await saveAllNotesAsync(existing)
  })
}

/** Load deposit notes, filtering out stale notes from defunct pools */
export async function loadNotes(): Promise<DepositNote[]> {
  // Build a map: appId → denomination (microAlgos string key)
  const poolByAppId = new Map<number, string>()
  for (const [denom, pool] of Object.entries(POOL_CONTRACTS)) {
    poolByAppId.set(pool.appId, denom)
  }

  const all = await loadAllNotesAsync()
  const valid = all.filter(n => {
    if (!n.appId) return false
    const expectedDenom = poolByAppId.get(n.appId)
    if (!expectedDenom) return false
    // Cross-check: note's denomination must match the pool it claims to belong to
    return n.denomination.toString() === expectedDenom
  })
  // Do NOT auto-delete notes with unknown appIds — they may belong to a
  // previous deployment and could be recovered after redeployment.
  return valid
}

/** Remove a note by index (from filtered loadNotes list) */
export async function removeNote(noteIndex: number): Promise<void> {
  const filtered = await loadNotes()
  if (noteIndex < 0 || noteIndex >= filtered.length) return
  const target = filtered[noteIndex]
  await removeNoteByCommitment(target.commitment)
}

/** Remove a note by its commitment value (safe regardless of index shifting) */
export async function removeNoteByCommitment(commitment: bigint): Promise<void> {
  return withNotesMutex(async () => {
    const all = await loadAllNotesAsync()
    const idx = all.findIndex(n => n.commitment === commitment)
    if (idx >= 0) {
      all.splice(idx, 1)
      await saveAllNotesAsync(all)
    }
  })
}

// ── Note Backup Export/Import (AES-GCM encrypted) ───────────

/** Derive an AES-GCM key from a password + salt using PBKDF2 */
async function deriveBackupKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt.buffer as ArrayBuffer, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Export all notes as a password-encrypted backup string */
export async function exportNotesBackup(password: string): Promise<string> {
  if (!password || password.length < 12) throw new Error('Backup password must be at least 12 characters')
  const notes = await loadAllNotesAsync()
  if (notes.length === 0) throw new Error('No notes to export')
  const payload = JSON.stringify(notes.map(n => ({
    commitment: n.commitment.toString(),
    nullifier: n.nullifier.toString(),
    secret: n.secret.toString(),
    denomination: n.denomination.toString(),
    leafIndex: n.leafIndex,
    timestamp: n.timestamp,
    appId: n.appId,
    assetId: n.assetId,
  })))
  const enc = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveBackupKey(password, salt)
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(payload)))
  // Format: base64(salt(16) + iv(12) + ciphertext)
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.length)
  combined.set(salt, 0)
  combined.set(iv, salt.length)
  combined.set(ciphertext, salt.length + iv.length)
  return uint8ToBase64(combined)
}

/** Import notes from a password-encrypted backup string, merging with existing notes */
export async function importNotesBackup(backupStr: string, password: string): Promise<number> {
  if (!password) throw new Error('Password required to decrypt backup')
  const raw = Uint8Array.from(atob(backupStr), c => c.charCodeAt(0))
  if (raw.length < 29) throw new Error('Invalid backup file')
  const salt = raw.slice(0, 16)
  const iv = raw.slice(16, 28)
  const ciphertext = raw.slice(28)
  const key = await deriveBackupKey(password, salt)
  let decrypted: ArrayBuffer
  try {
    decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext)
  } catch {
    throw new Error('Wrong password or corrupted backup')
  }
  const payload = JSON.parse(new TextDecoder().decode(decrypted))
  const existing = await loadAllNotesAsync()
  const existingCommitments = new Set(existing.map(n => n.commitment.toString()))
  let imported = 0
  for (const n of payload) {
    if (existingCommitments.has(n.commitment)) continue
    existing.push({
      commitment: BigInt(n.commitment),
      nullifier: BigInt(n.nullifier),
      secret: BigInt(n.secret),
      denomination: BigInt(n.denomination),
      leafIndex: n.leafIndex,
      timestamp: n.timestamp,
      appId: n.appId,
      assetId: n.assetId ?? 0,
    })
    imported++
  }
  if (imported > 0) await saveAllNotesAsync(existing)
  return imported
}

/** Check if a note's nullifier has been spent on-chain */
export async function isNoteSpent(client: algosdk.Algodv2, note: DepositNote): Promise<boolean> {
  if (!note.appId) {
    // No appId — look up from denomination
    const pool = POOL_CONTRACTS[note.denomination.toString()]
    if (!pool) return false
    note = { ...note, appId: pool.appId }
  }
  await initMimc()
  const nHash = computeNullifierHash(note.nullifier)
  // Convert bigint to 32-byte big-endian
  const hex = nHash.toString(16).padStart(64, '0')
  const hashBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) hashBytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  const boxName = new Uint8Array(4 + 32)
  boxName.set(TEXT_ENCODER.encode('null'), 0)
  boxName.set(hashBytes, 4)
  try {
    await client.getApplicationBoxByName(note.appId!, boxName).do()
    return true // box exists = nullifier spent
  } catch {
    return false // box doesn't exist = unspent
  }
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

/** Encode a Groth16 proof as 256 bytes for the app-based verifier (arg 0) */
export function encodeProofForVerifier(proof: {
  pi_a: [bigint, bigint]
  pi_b: [[bigint, bigint], [bigint, bigint]]
  pi_c: [bigint, bigint]
}): Uint8Array {
  const result = new Uint8Array(256)
  result.set(scalarToBytes(proof.pi_a[0]), 0)
  result.set(scalarToBytes(proof.pi_a[1]), 32)
  // AVM (gnark-crypto) expects G2 as: x_real (A0) || x_imag (A1) || y_real (A0) || y_imag (A1)
  // snarkjs gives pi_b as: [[x_c0, x_c1], [y_c0, y_c1]] where c0=real, c1=imag — same order
  result.set(scalarToBytes(proof.pi_b[0][0]), 64)
  result.set(scalarToBytes(proof.pi_b[0][1]), 96)
  result.set(scalarToBytes(proof.pi_b[1][0]), 128)
  result.set(scalarToBytes(proof.pi_b[1][1]), 160)
  result.set(scalarToBytes(proof.pi_c[0]), 192)
  result.set(scalarToBytes(proof.pi_c[1]), 224)
  return result
}

// ── PLONK Proof Support ─────────────────

/** Which proof system to use — controlled by config */
export type ProofSystem = 'groth16' | 'plonk'

// R2 + IPFS fallback for large PLONK zkey files (too big for CF Pages' 25 MiB limit)
const ZKEY_SOURCES = [
  'https://pub-1f17b1af48bb408e8ca34acad7658b0d.r2.dev',
  'https://dweb.link/ipfs/QmTkYMTmiZz18iCcUYdFGxuBzEpZ34zo5vDSBopXMn4FXi',
] as const

// Known-good SHA-256 hashes of zkey files (hex)
const ZKEY_HASHES: Record<string, string> = {
  '/circuits/deposit_final.zkey': 'c63146b69154d1ef8456b72b3e656421bf1b1509aec2ae116da598552f1d55dc',
  '/circuits/deposit_plonk.zkey': '0f603fb9ae326bb9c3fabe8bdf72c3ce0e62281ad7637bd1f711255f37450e80',
  '/circuits/privateSend_final.zkey': '667c0bc59b90f84cd86b4d4e6c6312a2842f7a0ad553263fd5dd10c60be63f69',
  '/circuits/privateSend_plonk.zkey': '85c442bb0720b9c4b48cb8a25c98cc5154553ca15a5ebd5df73055a3249ad5a2',
  '/circuits/withdraw_final.zkey': 'b6d7ba955d936bcad62203f9a329e1ec1f4dce76e5d62f20268a654cd406fcb1',
  '/circuits/withdraw_plonk.zkey': '078cf41bbc8ab2b1e7240f94492b0cac2f24c75cebc1d2edd7ca7183d893f9f1',
}

/** Resolve zkey path to fetch URLs — PLONK zkeys try R2 then IPFS fallback */
function resolveZkeyUrls(zkeyPath: string): string[] {
  if (zkeyPath.includes('_plonk.zkey')) {
    const filename = zkeyPath.split('/').pop()!
    return ZKEY_SOURCES.map(base => `${base}/${filename}`)
  }
  return [zkeyPath]
}

// Module-level cache: original zkey path → verified blob URL
// Fetch once, verify hash, then reuse the blob URL for snarkjs (which requires a URL string).
const verifiedZkeyBlobUrls = new Map<string, string>()

/**
 * Fetch a zkey file, verify its SHA-256 hash, and return a blob URL.
 * The blob URL is cached so subsequent calls for the same zkeyPath skip re-fetch.
 * This eliminates the TOCTOU gap where the file could change between verification and use.
 */
async function getVerifiedZkeyUrl(
  zkeyPath: string,
  onProgress?: (msg: string) => void,
): Promise<string> {
  const cached = verifiedZkeyBlobUrls.get(zkeyPath)
  if (cached) return cached

  const expectedHash = ZKEY_HASHES[zkeyPath]
  if (!expectedHash) throw new Error(`Unknown zkey path: ${zkeyPath} — cannot verify integrity`)

  const urls = resolveZkeyUrls(zkeyPath)
  let buf: ArrayBuffer | null = null
  for (const url of urls) {
    try {
      onProgress?.(`Downloading proving key...`)
      const resp = await fetch(url)
      if (!resp.ok) continue

      // Stream with progress if Content-Length is available
      const contentLength = Number(resp.headers.get('Content-Length') || 0)
      if (contentLength > 0 && resp.body) {
        const reader = resp.body.getReader()
        const chunks: Uint8Array[] = []
        let received = 0
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          chunks.push(value)
          received += value.length
          const pct = Math.round((received / contentLength) * 100)
          const mb = (received / 1_048_576).toFixed(1)
          const totalMb = (contentLength / 1_048_576).toFixed(0)
          onProgress?.(`Downloading proving key... ${mb}/${totalMb} MB (${pct}%)`)
        }
        const combined = new Uint8Array(received)
        let offset = 0
        for (const chunk of chunks) {
          combined.set(chunk, offset)
          offset += chunk.length
        }
        buf = combined.buffer
      } else {
        buf = await resp.arrayBuffer()
      }
      break
    } catch (e) {
      console.warn(`zkey fetch failed from ${url}:`, e)
      /* try next source */
    }
  }
  if (!buf) throw new Error(`Failed to fetch zkey from all sources: ${zkeyPath}`)

  onProgress?.('Verifying proving key integrity...')
  const hashBuf = await crypto.subtle.digest('SHA-256', buf)
  const actual = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('')
  if (actual !== expectedHash) {
    throw new Error(`zkey integrity check failed for ${zkeyPath}: expected ${expectedHash}, got ${actual}`)
  }

  const blobUrl = URL.createObjectURL(new Blob([buf], { type: 'application/octet-stream' }))
  verifiedZkeyBlobUrls.set(zkeyPath, blobUrl)
  return blobUrl
}

/**
 * Generate a ZK proof using the configured proof system.
 * Abstracts over snarkjs.groth16.fullProve vs snarkjs.plonk.fullProve.
 * Fetches the zkey once, verifies its SHA-256 hash, and passes the verified
 * blob URL to snarkjs — eliminating the TOCTOU double-fetch vulnerability.
 */
export async function generateProof(
  system: ProofSystem,
  circuitInput: Record<string, string | string[] | number[]>,
  wasmPath: string,
  zkeyPath: string,
  onProgress?: (msg: string) => void,
): Promise<{ proof: any; publicSignals: string[] }> {
  const verifiedUrl = await getVerifiedZkeyUrl(zkeyPath, onProgress)
  onProgress?.('Computing ZK proof...')
  const snarkjs = await import('snarkjs')
  if (system === 'plonk') {
    return snarkjs.plonk.fullProve(circuitInput, wasmPath, verifiedUrl)
  }
  return snarkjs.groth16.fullProve(circuitInput, wasmPath, verifiedUrl)
}

/**
 * Parse a Groth16 proof from snarkjs output into the format expected by encodeProofForVerifier.
 */
export function parseGroth16Proof(proof: any): {
  pi_a: [bigint, bigint]
  pi_b: [[bigint, bigint], [bigint, bigint]]
  pi_c: [bigint, bigint]
} {
  return {
    pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    pi_b: [
      [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
      [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
    ],
    pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
  }
}

/** Encode 4 deposit public signals as 128 bytes for the deposit verifier (arg 1) */
export function encodeDepositSignals(
  oldRoot: bigint,
  newRoot: bigint,
  commitment: bigint,
  leafIndex: bigint,
): Uint8Array {
  const result = new Uint8Array(128)
  result.set(scalarToBytes(oldRoot), 0)
  result.set(scalarToBytes(newRoot), 32)
  result.set(scalarToBytes(commitment), 64)
  result.set(scalarToBytes(leafIndex), 96)
  return result
}

/** Encode 6 public signals as 192 bytes for the LogicSig verifier (arg 1) */
export function encodePublicSignals(
  root: bigint,
  nullifierHash: bigint,
  recipient: string,
  relayer: string,
  fee: bigint,
  amount: bigint,
): Uint8Array {
  const result = new Uint8Array(192)
  result.set(scalarToBytes(root), 0)
  result.set(scalarToBytes(nullifierHash), 32)
  result.set(scalarToBytes(addressToScalar(recipient)), 64)
  result.set(scalarToBytes(addressToScalar(relayer)), 96)
  result.set(scalarToBytes(fee), 128)
  result.set(scalarToBytes(amount), 160)
  return result
}

/** Encode 9 public signals as 288 bytes for the combined privateSend verifier (arg 1) */
export function encodePrivateSendSignals(
  oldRoot: bigint,
  newRoot: bigint,
  commitment: bigint,
  leafIndex: bigint,
  nullifierHash: bigint,
  recipient: string,
  relayer: string,
  fee: bigint,
  amount: bigint,
): Uint8Array {
  const result = new Uint8Array(288)
  result.set(scalarToBytes(oldRoot), 0)
  result.set(scalarToBytes(newRoot), 32)
  result.set(scalarToBytes(commitment), 64)
  result.set(scalarToBytes(leafIndex), 96)
  result.set(scalarToBytes(nullifierHash), 128)
  result.set(scalarToBytes(addressToScalar(recipient)), 160)
  result.set(scalarToBytes(addressToScalar(relayer)), 192)
  result.set(scalarToBytes(fee), 224)
  result.set(scalarToBytes(amount), 256)
  return result
}

/** Build all box references needed for a privateSend (4-5 boxes — commitment, root history, nullifier, knownRoot, evicted root) */
export function privateSendBoxRefs(appId: number, rootHistoryIndex: number, leafIndex: number, nullifierHash: Uint8Array, mimcRoot: Uint8Array, evictedRoot?: Uint8Array) {
  const refs = [
    commitmentBox(appId, leafIndex),
    rootBox(appId, rootHistoryIndex % 10000),
    nullifierBox(appId, nullifierHash),
    knownRootBox(appId, mimcRoot),
  ]
  if (evictedRoot) {
    refs.push(knownRootBox(appId, evictedRoot))
  }
  return refs
}

// ── Deterministic Note Derivation ────────
// Derives deposit secrets from a wallet signature so notes survive cache clears.
// Same wallet → same signature → same master key → same notes on any device.

const MASTER_KEY_SESSION = 'privacy_pool_master_key'
const MASTER_KEY_MESSAGE = 'privacy-pool-master-key-v1'

/** Cached master key for this session */
let cachedMasterKey: bigint | null = null

/** Whether the master key was deterministically derived (signData) vs random fallback */
let masterKeyDeterministic = false

/** Cached view keypair (derived from master key) */
let cachedViewKeypair: { privateKey: Uint8Array; publicKey: Uint8Array } | null = null

/** Inactivity timeout — clear cached key after 5 minutes of no crypto operations */
const KEY_INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000
let keyInactivityTimer: ReturnType<typeof setTimeout> | null = null

function wipeMasterKeyFromMemory() {
  cachedMasterKey = null
  cachedViewKeypair = null
  masterKeyDeterministic = false
  sessionStorage.removeItem(MASTER_KEY_SESSION)
  keyInactivityTimer = null
  // Also clear Falcon cache on inactivity timeout
  import('./falcon').then(m => m.clearFalconCache()).catch(e => console.warn('[Falcon] Failed to clear cache:', e))
}

function resetKeyInactivityTimer() {
  if (keyInactivityTimer) clearTimeout(keyInactivityTimer)
  keyInactivityTimer = setTimeout(wipeMasterKeyFromMemory, KEY_INACTIVITY_TIMEOUT_MS)
}


/** Get or derive the view keypair from the cached master key */
export async function getViewKeypair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array } | null> {
  if (cachedViewKeypair) return cachedViewKeypair
  const mk = await getCachedMasterKey()
  if (!mk) return null
  cachedViewKeypair = deriveViewKeypair(mk)
  return cachedViewKeypair
}

/** Per-tab ephemeral key for encrypting master key in sessionStorage */
let tabEncryptionKey: CryptoKey | null = null

async function getTabKey(): Promise<CryptoKey> {
  if (tabEncryptionKey) return tabEncryptionKey
  tabEncryptionKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
  return tabEncryptionKey
}

/** Encrypt master key before storing in sessionStorage */
async function encryptMasterKey(mk: bigint): Promise<string> {
  const key = await getTabKey()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    scalarToBytes(mk) as ArrayBufferView<ArrayBuffer>,
  )
  const combined = new Uint8Array(12 + ct.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ct), 12)
  return uint8ToBase64(combined)
}

/** Decrypt master key from sessionStorage */
async function decryptMasterKey(encoded: string): Promise<bigint> {
  const key = await getTabKey()
  const combined = Uint8Array.from(atob(encoded), c => c.charCodeAt(0))
  const iv = combined.slice(0, 12)
  const ct = combined.slice(12)
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ct,
  )
  return bytesToScalar(new Uint8Array(pt))
}

/** Get the master key, loading from sessionStorage cache if available */
export async function getCachedMasterKey(): Promise<bigint | null> {
  if (cachedMasterKey) {
    resetKeyInactivityTimer()
    return cachedMasterKey
  }
  const stored = sessionStorage.getItem(MASTER_KEY_SESSION)
  if (stored) {
    try {
      cachedMasterKey = await decryptMasterKey(stored)
      resetKeyInactivityTimer()
      return cachedMasterKey
    } catch {
      // Tab key changed (new tab loaded same session) — key is unrecoverable
      sessionStorage.removeItem(MASTER_KEY_SESSION)
      return null
    }
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
  const cached = await getCachedMasterKey()
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
      masterKeyDeterministic = true
    } catch {
      // Wallet doesn't support signData — prompt user for password
      throw new PasswordRequiredError()
    }
  } else {
    // No signData available — prompt user for password
    throw new PasswordRequiredError()
  }

  // Cache in memory and encrypted in sessionStorage
  cachedMasterKey = masterKey
  cachedViewKeypair = deriveViewKeypair(masterKey)
  const encrypted = await encryptMasterKey(masterKey)
  sessionStorage.setItem(MASTER_KEY_SESSION, encrypted)
  resetKeyInactivityTimer()

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
  // commitment = MiMC(secret, nullifier, amount) — binds proof to deposited amount
  const commitment = mimcHashTriple(secret, nullifier, denomination)

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

/** Active wallet address for per-wallet counter keying */
let _activeWallet = ''
export function setActiveWallet(addr: string) { _activeWallet = addr }

/** Get the deposit counter localStorage key for the active wallet */
function depositCounterKey(): string {
  return _activeWallet
    ? `privacy_pool_deposit_counter_${_activeWallet}`
    : 'privacy_pool_deposit_counter'
}

/** Get the next deposit index for this wallet (global across all tiers) */
function getNextDepositIndex(): number {
  const key = depositCounterKey()
  // Migrate from old global key if per-wallet key doesn't exist yet
  const globalKey = 'privacy_pool_deposit_counter'
  const globalVal = localStorage.getItem(globalKey)
  if (_activeWallet && globalVal && !localStorage.getItem(key)) {
    localStorage.setItem(key, globalVal)
  }
  return parseInt(localStorage.getItem(key) || '0', 10)
}

/**
 * Atomically claim the next deposit index using Web Locks API for cross-tab safety.
 * Falls back to non-atomic localStorage if navigator.locks is unavailable.
 */
export async function claimNextDepositIndex(): Promise<number> {
  const key = depositCounterKey()
  const claim = () => {
    // Migrate if needed
    const globalKey = 'privacy_pool_deposit_counter'
    const globalVal = localStorage.getItem(globalKey)
    if (_activeWallet && globalVal && !localStorage.getItem(key)) {
      localStorage.setItem(key, globalVal)
    }
    const idx = parseInt(localStorage.getItem(key) || '0', 10)
    localStorage.setItem(key, (idx + 1).toString())
    return idx
  }

  if (navigator.locks) {
    return navigator.locks.request('privacy_deposit_counter', () => claim())
  }
  return claim()
}


/**
 * Recover notes by scanning all pool tiers for matching commitments.
 * Fetches all commitment boxes once per pool, then compares locally — O(n + m) per pool.
 * Skips notes whose nullifiers have already been spent.
 */
export async function recoverNotes(
  masterKey: bigint,
  client: algosdk.Algodv2,
  appId?: number,
): Promise<{ recovered: DepositNote[]; total: number; spent: number }> {
  await initMimc()

  // If a specific appId is given, look up its denomination; otherwise scan all tiers
  const poolsToScan: { appId: number; denomination: bigint }[] = appId
    ? (() => {
        const entry = Object.entries(POOL_CONTRACTS).find(([, p]) => p.appId === appId)
        const denom = entry ? BigInt(entry[0]) : POOL_DENOMINATION
        return [{ appId, denomination: denom }]
      })()
    : Object.entries(POOL_CONTRACTS).map(([denom, pool]) => ({
        appId: pool.appId,
        denomination: BigInt(denom),
      }))

  const recovered: DepositNote[] = []
  let total = 0
  let spent = 0
  let highestDerivationIndex = -1

  for (const pool of poolsToScan) {
    const id = pool.appId

    // Read nextIndex from global state
    let onChainNextIndex = 0
    try {
      const appInfo = await client.getApplicationByID(id).do()
      const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
      for (const kv of globalState) {
        const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
        if (key === 'next_idx') onChainNextIndex = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
      }
    } catch {
      continue // Pool doesn't exist or is inaccessible
    }

    if (onChainNextIndex === 0) continue

    // Batch fetch: commitments (BATCH_SIZE concurrent RPCs)
    const BATCH_SIZE = 10
    const onChainCommitments = new Map<string, number>() // hex(commitment) → leafIndex

    for (let start = 0; start < onChainNextIndex; start += BATCH_SIZE) {
      const end = Math.min(start + BATCH_SIZE, onChainNextIndex)
      const batch = Array.from({ length: end - start }, (_, i) => {
        const leaf = start + i
        return (async () => {
          const cmtBoxName = new Uint8Array(11)
          cmtBoxName.set(TEXT_ENCODER.encode('cmt'), 0)
          cmtBoxName.set(uint64ToBytes(BigInt(leaf)), 3)
          try {
            const boxResult = await client.getApplicationBoxByName(id, cmtBoxName).do()
            const hex = Array.from(boxResult.value as Uint8Array).map(b => b.toString(16).padStart(2, '0')).join('')
            onChainCommitments.set(hex, leaf)
          } catch {
            return
          }
        })()
      })
      await Promise.all(batch)
    }

    // Try deposit indices across all tiers — local comparison against the pre-fetched map
    let consecutiveMisses = 0
    for (let i = 0; consecutiveMisses < 20; i++) {
      const note = deriveDeposit(masterKey, i, pool.denomination)
      const commitBytes = scalarToBytes(note.commitment)
      const commitHex = Array.from(commitBytes).map(b => b.toString(16).padStart(2, '0')).join('')

      const foundLeafIndex = onChainCommitments.get(commitHex)
      if (foundLeafIndex === undefined) {
        consecutiveMisses++
        continue
      }

      consecutiveMisses = 0
      total++
      highestDerivationIndex = Math.max(highestDerivationIndex, i)
      note.leafIndex = foundLeafIndex
      note.appId = id

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
  }

  // Batch save recovered notes under mutex (avoids race with concurrent saveNote calls)
  if (recovered.length > 0) {
    await withNotesMutex(async () => {
      const existingNotes = await loadNotes()
      const newNotes = recovered.filter(note =>
        !existingNotes.some(n => n.commitment === note.commitment && n.appId === note.appId)
      )
      if (newNotes.length > 0) {
        const all = await loadAllNotesAsync()
        for (const note of newNotes) {
          const pool = getPoolForTier(note.denomination)
          all.push({ ...note, appId: pool.appId })
        }
        await saveAllNotesAsync(all)
      }
    })
  }

  // Update deposit counter to one past the highest derivation index found.
  // This must track the derivation index (not match count), because spent notes
  // from privateSend/withdrawals also consumed derivation indices.
  if (highestDerivationIndex >= 0) {
    const updateCounter = () => {
      const newCounter = highestDerivationIndex + 1
      const current = getNextDepositIndex()
      if (newCounter > current) {
        const counterKey = _activeWallet
          ? `privacy_pool_deposit_counter_${_activeWallet}`
          : 'privacy_pool_deposit_counter'
        localStorage.setItem(counterKey, newCounter.toString())
      }
    }
    if (navigator.locks) {
      await navigator.locks.request('privacy_deposit_counter', () => updateCounter())
    } else {
      updateCounter()
    }
  }

  return { recovered, total, spent }
}

/** Check if a nullifier has already been spent on-chain */
export async function isNullifierSpent(
  client: algosdk.Algodv2,
  appId: number,
  nullifier: bigint,
): Promise<boolean> {
  const nullHash = computeNullifierHash(nullifier)
  const nullBytes = scalarToBytes(nullHash)
  const boxName = new Uint8Array(4 + nullBytes.length)
  boxName.set(new TextEncoder().encode('null'), 0)
  boxName.set(nullBytes, 4)
  try {
    await client.getApplicationBoxByName(appId, boxName).do()
    return true // box exists = spent
  } catch {
    return false // box doesn't exist = unspent
  }
}

// ── Password-Based Key Derivation (Pera fallback) ────────

const PWD_SALT_KEY = 'privacy_pool_pwd_salt'
const PWD_VERIFY_KEY = 'privacy_pool_pwd_verify' // AES-GCM encrypted marker (replaces plaintext hash)
const PWD_MARKER = 'privacy-pool-password-ok' // known plaintext for verification

/** Check if a password-derived key has been set up */
export function hasPasswordKey(): boolean {
  return localStorage.getItem(PWD_SALT_KEY) !== null
}

/** Clear password key data (for "forgot password" reset) */
export function clearPasswordKey(): void {
  localStorage.removeItem(PWD_SALT_KEY)
  localStorage.removeItem(PWD_VERIFY_KEY)
  localStorage.removeItem('privacy_pool_pwd_hash') // legacy
}

/** Derive an AES key from a password using PBKDF2 */
async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as ArrayBufferView<ArrayBuffer>, iterations: 600_000 },
    keyMaterial,
    256,
  )
  return new Uint8Array(bits)
}

/** Encrypt a known marker with the derived key — used to verify password without storing a hash */
async function encryptPasswordMarker(derived: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey('raw', derived as ArrayBufferView<ArrayBuffer>, 'AES-GCM', false, ['encrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(PWD_MARKER))
  const combined = new Uint8Array(12 + ct.byteLength)
  combined.set(iv, 0)
  combined.set(new Uint8Array(ct), 12)
  return Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('')
}

/** Decrypt the marker — throws on wrong password (AEAD tag mismatch) */
async function verifyPasswordMarker(derived: Uint8Array, markerHex: string): Promise<void> {
  const markerBytes = Uint8Array.from(markerHex.match(/.{2}/g)!.map(b => parseInt(b, 16)))
  const iv = markerBytes.slice(0, 12)
  const ct = markerBytes.slice(12)
  const key = await crypto.subtle.importKey('raw', derived as ArrayBufferView<ArrayBuffer>, 'AES-GCM', false, ['decrypt'])
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
    if (new TextDecoder().decode(pt) !== PWD_MARKER) throw new Error('Incorrect password')
  } catch {
    throw new Error('Incorrect password')
  }
}

/** Password attempt throttle — delays after repeated failures */
let _pwdFailCount = 0

/** Derive and cache a master key from a user-provided password */
export async function deriveMasterKeyFromPassword(password: string): Promise<bigint> {
  // Throttle after 5 consecutive failures: 1s delay per failure beyond 5
  if (_pwdFailCount >= 5) {
    const delay = (_pwdFailCount - 4) * 1000
    await new Promise(r => setTimeout(r, Math.min(delay, 10_000)))
  }

  await initMimc()

  let salt: Uint8Array
  const existingSaltHex = localStorage.getItem(PWD_SALT_KEY)

  if (existingSaltHex) {
    // Existing password — verify via AEAD decryption (no hash stored)
    salt = Uint8Array.from(existingSaltHex.match(/.{2}/g)!.map(b => parseInt(b, 16)))
    let derived: Uint8Array
    try {
      derived = await deriveKeyFromPassword(password, salt)
    } catch {
      _pwdFailCount++
      throw new Error('Incorrect password')
    }

    const storedMarker = localStorage.getItem(PWD_VERIFY_KEY)
    if (storedMarker) {
      try {
        await verifyPasswordMarker(derived, storedMarker)
      } catch {
        _pwdFailCount++
        throw new Error('Incorrect password')
      }
    }
    // Migrate: remove legacy hash if present
    localStorage.removeItem('privacy_pool_pwd_hash')

    _pwdFailCount = 0 // Reset on success
    const masterKey = bytesToScalar(derived) % BN254_R
    masterKeyDeterministic = true
    cachedMasterKey = masterKey
    cachedViewKeypair = deriveViewKeypair(masterKey)
    const encrypted = await encryptMasterKey(masterKey)
    sessionStorage.setItem(MASTER_KEY_SESSION, encrypted)
    resetKeyInactivityTimer()
    return masterKey
  } else {
    // New password setup
    salt = crypto.getRandomValues(new Uint8Array(32))
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
    const derived = await deriveKeyFromPassword(password, salt)

    // Store salt and AEAD-encrypted marker (no plaintext hash)
    localStorage.setItem(PWD_SALT_KEY, saltHex)
    localStorage.setItem(PWD_VERIFY_KEY, await encryptPasswordMarker(derived))

    const masterKey = bytesToScalar(derived) % BN254_R
    masterKeyDeterministic = true
    cachedMasterKey = masterKey
    cachedViewKeypair = deriveViewKeypair(masterKey)
    const encrypted = await encryptMasterKey(masterKey)
    sessionStorage.setItem(MASTER_KEY_SESSION, encrypted)
    resetKeyInactivityTimer()
    return masterKey
  }
}

/** Clear master key from memory (on wallet disconnect, tab hide, or manual wipe) */
export function clearMasterKey(): void {
  if (keyInactivityTimer) clearTimeout(keyInactivityTimer)
  wipeMasterKeyFromMemory()
  // Clear Falcon cached keypair/program when master key is wiped
  // Dynamic import to avoid circular dependency (falcon.ts imports from privacy.ts)
  import('./falcon').then(m => m.clearFalconCache()).catch(e => console.warn('[Falcon] Failed to clear cache:', e))
  // Revoke cached zkey blob URLs to free memory
  for (const blobUrl of verifiedZkeyBlobUrls.values()) {
    URL.revokeObjectURL(blobUrl)
  }
  verifiedZkeyBlobUrls.clear()
}

// ── Chain-Based Note Recovery (HPKE) ────

/**
 * Recover notes from on-chain HPKE envelopes using the view keypair.
 * Scans all pool app transactions for encrypted notes and merges with localStorage.
 */
export async function recoverNotesFromChain(
  viewKeypair: { privateKey: Uint8Array; publicKey: Uint8Array },
  poolAppIds: number[],
  fromRound?: number,
  onProgress?: (round: number, found: number) => void,
): Promise<{ recovered: DepositNote[]; newNotes: number }> {
  const scanResult = await scanChainForNotes(viewKeypair, poolAppIds, fromRound, onProgress)

  if (scanResult.errors.length > 0) {
    console.warn('Scanner encountered errors (results may be partial):', scanResult.errors)
  }

  // Merge with existing localStorage notes (deduplicate by commitment + appId)
  const mergeCount = await withNotesMutex(async () => {
    const existing = await loadNotes()
    const newNotes = scanResult.recovered.filter(cn =>
      !existing.some(en => en.commitment === cn.commitment && en.appId === cn.appId),
    )
    if (newNotes.length > 0) {
      const all = await loadAllNotesAsync()
      for (const note of newNotes) {
        all.push(note)
      }
      await saveAllNotesAsync(all)
    }
    return newNotes.length
  })

  return { recovered: scanResult.recovered, newNotes: mergeCount }
}

// ── Stale Note Detection ────────────────

/**
 * Find notes that are stale — pool has had many operations since note was created
 * but the note hasn't been touched. These are easier to identify by chain analysis.
 */
export function findStaleNotes(
  notes: DepositNote[],
  poolNextIndices: Map<number, number>,
  threshold: number = 20,
): DepositNote[] {
  return notes.filter(note => {
    if (!note.appId || note.leafIndex < 0) return false
    const nextIndex = poolNextIndices.get(note.appId)
    if (nextIndex === undefined) return false
    return nextIndex - note.leafIndex >= threshold
  })
}

// ── Utilities ───────────────────────────

export function formatAlgo(microAlgos: bigint | number): string {
  const n = typeof microAlgos === 'bigint' ? microAlgos : BigInt(microAlgos)
  const whole = n / 1_000_000n
  const frac = n % 1_000_000n
  const fracStr = frac.toString().padStart(6, '0').replace(/0+$/, '')
  return fracStr ? `${whole}.${fracStr}` : whole.toString()
}
