/**
 * Local MiMC Merkle Tree — mirrors on-chain commitment storage.
 *
 * The on-chain contract stores raw commitments (no SHA256 tree).
 * This module maintains a local incremental Merkle tree using MiMC hashing
 * so that we can generate ZK proofs (Merkle paths) for withdrawals.
 *
 * Trees are keyed by pool appId so each pool has its own independent tree.
 */

import { initMimc, mimcHash, bytesToScalar, scalarToBytes } from './privacy'
import { CONTRACTS, ALGOD_CONFIG, POOL_CONTRACTS, getAllPools } from './config'
import algosdk from 'algosdk'

const TREE_DEPTH = 16
const TREE_CAPACITY = 2 ** TREE_DEPTH // 65536
const OLD_TREE_STORAGE_KEY = 'privacy_pool_merkle_tree'

function treeStorageKey(appId: number): string {
  return `privacy_pool_merkle_tree_${appId}`
}

type Scalar = bigint

interface MerklePath {
  pathElements: Scalar[]
  pathIndices: number[]
}

/** Pre-compute zero hashes for each tree level */
function computeZeroHashes(depth: number): Scalar[] {
  const zeros: Scalar[] = [0n]
  for (let i = 1; i <= depth; i++) {
    zeros[i] = mimcHash(zeros[i - 1], zeros[i - 1])
  }
  return zeros
}

/** Incremental Merkle tree with MiMC hashing */
class MerkleTree {
  readonly depth: number
  readonly zeroHashes: Scalar[]
  private leaves: Scalar[] = []
  private layers: Scalar[][] = []

  constructor(depth: number, zeroHashes: Scalar[]) {
    this.depth = depth
    this.zeroHashes = zeroHashes
    this.layers = Array.from({ length: depth + 1 }, () => [])
  }

  get root(): Scalar {
    if (this.leaves.length === 0) return this.zeroHashes[this.depth]
    return this.layers[this.depth]?.[0] ?? this.zeroHashes[this.depth]
  }

  get nextIndex(): number {
    return this.leaves.length
  }

  /** Maximum number of leaves this tree can hold */
  get capacity(): number {
    return 2 ** this.depth
  }

  /** Number of remaining empty leaf slots */
  get remainingCapacity(): number {
    return this.capacity - this.leaves.length
  }

  /** Percentage of tree capacity used (0–100) */
  get percentFull(): number {
    return (this.leaves.length / this.capacity) * 100
  }

  /** True when the tree has zero remaining capacity */
  get isFull(): boolean {
    return this.leaves.length >= this.capacity
  }

  /** True when the tree is at or above the given threshold (0–100) */
  isApproachingCapacity(thresholdPercent: number = 90): boolean {
    return this.percentFull >= thresholdPercent
  }

  insert(leaf: Scalar): number {
    const index = this.leaves.length
    if (index >= 2 ** this.depth) throw new Error('Merkle tree is full')
    this.leaves.push(leaf)

    // O(depth) incremental update — only recompute hashes along the insertion path
    this.layers[0].push(leaf)
    let currentIndex = index

    for (let level = 0; level < this.depth; level++) {
      const parentIndex = Math.floor(currentIndex / 2)
      const leftIndex = parentIndex * 2
      const rightIndex = leftIndex + 1

      const left = this.layers[level][leftIndex]
      const right = rightIndex < this.layers[level].length
        ? this.layers[level][rightIndex]
        : this.zeroHashes[level]
      const parent = mimcHash(left, right)

      if (parentIndex < this.layers[level + 1].length) {
        this.layers[level + 1][parentIndex] = parent
      } else {
        this.layers[level + 1].push(parent)
      }

      currentIndex = parentIndex
    }

    return index
  }

  getPath(leafIndex: number): MerklePath {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Leaf index ${leafIndex} out of range [0, ${this.leaves.length})`)
    }

    const pathElements: Scalar[] = []
    const pathIndices: number[] = []
    let currentIndex = leafIndex

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1

      pathIndices.push(isRight ? 1 : 0)

      if (siblingIndex < this.layers[level].length) {
        pathElements.push(this.layers[level][siblingIndex])
      } else {
        pathElements.push(this.zeroHashes[level])
      }

      currentIndex = Math.floor(currentIndex / 2)
    }

    return { pathElements, pathIndices }
  }

  serialize(): string {
    return JSON.stringify({
      depth: this.depth,
      leaves: this.leaves.map(l => l.toString()),
    })
  }
}

// ── Module-level tree cache (keyed by appId) ──────────────────

const cachedTrees = new Map<number, MerkleTree>()

/** Migrate old single-key tree storage to per-pool key if it exists */
async function migrateOldTree(zeroHashes: Scalar[]): Promise<void> {
  const stored = localStorage.getItem(OLD_TREE_STORAGE_KEY)
  if (!stored) return

  try {
    const obj = JSON.parse(stored)
    const leafCount = obj.leaves?.length ?? 0
    if (leafCount === 0) {
      localStorage.removeItem(OLD_TREE_STORAGE_KEY)
      return
    }

    // Try to find which pool this tree belongs to by comparing leaf count to on-chain next_idx
    const client = new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)
    for (const pool of getAllPools()) {
      try {
        const appInfo = await client.getApplicationByID(pool.appId).do()
        const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
        let nextIndex = 0
        for (const kv of globalState) {
          const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
          if (key === 'next_idx') nextIndex = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
        }
        if (nextIndex > 0 && nextIndex === leafCount) {
          localStorage.setItem(treeStorageKey(pool.appId), stored)
          break
        }
      } catch {
        continue
      }
    }
  } catch {
    // Corrupted data
  }

  localStorage.removeItem(OLD_TREE_STORAGE_KEY)
}

/** Get or create the local Merkle tree for a specific pool */
export async function getOrCreateTree(appId: number): Promise<MerkleTree> {
  const cached = cachedTrees.get(appId)
  if (cached) return cached

  await initMimc()
  const zeroHashes = computeZeroHashes(TREE_DEPTH)

  // Migrate old single-key storage on first access
  if (localStorage.getItem(OLD_TREE_STORAGE_KEY)) {
    await migrateOldTree(zeroHashes)
  }

  const stored = localStorage.getItem(treeStorageKey(appId))
  if (stored) {
    try {
      const obj = JSON.parse(stored)
      const tree = new MerkleTree(obj.depth ?? TREE_DEPTH, zeroHashes)
      for (const leaf of obj.leaves) {
        tree.insert(BigInt(leaf))
      }
      cachedTrees.set(appId, tree)
      return tree
    } catch {
      // Corrupted — create fresh
    }
  }

  const tree = new MerkleTree(TREE_DEPTH, zeroHashes)
  cachedTrees.set(appId, tree)
  return tree
}

/** Insert a commitment leaf and return the new MiMC root */
export function insertLeaf(tree: MerkleTree, commitment: bigint): { index: number; root: bigint } {
  const index = tree.insert(commitment)
  return { index, root: tree.root }
}

/** Get the Merkle path for a leaf at a given index */
export function getPath(tree: MerkleTree, leafIndex: number): MerklePath {
  return tree.getPath(leafIndex)
}

/** Persist the tree to localStorage for a specific pool */
export function saveTree(tree: MerkleTree, appId: number): void {
  localStorage.setItem(treeStorageKey(appId), tree.serialize())
}

/** Read on-chain nextIndex for a pool */
async function readOnChainNextIndex(client: algosdk.Algodv2, appId: number): Promise<number> {
  const appInfo = await client.getApplicationByID(appId).do()
  const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
  for (const kv of globalState) {
    const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
    if (key === 'next_idx') return Number(kv.value?.uint ?? kv.value?.ui ?? 0)
  }
  return 0
}

/** Fetch a single commitment box from chain */
async function fetchCommitmentBox(client: algosdk.Algodv2, appId: number, index: number): Promise<bigint> {
  const boxName = new Uint8Array(11) // "cmt" (3) + uint64 (8)
  boxName.set(new TextEncoder().encode('cmt'), 0)
  const idxBytes = new Uint8Array(8)
  let val = BigInt(index)
  for (let b = 7; b >= 0; b--) {
    idxBytes[b] = Number(val & 0xffn)
    val >>= 8n
  }
  boxName.set(idxBytes, 3)
  const boxResult = await client.getApplicationBoxByName(appId, boxName).do()
  return bytesToScalar(boxResult.value)
}

/**
 * Incremental tree sync — only fetches new leaves since last sync.
 * O(delta) instead of O(N). Falls back to full rebuild if local tree is corrupted.
 */
export async function incrementalSyncTree(appId: number): Promise<MerkleTree> {
  await initMimc()

  const client = new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)
  const onChainNextIndex = await readOnChainNextIndex(client, appId)

  // Load existing local tree
  const tree = await getOrCreateTree(appId)
  const localNextIndex = tree.nextIndex

  if (localNextIndex === onChainNextIndex) {
    // Already in sync
    return tree
  }

  if (localNextIndex > onChainNextIndex) {
    // Local tree is ahead of chain — corrupted, do full rebuild
    console.warn(`Local tree ahead of chain (${localNextIndex} > ${onChainNextIndex}), rebuilding`)
    return syncTreeFromChain(appId)
  }

  // Fetch only the missing leaves (delta)
  for (let i = localNextIndex; i < onChainNextIndex; i++) {
    try {
      const commitment = await fetchCommitmentBox(client, appId, i)
      tree.insert(commitment)
    } catch {
      console.warn(`Missing commitment box at index ${i}, falling back to full rebuild`)
      return syncTreeFromChain(appId)
    }
  }

  cachedTrees.set(appId, tree)
  saveTree(tree, appId)
  return tree
}

/** Rebuild the tree from on-chain commitment boxes (full recovery / sync) */
export async function syncTreeFromChain(appId: number): Promise<MerkleTree> {
  await initMimc()
  const zeroHashes = computeZeroHashes(TREE_DEPTH)
  const tree = new MerkleTree(TREE_DEPTH, zeroHashes)

  const client = new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)
  const nextIndex = await readOnChainNextIndex(client, appId)

  // Read each commitment box sequentially
  for (let i = 0; i < nextIndex; i++) {
    try {
      const commitment = await fetchCommitmentBox(client, appId, i)
      tree.insert(commitment)
    } catch {
      console.warn(`Missing commitment box at index ${i}, stopping sync`)
      break
    }
  }

  cachedTrees.set(appId, tree)
  saveTree(tree, appId)
  return tree
}

/** Sync all pool trees from chain (across all generations) */
export async function syncAllTreesFromChain(
  onProgress?: (pool: string, done: boolean) => void,
): Promise<void> {
  for (const pool of getAllPools()) {
    const label = `pool ${pool.appId}`
    onProgress?.(label, false)
    try {
      await syncTreeFromChain(pool.appId)
    } catch (err) {
      console.warn(`Failed to sync tree for pool ${pool.appId}:`, err)
    }
    onProgress?.(label, true)
  }
}

/** Clear the cached tree (useful when switching contracts) */
export function clearTreeCache(appId?: number): void {
  if (appId !== undefined) {
    cachedTrees.delete(appId)
    localStorage.removeItem(treeStorageKey(appId))
  } else {
    cachedTrees.clear()
    for (const pool of getAllPools()) {
      localStorage.removeItem(treeStorageKey(pool.appId))
    }
  }
}

/** Get capacity info for a pool's tree without mutating it */
export function getTreeCapacityInfo(tree: MerkleTree): {
  capacity: number
  used: number
  remaining: number
  percentFull: number
  isFull: boolean
  isNearFull: boolean
} {
  return {
    capacity: tree.capacity,
    used: tree.nextIndex,
    remaining: tree.remainingCapacity,
    percentFull: tree.percentFull,
    isFull: tree.isFull,
    isNearFull: tree.isApproachingCapacity(90),
  }
}

/**
 * Check pool capacity from on-chain nextIndex (no local tree needed).
 * Useful for fast pre-flight checks before expensive proof generation.
 */
export function checkPoolCapacity(nextIndex: number): {
  capacity: number
  used: number
  remaining: number
  percentFull: number
  isFull: boolean
  isNearFull: boolean
} {
  const capacity = TREE_CAPACITY
  const used = nextIndex
  const remaining = capacity - used
  const percentFull = (used / capacity) * 100
  return {
    capacity,
    used,
    remaining,
    percentFull,
    isFull: remaining <= 0,
    isNearFull: percentFull >= 90,
  }
}

export { TREE_DEPTH, TREE_CAPACITY }

export type { MerklePath, MerkleTree }
