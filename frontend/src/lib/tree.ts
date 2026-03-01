/**
 * Local MiMC Merkle Tree — mirrors on-chain commitment storage.
 *
 * The on-chain contract stores raw commitments (no SHA256 tree).
 * This module maintains a local incremental Merkle tree using MiMC hashing
 * so that we can generate ZK proofs (Merkle paths) for withdrawals.
 *
 * Ported from packages/pool/src/pool/merkle.ts (~60 lines core logic).
 */

import { initMimc, mimcHash, bytesToScalar, scalarToBytes } from './privacy'
import { CONTRACTS, ALGOD_CONFIG } from './config'
import algosdk from 'algosdk'

const TREE_DEPTH = 20
const TREE_STORAGE_KEY = 'privacy_pool_merkle_tree'

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

  insert(leaf: Scalar): number {
    const index = this.leaves.length
    if (index >= 2 ** this.depth) throw new Error('Merkle tree is full')
    this.leaves.push(leaf)
    this.rebuildLayers()
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

  private rebuildLayers(): void {
    this.layers[0] = [...this.leaves]

    for (let level = 1; level <= this.depth; level++) {
      const prevLayer = this.layers[level - 1]
      const currentLayer: Scalar[] = []

      for (let i = 0; i < prevLayer.length; i += 2) {
        const left = prevLayer[i]
        const right = i + 1 < prevLayer.length ? prevLayer[i + 1] : this.zeroHashes[level - 1]
        currentLayer.push(mimcHash(left, right))
      }

      this.layers[level] = currentLayer
    }
  }

  serialize(): string {
    return JSON.stringify({
      depth: this.depth,
      leaves: this.leaves.map(l => l.toString()),
    })
  }
}

// ── Module-level tree cache ──────────────────

let cachedTree: MerkleTree | null = null

/** Get or create the local Merkle tree (loads from localStorage if available) */
export async function getOrCreateTree(): Promise<MerkleTree> {
  if (cachedTree) return cachedTree

  await initMimc()
  const zeroHashes = computeZeroHashes(TREE_DEPTH)

  const stored = localStorage.getItem(TREE_STORAGE_KEY)
  if (stored) {
    try {
      const obj = JSON.parse(stored)
      const tree = new MerkleTree(obj.depth ?? TREE_DEPTH, zeroHashes)
      for (const leaf of obj.leaves) {
        tree.insert(BigInt(leaf))
      }
      cachedTree = tree
      return tree
    } catch {
      // Corrupted — create fresh
    }
  }

  cachedTree = new MerkleTree(TREE_DEPTH, zeroHashes)
  return cachedTree
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

/** Persist the tree to localStorage */
export function saveTree(tree: MerkleTree): void {
  localStorage.setItem(TREE_STORAGE_KEY, tree.serialize())
}

/** Rebuild the tree from on-chain commitment boxes (recovery / sync) */
export async function syncTreeFromChain(appId?: number): Promise<MerkleTree> {
  await initMimc()
  const zeroHashes = computeZeroHashes(TREE_DEPTH)
  const tree = new MerkleTree(TREE_DEPTH, zeroHashes)

  const id = appId ?? CONTRACTS.PrivacyPool.appId
  const client = new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)

  // Read nextIndex from global state
  const appInfo = await client.getApplicationByID(id).do()
  const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []

  let nextIndex = 0
  for (const kv of globalState) {
    const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
    if (key === 'next_idx') {
      nextIndex = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
    }
  }

  // Read each commitment box sequentially
  const enc = new TextEncoder()
  for (let i = 0; i < nextIndex; i++) {
    const boxName = new Uint8Array(11) // "cmt" (3) + uint64 (8)
    boxName.set(enc.encode('cmt'), 0)
    const idxBytes = new Uint8Array(8)
    let val = BigInt(i)
    for (let b = 7; b >= 0; b--) {
      idxBytes[b] = Number(val & 0xffn)
      val >>= 8n
    }
    boxName.set(idxBytes, 3)

    try {
      const boxResult = await client.getApplicationBoxByName(id, boxName).do()
      const commitment = bytesToScalar(boxResult.value)
      tree.insert(commitment)
    } catch {
      console.warn(`Missing commitment box at index ${i}, stopping sync`)
      break
    }
  }

  cachedTree = tree
  saveTree(tree)
  return tree
}

/** Clear the cached tree (useful when switching contracts) */
export function clearTreeCache(): void {
  cachedTree = null
  localStorage.removeItem(TREE_STORAGE_KEY)
}

export type { MerklePath, MerkleTree }
