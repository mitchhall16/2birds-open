/**
 * @2birds/pool — Incremental Merkle Tree
 *
 * Off-chain mirror of the on-chain incremental Merkle tree.
 * Used to compute Merkle paths for withdrawal proofs.
 *
 * The incremental Merkle tree only stores the "frontier" (one node per level)
 * plus all inserted leaves. This allows computing any leaf's Merkle path
 * with O(n) storage and O(log n) path computation.
 *
 * Hash function: MiMC sponge (matches on-chain MiMC BN254_MP_110)
 */

import { mimcHash, initMimc, type Scalar, type MerklePath } from '@2birds/core';

/** Pre-computed zero hashes for each level of the Merkle tree */
function computeZeroHashes(depth: number): Scalar[] {
  const zeros: Scalar[] = [0n]; // zero hash at level 0
  for (let i = 1; i <= depth; i++) {
    zeros[i] = mimcHash(zeros[i - 1], zeros[i - 1]);
  }
  return zeros;
}

/**
 * IncrementalMerkleTree — mirrors the on-chain Merkle tree for proof generation.
 */
export class IncrementalMerkleTree {
  readonly depth: number;
  readonly zeroHashes: Scalar[];
  private leaves: Scalar[] = [];
  private layers: Scalar[][] = [];

  private constructor(depth: number, zeroHashes: Scalar[]) {
    this.depth = depth;
    this.zeroHashes = zeroHashes;
    this.layers = Array.from({ length: depth + 1 }, () => []);
  }

  /** Create a new Merkle tree. Must use this factory (MiMC requires async init). */
  static async create(depth: number = 20): Promise<IncrementalMerkleTree> {
    await initMimc();
    const zeroHashes = computeZeroHashes(depth);
    return new IncrementalMerkleTree(depth, zeroHashes);
  }

  /** Get the current Merkle root */
  get root(): Scalar {
    if (this.leaves.length === 0) {
      return this.zeroHashes[this.depth];
    }
    return this.computeRoot();
  }

  /** Get the number of leaves inserted */
  get nextIndex(): number {
    return this.leaves.length;
  }

  /** Insert a new leaf (commitment) */
  insert(leaf: Scalar): number {
    const index = this.leaves.length;
    if (index >= 2 ** this.depth) {
      throw new Error('Merkle tree is full');
    }
    this.leaves.push(leaf);
    this.rebuildLayers();
    return index;
  }

  /** Get the Merkle path for a leaf at the given index */
  getPath(leafIndex: number): MerklePath {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Leaf index ${leafIndex} out of range [0, ${this.leaves.length})`);
    }

    const pathElements: Scalar[] = [];
    const pathIndices: number[] = [];

    let currentIndex = leafIndex;

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIndex % 2 === 1;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;

      pathIndices.push(isRight ? 1 : 0);

      if (siblingIndex < this.layers[level].length) {
        pathElements.push(this.layers[level][siblingIndex]);
      } else {
        pathElements.push(this.zeroHashes[level]);
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return { pathElements, pathIndices };
  }

  /** Verify a Merkle path */
  verifyPath(leaf: Scalar, path: MerklePath, root: Scalar): boolean {
    let currentHash = leaf;
    for (let i = 0; i < this.depth; i++) {
      if (path.pathIndices[i] === 0) {
        currentHash = mimcHash(currentHash, path.pathElements[i]);
      } else {
        currentHash = mimcHash(path.pathElements[i], currentHash);
      }
    }
    return currentHash === root;
  }

  /** Rebuild all layers from leaves */
  private rebuildLayers(): void {
    this.layers[0] = [...this.leaves];

    for (let level = 1; level <= this.depth; level++) {
      const prevLayer = this.layers[level - 1];
      const currentLayer: Scalar[] = [];

      for (let i = 0; i < prevLayer.length; i += 2) {
        const left = prevLayer[i];
        const right = i + 1 < prevLayer.length ? prevLayer[i + 1] : this.zeroHashes[level - 1];
        currentLayer.push(mimcHash(left, right));
      }

      this.layers[level] = currentLayer;
    }
  }

  /** Compute root from current layers */
  private computeRoot(): Scalar {
    if (this.layers[this.depth] && this.layers[this.depth].length > 0) {
      return this.layers[this.depth][0];
    }
    return this.zeroHashes[this.depth];
  }

  /** Serialize tree state for persistence */
  serialize(): string {
    return JSON.stringify({
      depth: this.depth,
      leaves: this.leaves.map(l => l.toString()),
    });
  }

  /** Deserialize tree state */
  static async deserialize(json: string): Promise<IncrementalMerkleTree> {
    const obj = JSON.parse(json);
    const tree = await IncrementalMerkleTree.create(obj.depth);
    for (const leaf of obj.leaves) {
      tree.insert(BigInt(leaf));
    }
    return tree;
  }
}
