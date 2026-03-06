import { describe, it, expect, beforeAll } from 'vitest';
import { IncrementalMerkleTree } from '../index.js';
import { initMimc, mimcHash, randomScalar } from '@2birds/core';

describe('Incremental Merkle Tree', () => {
  beforeAll(async () => {
    await initMimc();
  });

  it('creates a tree with an empty root', async () => {
    const tree = await IncrementalMerkleTree.create(4);
    expect(tree.root).not.toBe(0n);
    expect(tree.nextIndex).toBe(0);
  });

  it('inserting a leaf changes the root', async () => {
    const tree = await IncrementalMerkleTree.create(4);
    const emptyRoot = tree.root;
    tree.insert(123n);
    expect(tree.root).not.toBe(emptyRoot);
    expect(tree.nextIndex).toBe(1);
  });

  it('different leaves produce different roots', async () => {
    const tree1 = await IncrementalMerkleTree.create(4);
    const tree2 = await IncrementalMerkleTree.create(4);
    tree1.insert(111n);
    tree2.insert(222n);
    expect(tree1.root).not.toBe(tree2.root);
  });

  it('same sequence of inserts produces same root', async () => {
    const tree1 = await IncrementalMerkleTree.create(4);
    const tree2 = await IncrementalMerkleTree.create(4);
    tree1.insert(100n);
    tree1.insert(200n);
    tree2.insert(100n);
    tree2.insert(200n);
    expect(tree1.root).toBe(tree2.root);
  });

  describe('Merkle path verification', () => {
    it('verifies a valid path for a single leaf', async () => {
      const tree = await IncrementalMerkleTree.create(4);
      const leaf = 42n;
      const idx = tree.insert(leaf);
      const path = tree.getPath(idx);
      expect(tree.verifyPath(leaf, path, tree.root)).toBe(true);
    });

    it('verifies paths for multiple leaves', async () => {
      const tree = await IncrementalMerkleTree.create(4);
      const leaves = [10n, 20n, 30n, 40n, 50n];
      const indices = leaves.map(l => tree.insert(l));

      for (let i = 0; i < leaves.length; i++) {
        const path = tree.getPath(indices[i]);
        expect(tree.verifyPath(leaves[i], path, tree.root)).toBe(true);
      }
    });

    it('rejects a wrong leaf', async () => {
      const tree = await IncrementalMerkleTree.create(4);
      tree.insert(42n);
      const path = tree.getPath(0);
      expect(tree.verifyPath(99n, path, tree.root)).toBe(false);
    });

    it('rejects a wrong root', async () => {
      const tree = await IncrementalMerkleTree.create(4);
      const leaf = 42n;
      tree.insert(leaf);
      const path = tree.getPath(0);
      expect(tree.verifyPath(leaf, path, 999n)).toBe(false);
    });

    it('path elements have correct length', async () => {
      const depth = 8;
      const tree = await IncrementalMerkleTree.create(depth);
      tree.insert(1n);
      const path = tree.getPath(0);
      expect(path.pathElements.length).toBe(depth);
      expect(path.pathIndices.length).toBe(depth);
    });
  });

  describe('Serialization', () => {
    it('round-trips via serialize/deserialize', async () => {
      const tree = await IncrementalMerkleTree.create(4);
      tree.insert(100n);
      tree.insert(200n);
      tree.insert(300n);
      const rootBefore = tree.root;

      const json = tree.serialize();
      const restored = await IncrementalMerkleTree.deserialize(json);
      expect(restored.root).toBe(rootBefore);
      expect(restored.nextIndex).toBe(3);
    });
  });

  describe('Edge cases', () => {
    it('throws when getting path for out-of-range index', async () => {
      const tree = await IncrementalMerkleTree.create(4);
      tree.insert(1n);
      expect(() => tree.getPath(5)).toThrow();
    });

    it('works with depth 2 (4 leaves max)', async () => {
      const tree = await IncrementalMerkleTree.create(2);
      tree.insert(1n);
      tree.insert(2n);
      tree.insert(3n);
      tree.insert(4n);
      expect(tree.nextIndex).toBe(4);

      // All paths should verify
      for (let i = 0; i < 4; i++) {
        const path = tree.getPath(i);
        expect(tree.verifyPath(BigInt(i + 1), path, tree.root)).toBe(true);
      }
    });
  });
});
