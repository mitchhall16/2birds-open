pragma circom 2.0.0;

include "../node_modules/circomlibjs/circuits/mimcsponge.circom";
include "merkleTree.circom";

/**
 * Combine circuit — proves two withdrawals from pool A and one deposit into pool B.
 *
 * Proves:
 * 1. Prover knows two (secret, nullifier) pairs whose commitments exist in tree A at rootA
 * 2. One new commitment was correctly inserted into tree B
 * 3. 2 * denomA == denomB (e.g., two 0.5 ALGO → 1.0 ALGO)
 *
 * Conservation: Two input denominations sum to exactly the output denomination,
 * ensuring no value is created or destroyed during the combine.
 */
template Combine(levels) {
    // Public inputs — pool A (source, two withdrawals)
    signal input rootA;
    signal input nullifierHash1;
    signal input nullifierHash2;
    signal input denomA;

    // Public inputs — pool B (destination, one deposit)
    signal input oldRootB;
    signal input newRootB;
    signal input commitment;
    signal input leafIndex;
    signal input denomB;

    // Anti-frontrun binding
    signal input recipient;      // Pool B app address
    signal input relayer;
    signal input fee;

    // Private inputs — pool A (two notes to spend)
    signal input secret1;
    signal input nullifier1;
    signal input pathElementsA1[levels];
    signal input pathIndicesA1[levels];
    signal input secret2;
    signal input nullifier2;
    signal input pathElementsA2[levels];
    signal input pathIndicesA2[levels];

    // Private inputs — pool B (one note to create)
    signal input secretB;
    signal input nullifierB;
    signal input pathElementsB[levels];

    // ── Denomination conservation ──
    // 2 * denomA must equal denomB
    signal doubledDenomA;
    doubledDenomA <== 2 * denomA;
    denomB === doubledDenomA;

    // ── Pool A: Verify first withdrawal ──

    // Commitment 1: MiMC(secret1, nullifier1, denomA)
    component commitHasher1 = MiMCSponge(3, 220, 1);
    commitHasher1.ins[0] <== secret1;
    commitHasher1.ins[1] <== nullifier1;
    commitHasher1.ins[2] <== denomA;
    commitHasher1.k <== 0;

    // Nullifier hash 1: MiMC(nullifier1)
    component nullHasher1 = MiMCSponge(1, 220, 1);
    nullHasher1.ins[0] <== nullifier1;
    nullHasher1.k <== 0;
    nullHasher1.outs[0] === nullifierHash1;

    // Verify commitment 1 exists in tree A
    component treeChecker1 = MerkleTreeChecker(levels);
    treeChecker1.leaf <== commitHasher1.outs[0];
    treeChecker1.root <== rootA;
    for (var i = 0; i < levels; i++) {
        treeChecker1.pathElements[i] <== pathElementsA1[i];
        treeChecker1.pathIndices[i] <== pathIndicesA1[i];
    }

    // ── Pool A: Verify second withdrawal ──

    // Commitment 2: MiMC(secret2, nullifier2, denomA)
    component commitHasher2 = MiMCSponge(3, 220, 1);
    commitHasher2.ins[0] <== secret2;
    commitHasher2.ins[1] <== nullifier2;
    commitHasher2.ins[2] <== denomA;
    commitHasher2.k <== 0;

    // Nullifier hash 2: MiMC(nullifier2)
    component nullHasher2 = MiMCSponge(1, 220, 1);
    nullHasher2.ins[0] <== nullifier2;
    nullHasher2.k <== 0;
    nullHasher2.outs[0] === nullifierHash2;

    // Verify commitment 2 exists in tree A
    component treeChecker2 = MerkleTreeChecker(levels);
    treeChecker2.leaf <== commitHasher2.outs[0];
    treeChecker2.root <== rootA;
    for (var i = 0; i < levels; i++) {
        treeChecker2.pathElements[i] <== pathElementsA2[i];
        treeChecker2.pathIndices[i] <== pathIndicesA2[i];
    }

    // ── Pool B: Verify deposit ──

    // Commitment: MiMC(secretB, nullifierB, denomB)
    component commitHasherB = MiMCSponge(3, 220, 1);
    commitHasherB.ins[0] <== secretB;
    commitHasherB.ins[1] <== nullifierB;
    commitHasherB.ins[2] <== denomB;
    commitHasherB.k <== 0;
    commitHasherB.outs[0] === commitment;

    // Convert leafIndex to bits
    component idxBits = Num2Bits(levels);
    idxBits.in <== leafIndex;

    // Verify insertion: commitment at leafIndex → newRootB
    component insertChecker = MerkleTreeChecker(levels);
    insertChecker.leaf <== commitment;
    insertChecker.root <== newRootB;
    for (var i = 0; i < levels; i++) {
        insertChecker.pathElements[i] <== pathElementsB[i];
        insertChecker.pathIndices[i] <== idxBits.out[i];
    }

    // Verify old root: empty (0) at leafIndex → oldRootB
    component oldRootChecker = MerkleTreeChecker(levels);
    oldRootChecker.leaf <== 0;
    oldRootChecker.root <== oldRootB;
    for (var i = 0; i < levels; i++) {
        oldRootChecker.pathElements[i] <== pathElementsB[i];
        oldRootChecker.pathIndices[i] <== idxBits.out[i];
    }

    // ── Anti-frontrun binding ──
    signal recipientSquare;
    signal relayerSquare;
    signal feeSquare;
    recipientSquare <== recipient * recipient;
    relayerSquare <== relayer * relayer;
    feeSquare <== fee * fee;
}

component main {public [rootA, nullifierHash1, nullifierHash2, denomA, oldRootB, newRootB, commitment, leafIndex, denomB, recipient, relayer, fee]} = Combine(16);
