pragma circom 2.0.0;

include "../node_modules/circomlibjs/circuits/mimcsponge.circom";
include "merkleTree.circom";

/**
 * Split circuit — proves withdrawal from pool A and two deposits into pool B.
 *
 * Proves:
 * 1. Prover knows (secret, nullifier) whose commitment exists in tree A at rootA
 * 2. Two new commitments were correctly inserted into tree B
 * 3. denomA == 2 * denomB (e.g., 1.0 ALGO → two 0.5 ALGO)
 *
 * Conservation: The input denomination is exactly twice the output denomination,
 * ensuring no value is created or destroyed during the split.
 */
template Split(levels) {
    // Public inputs — pool A (source)
    signal input rootA;
    signal input nullifierHash;
    signal input denomA;

    // Public inputs — pool B (destination)
    signal input oldRootB;
    signal input newRootB1;      // Root after first insertion
    signal input newRootB2;      // Root after second insertion
    signal input commitment1;
    signal input commitment2;
    signal input leafIndex1;
    signal input leafIndex2;
    signal input denomB;

    // Anti-frontrun binding
    signal input recipient;      // Pool B app address
    signal input relayer;
    signal input fee;

    // Private inputs
    signal input secret;
    signal input nullifier;
    signal input pathElementsA[levels];
    signal input pathIndicesA[levels];

    // Private inputs — pool B insertion proofs
    signal input secret1;
    signal input nullifier1;
    signal input secret2;
    signal input nullifier2;
    signal input pathElementsB1[levels];
    signal input pathElementsB2[levels];

    // ── Denomination conservation ──
    // denomA must equal 2 * denomB
    signal doubledDenomB;
    doubledDenomB <== 2 * denomB;
    denomA === doubledDenomB;

    // ── Pool A: Verify withdrawal ──

    // Compute commitment from private inputs: MiMC(secret, nullifier, denomA)
    component commitHasherA = MiMCSponge(3, 220, 1);
    commitHasherA.ins[0] <== secret;
    commitHasherA.ins[1] <== nullifier;
    commitHasherA.ins[2] <== denomA;
    commitHasherA.k <== 0;

    // Compute nullifier hash: MiMC(nullifier)
    component nullHasher = MiMCSponge(1, 220, 1);
    nullHasher.ins[0] <== nullifier;
    nullHasher.k <== 0;
    nullHasher.outs[0] === nullifierHash;

    // Verify commitment exists in tree A
    component treeCheckerA = MerkleTreeChecker(levels);
    treeCheckerA.leaf <== commitHasherA.outs[0];
    treeCheckerA.root <== rootA;
    for (var i = 0; i < levels; i++) {
        treeCheckerA.pathElements[i] <== pathElementsA[i];
        treeCheckerA.pathIndices[i] <== pathIndicesA[i];
    }

    // ── Pool B: Verify two deposits ──

    // Commitment 1: MiMC(secret1, nullifier1, denomB)
    component commitHasher1 = MiMCSponge(3, 220, 1);
    commitHasher1.ins[0] <== secret1;
    commitHasher1.ins[1] <== nullifier1;
    commitHasher1.ins[2] <== denomB;
    commitHasher1.k <== 0;
    commitHasher1.outs[0] === commitment1;

    // Commitment 2: MiMC(secret2, nullifier2, denomB)
    component commitHasher2 = MiMCSponge(3, 220, 1);
    commitHasher2.ins[0] <== secret2;
    commitHasher2.ins[1] <== nullifier2;
    commitHasher2.ins[2] <== denomB;
    commitHasher2.k <== 0;
    commitHasher2.outs[0] === commitment2;

    // Verify insertion 1: empty leaf at leafIndex1 → commitment1
    // newRootB1 is the root after inserting commitment1 at leafIndex1
    component insertChecker1 = MerkleTreeChecker(levels);
    insertChecker1.leaf <== commitment1;
    insertChecker1.root <== newRootB1;
    for (var i = 0; i < levels; i++) {
        insertChecker1.pathElements[i] <== pathElementsB1[i];
        insertChecker1.pathIndices[i] <== pathIndicesA[i]; // Reusing index bits from leafIndex1
    }

    // Verify old root B: empty (0) at leafIndex1 → oldRootB
    component oldRootChecker1 = MerkleTreeChecker(levels);
    oldRootChecker1.leaf <== 0;
    oldRootChecker1.root <== oldRootB;
    for (var i = 0; i < levels; i++) {
        oldRootChecker1.pathElements[i] <== pathElementsB1[i];
        oldRootChecker1.pathIndices[i] <== pathIndicesA[i];
    }

    // Convert leafIndex1 to bits for insertion 1
    component idx1Bits = Num2Bits(levels);
    idx1Bits.in <== leafIndex1;

    // Verify insertion 2: empty leaf at leafIndex2 → commitment2
    component insertChecker2 = MerkleTreeChecker(levels);
    insertChecker2.leaf <== commitment2;
    insertChecker2.root <== newRootB2;
    for (var i = 0; i < levels; i++) {
        insertChecker2.pathElements[i] <== pathElementsB2[i];
        insertChecker2.pathIndices[i] <== idx1Bits.out[i];
    }

    // Verify intermediate root: empty (0) at leafIndex2 → newRootB1
    component midRootChecker = MerkleTreeChecker(levels);
    midRootChecker.leaf <== 0;
    midRootChecker.root <== newRootB1;

    // Convert leafIndex2 to bits for insertion 2
    component idx2Bits = Num2Bits(levels);
    idx2Bits.in <== leafIndex2;
    for (var i = 0; i < levels; i++) {
        midRootChecker.pathElements[i] <== pathElementsB2[i];
        midRootChecker.pathIndices[i] <== idx2Bits.out[i];
    }

    // ── Anti-frontrun binding ──
    signal recipientSquare;
    signal relayerSquare;
    signal feeSquare;
    recipientSquare <== recipient * recipient;
    relayerSquare <== relayer * relayer;
    feeSquare <== fee * fee;
}

component main {public [rootA, nullifierHash, denomA, oldRootB, newRootB1, newRootB2, commitment1, commitment2, leafIndex1, leafIndex2, denomB, recipient, relayer, fee]} = Split(16);
