pragma circom 2.1.6;

/**
 * Shielded Transfer Circuit — Full Privacy (Phase 4)
 *
 * Combines:
 * - Merkle tree membership (privacy pool)
 * - Nullifier derivation (double-spend prevention)
 * - Amount conservation (confidential transactions)
 * - Range proofs (non-negative amounts)
 * - Anti-frontrunning (relayer + fee binding)
 *
 * UTXO model: consumes N input notes, creates M output notes.
 * Fixed N=2 inputs and M=2 outputs (like Zcash Sapling).
 * Zero-amount inputs/outputs are treated as dummies (Merkle proof skipped).
 *
 * Each note: { amount, ownerPubKey, blinding, nullifier }
 * Commitment = MiMC(amount, ownerPubKey, blinding, nullifier)
 * NullifierHash = MiMC(nullifier, spendingKey)
 *
 * Public:  root, nullifierHashes[2], outputCommitments[2], relayer, fee
 * Private: inputAmounts[2], inputBlindings[2], inputNullifiers[2],
 *          inputPaths[2][20], inputIndices[2][20], spendingKey,
 *          outputAmounts[2], outputBlindings[2], outputOwnerPubKeys[2], outputNullifiers[2]
 */

include "merkleTree.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/mimcsponge.circom";
include "circomlib/circuits/comparators.circom";

template ShieldedTransfer(levels, nInputs, nOutputs) {
    // === Public Inputs ===
    signal input root;                              // Current Merkle tree root
    signal input nullifierHashes[nInputs];          // Nullifier hashes (double-spend prevention)
    signal input outputCommitments[nOutputs];       // New note commitments
    signal input relayer;                           // Relayer address (anti-frontrunning)
    signal input fee;                               // Relayer fee (anti-frontrunning)

    // === Private Inputs: Input Notes ===
    signal input inputAmounts[nInputs];
    signal input inputBlindings[nInputs];
    signal input inputNullifiers[nInputs];
    signal input inputOwnerPubKeys[nInputs];        // Derived from spendingKey via MiMC
    signal input inputPathElements[nInputs][levels];
    signal input inputPathIndices[nInputs][levels];
    signal input spendingKey;                       // Proves ownership of input notes

    // === Private Inputs: Output Notes ===
    signal input outputAmounts[nOutputs];
    signal input outputBlindings[nOutputs];
    signal input outputOwnerPubKeys[nOutputs];
    signal input outputNullifiers[nOutputs];

    // === 1. Verify each input note ===
    component inputCommitHashers[nInputs];
    component inputNullifierHashers[nInputs];
    component inputTreeCheckers[nInputs];
    component ownerCheck[nInputs];
    component inputAmountIsZero[nInputs];
    signal ownerDiff[nInputs];

    for (var i = 0; i < nInputs; i++) {
        // Check if this input is a dummy (zero-amount)
        inputAmountIsZero[i] = IsZero();
        inputAmountIsZero[i].in <== inputAmounts[i];
        // inputAmountIsZero[i].out = 1 if dummy, 0 if real

        // Compute commitment = MiMC(amount, ownerPubKey, blinding, nullifier)
        inputCommitHashers[i] = MiMCSponge(4, 220, 1);
        inputCommitHashers[i].ins[0] <== inputAmounts[i];
        inputCommitHashers[i].ins[1] <== inputOwnerPubKeys[i];
        inputCommitHashers[i].ins[2] <== inputBlindings[i];
        inputCommitHashers[i].ins[3] <== inputNullifiers[i];
        inputCommitHashers[i].k <== 0;

        // Verify Merkle membership (only for real inputs, skip for dummies)
        inputTreeCheckers[i] = MerkleTreeChecker(levels);
        inputTreeCheckers[i].leaf <== inputCommitHashers[i].outs[0];
        inputTreeCheckers[i].root <== root;
        for (var j = 0; j < levels; j++) {
            inputTreeCheckers[i].pathElements[j] <== inputPathElements[i][j];
            inputTreeCheckers[i].pathIndices[j] <== inputPathIndices[i][j];
        }
        // Conditional Merkle check: (1 - isDummy) * (computedRoot - root) === 0
        // MerkleTreeChecker outputs root via tree computation; we verify it matches
        // For dummies: skip by allowing any path. The check below constrains real inputs only.
        // Since MerkleTreeChecker constrains leaf+path→root internally, we need a different approach:
        // Use the tree checker output and conditionally enforce it equals the public root.
        // Actually, MerkleTreeChecker already has `root === computed` as a hard constraint.
        // For dummy notes, we need to provide a valid path for a leaf that IS in the tree.
        // The standard approach: dummy inputs use nullifierHash = 0 (public), and the contract
        // checks nullifierHash != 0 before recording. So dummies must still have valid Merkle proofs
        // but their nullifiers are never recorded on-chain.
        //
        // ALTERNATIVE: We accept that dummy inputs must point to a real tree leaf.
        // Since the pool always has at least one leaf (the genesis zero leaf), dummies can use that.
        // The amount=0 means no value is consumed even though the Merkle proof is valid.

        // Verify nullifier hash = MiMC(nullifier, spendingKey)
        inputNullifierHashers[i] = MiMCSponge(2, 220, 1);
        inputNullifierHashers[i].ins[0] <== inputNullifiers[i];
        inputNullifierHashers[i].ins[1] <== spendingKey;
        inputNullifierHashers[i].k <== 0;
        inputNullifierHashers[i].outs[0] === nullifierHashes[i];

        // Verify ownership: ownerPubKey = MiMC(spendingKey)
        // Conditional: only enforced for real inputs (non-zero amount).
        // For dummies, the ownership check is skipped so the prover doesn't need
        // a zero-amount leaf with their exact ownerPubKey in the tree.
        ownerCheck[i] = MiMCSponge(1, 220, 1);
        ownerCheck[i].ins[0] <== spendingKey;
        ownerCheck[i].k <== 0;
        // (1 - isDummy) * (computed - actual) === 0
        // Real: computed === actual. Dummy: unconstrained.
        ownerDiff[i] <== ownerCheck[i].outs[0] - inputOwnerPubKeys[i];
        (1 - inputAmountIsZero[i].out) * ownerDiff[i] === 0;
    }

    // === 2. Verify each output note commitment ===
    component outputCommitHashers[nOutputs];

    for (var i = 0; i < nOutputs; i++) {
        outputCommitHashers[i] = MiMCSponge(4, 220, 1);
        outputCommitHashers[i].ins[0] <== outputAmounts[i];
        outputCommitHashers[i].ins[1] <== outputOwnerPubKeys[i];
        outputCommitHashers[i].ins[2] <== outputBlindings[i];
        outputCommitHashers[i].ins[3] <== outputNullifiers[i];
        outputCommitHashers[i].k <== 0;

        // Verify commitment matches public output
        outputCommitHashers[i].outs[0] === outputCommitments[i];
    }

    // === 2b. Duplicate nullifier check ===
    // Only enforce when both inputs are real (non-zero amount).
    // If either input is a dummy (amount=0), its nullifierHash is deterministic
    // (MiMC(0, spendingKey)) and the contract will check it's not already spent.
    // For 2-input case: if both real, nullifierHashes must differ.
    signal bothReal;
    bothReal <== (1 - inputAmountIsZero[0].out) * (1 - inputAmountIsZero[1].out);

    signal nullifierDiff;
    nullifierDiff <== nullifierHashes[0] - nullifierHashes[1];
    // bothReal * nullifierDiff must be non-zero when both are real
    // i.e., if bothReal=1 then nullifierDiff != 0
    signal conditionalDiff;
    conditionalDiff <== bothReal * nullifierDiff;
    // When bothReal=1: conditionalDiff = nullifierDiff, and we need it non-zero
    // When bothReal=0: conditionalDiff = 0, constraint is trivially satisfied
    signal conditionalDiffInv;
    conditionalDiffInv <-- bothReal == 1 ? 1 / nullifierDiff : 0;
    // Constraint: bothReal * (conditionalDiff * conditionalDiffInv - 1) === 0
    // When bothReal=1: nullifierDiff * inv - 1 === 0 → nullifierDiff != 0
    // When bothReal=0: 0 === 0 ✓
    signal diffCheck;
    diffCheck <== conditionalDiff * conditionalDiffInv;
    bothReal * (diffCheck - 1) === 0;

    // === 2c. Duplicate output commitment check ===
    signal outputDiff;
    outputDiff <== outputCommitments[0] - outputCommitments[1];
    signal outputDiffInv;
    outputDiffInv <-- 1 / outputDiff;
    outputDiff * outputDiffInv === 1;

    // === 3. Conservation: sum(inputs) == sum(outputs) + fee ===
    var inputSum = 0;
    for (var i = 0; i < nInputs; i++) {
        inputSum += inputAmounts[i];
    }

    var outputSum = 0;
    for (var i = 0; i < nOutputs; i++) {
        outputSum += outputAmounts[i];
    }

    signal totalInput;
    signal totalOutput;
    totalInput <== inputSum;
    totalOutput <== outputSum + fee;
    totalInput === totalOutput;

    // === 4. Range proofs: all amounts in [0, 2^64) ===
    component inputBits[nInputs];
    for (var i = 0; i < nInputs; i++) {
        inputBits[i] = Num2Bits(64);
        inputBits[i].in <== inputAmounts[i];
    }

    component outputBits[nOutputs];
    for (var i = 0; i < nOutputs; i++) {
        outputBits[i] = Num2Bits(64);
        outputBits[i].in <== outputAmounts[i];
    }

    // Fee range proof
    component feeBits = Num2Bits(64);
    feeBits.in <== fee;

    // === 5. Anti-frontrunning: bind relayer into proof ===
    // Squaring forces the public input into at least one R1CS constraint,
    // preventing the compiler from optimizing it away.
    signal relayerSquare;
    relayerSquare <== relayer * relayer;
}

// 2-in, 2-out with depth 20 Merkle tree
component main {public [root, nullifierHashes, outputCommitments, relayer, fee]} = ShieldedTransfer(20, 2, 2);
