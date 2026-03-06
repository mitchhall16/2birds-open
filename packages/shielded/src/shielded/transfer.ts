/**
 * @2birds/shielded — Shielded Transfer
 *
 * Full privacy transfers: sender privacy + receiver privacy + hidden amounts.
 * Uses the UTXO model — consume old notes, create new notes, prove validity with ZK.
 */

import algosdk from 'algosdk';
import {
  type ShieldedNote,
  type ShieldedTransfer,
  type Scalar,
  type BN254Point,
  type NetworkConfig,
  scalarToBytes,
  createAlgodClient,
} from '@2birds/core';
import { IncrementalMerkleTree } from '@2birds/pool';
import { computeNoteCommitment, computeNullifierHash, createTransferOutputs } from './note.js';

let snarkjs: any;
async function loadSnarkjs() {
  if (!snarkjs) snarkjs = await import('snarkjs');
  return snarkjs;
}

/** Shielded pool configuration */
export interface ShieldedPoolConfig {
  appId: bigint;
  assetId: number;
  network: NetworkConfig;
  verifierLsig: Uint8Array;
}

/**
 * Execute a shielded transfer (2-in, 2-out).
 *
 * @param inputNotes - Notes to consume (max 2)
 * @param transferAmount - Amount to send to recipient
 * @param recipientPubKey - Recipient's BN254 public key
 * @param senderPubKey - Sender's public key (for change)
 * @param spendingKey - Sender's spending private key
 * @param tree - Current Merkle tree state
 * @param config - Pool configuration
 * @param wasmPath - Path to shielded transfer circuit WASM
 * @param zkeyPath - Path to proving key
 */
export async function shieldedTransfer(
  inputNotes: ShieldedNote[],
  transferAmount: bigint,
  recipientPubKey: BN254Point,
  senderPubKey: BN254Point,
  spendingKey: Scalar,
  tree: IncrementalMerkleTree,
  config: ShieldedPoolConfig,
  wasmPath: string,
  zkeyPath: string,
): Promise<ShieldedTransfer> {
  const snarks = await loadSnarkjs();

  if (inputNotes.length > 2) throw new Error('Max 2 input notes');

  // Pad to exactly 2 inputs (use zero-value dummy notes if needed)
  const paddedInputs = [...inputNotes];
  while (paddedInputs.length < 2) {
    paddedInputs.push({
      amount: 0n,
      ownerPubKey: senderPubKey,
      blinding: 0n,
      nullifier: 0n,
      commitment: computeNoteCommitment(0n, senderPubKey.x, 0n, 0n),
      index: 0,
      assetId: config.assetId,
      spent: false,
    });
  }

  // Compute total input
  const totalInput = paddedInputs.reduce((sum, n) => sum + n.amount, 0n);
  if (transferAmount > totalInput) throw new Error('Insufficient funds');

  // Create output notes
  const { recipientNote, changeNote } = createTransferOutputs(
    transferAmount,
    totalInput,
    recipientPubKey,
    senderPubKey,
    config.assetId,
  );
  const outputNotes = [recipientNote, changeNote];

  // Compute nullifier hashes
  const nullifierHashes = paddedInputs.map(n => computeNullifierHash(n.nullifier, spendingKey));

  // Get Merkle paths for input notes
  const paths = paddedInputs.map(n => tree.getPath(n.index));

  // Build circuit inputs
  const circuitInput = {
    root: tree.root.toString(),
    nullifierHashes: nullifierHashes.map(h => h.toString()),
    outputCommitments: outputNotes.map(n => n.commitment.toString()),

    inputAmounts: paddedInputs.map(n => n.amount.toString()),
    inputBlindings: paddedInputs.map(n => n.blinding.toString()),
    inputNullifiers: paddedInputs.map(n => n.nullifier.toString()),
    inputOwnerPubKeys: paddedInputs.map(n => n.ownerPubKey.x.toString()),
    inputPathElements: paths.map(p => p.pathElements.map((e: bigint) => e.toString())),
    inputPathIndices: paths.map(p => p.pathIndices),
    spendingKey: spendingKey.toString(),

    outputAmounts: outputNotes.map(n => n.amount.toString()),
    outputBlindings: outputNotes.map(n => n.blinding.toString()),
    outputOwnerPubKeys: outputNotes.map(n => n.ownerPubKey.x.toString()),
    outputNullifiers: outputNotes.map(n => n.nullifier.toString()),
  };

  // Generate ZK proof
  const { proof, publicSignals } = await snarks.groth16.fullProve(
    circuitInput,
    wasmPath,
    zkeyPath,
  );

  return {
    inputNotes: paddedInputs,
    outputNotes,
    proof: {
      pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
      pi_b: [
        [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
        [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
      ],
      pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
    },
    publicInputs: {
      oldRoot: tree.root,
      newRoot: 0n, // Computed after inserting output notes
      nullifierHashes,
      outputCommitments: outputNotes.map(n => n.commitment),
    },
  };
}

/**
 * Submit a shielded transfer to the on-chain pool.
 */
export async function submitShieldedTransfer(
  transfer: ShieldedTransfer,
  config: ShieldedPoolConfig,
  sender: algosdk.Account,
): Promise<string> {
  const algod = createAlgodClient(config.network);
  const params = await algod.getTransactionParams().do();

  // LogicSig verifier transaction
  const proofBytes = encodeTransferProof(transfer);
  const verifierLsig = new algosdk.LogicSigAccount(config.verifierLsig, [proofBytes]);

  const verifierTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: verifierLsig.address(),
    receiver: verifierLsig.address(),
    amount: 0,
    suggestedParams: { ...params, fee: 10 * 1000, flatFee: true },
  });

  // App call — transfer
  const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: sender.addr,
    appIndex: Number(config.appId),
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      new TextEncoder().encode('transfer'),
      // Nullifier hashes
      ...transfer.publicInputs.nullifierHashes.map(h => scalarToBytes(h)),
      // Output commitments
      ...transfer.publicInputs.outputCommitments.map(c => scalarToBytes(c)),
      // Root used in proof
      scalarToBytes(transfer.publicInputs.oldRoot),
    ],
    boxes: [
      // Nullifier boxes
      ...transfer.publicInputs.nullifierHashes.map(h => ({
        appIndex: Number(config.appId),
        name: new Uint8Array([...new TextEncoder().encode('null:'), ...scalarToBytes(h)]),
      })),
      // Tree frontier boxes
      ...Array.from({ length: 5 }, (_, i) => ({
        appIndex: Number(config.appId),
        name: new Uint8Array([...new TextEncoder().encode('tree:'), ...numberToBytes8(i)]),
      })),
    ],
    suggestedParams: params,
  });

  const grouped = algosdk.assignGroupID([verifierTxn, appCallTxn]);
  const signedVerifier = algosdk.signLogicSigTransactionObject(grouped[0], verifierLsig);
  const signedApp = grouped[1].signTxn(sender.sk);

  const resp = await algod.sendRawTransaction([signedVerifier.blob, signedApp]).do();
  const txId = (resp as any).txid ?? (resp as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);
  return txId;
}

function encodeTransferProof(transfer: ShieldedTransfer): Uint8Array {
  const parts = [
    scalarToBytes(transfer.proof.pi_a[0]),
    scalarToBytes(transfer.proof.pi_a[1]),
    scalarToBytes(transfer.proof.pi_b[0][0]),
    scalarToBytes(transfer.proof.pi_b[0][1]),
    scalarToBytes(transfer.proof.pi_b[1][0]),
    scalarToBytes(transfer.proof.pi_b[1][1]),
    scalarToBytes(transfer.proof.pi_c[0]),
    scalarToBytes(transfer.proof.pi_c[1]),
  ];
  const total = parts.reduce((s, p) => s + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function numberToBytes8(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  let val = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return buf;
}
