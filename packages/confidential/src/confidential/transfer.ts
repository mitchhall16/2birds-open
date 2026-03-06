/**
 * @2birds/confidential — Confidential Transfer Flow
 *
 * Orchestrates shielding (deposit), confidential transfers, and unshielding (withdrawal)
 * with hidden amounts using Pedersen commitments and range proofs.
 */

import algosdk from 'algosdk';
import {
  type BN254Point,
  type Scalar,
  type PedersenCommitment,
  type NetworkConfig,
  mimcHash,
  scalarToBytes,
  createAlgodClient,
  encodePoint,
} from '@2birds/core';
import { commit, subtractCommitments, verifyBalance, encodeCommitment } from './pedersen.js';

// snarkjs loaded dynamically
let snarkjs: any;
async function loadSnarkjs() {
  if (!snarkjs) snarkjs = await import('snarkjs');
  return snarkjs;
}

/** Contract configuration for confidential assets */
export interface ConfidentialAssetConfig {
  appId: bigint;
  assetId: number; // 0 = ALGO
  network: NetworkConfig;
}

/**
 * Shield (deposit) — convert public balance to a Pedersen commitment.
 *
 * @param amount - Amount to shield
 * @param config - Contract configuration
 * @param sender - Sender's account
 * @returns The commitment (with secret blinding factor — SAVE THIS)
 */
export async function shield(
  amount: bigint,
  config: ConfidentialAssetConfig,
  sender: algosdk.Account,
): Promise<PedersenCommitment> {
  const algod = createAlgodClient(config.network);
  const params = await algod.getTransactionParams().do();

  // Create Pedersen commitment
  const pc = commit(amount);
  const commitmentBytes = encodeCommitment(pc);

  // Payment transaction
  let payTxn: algosdk.Transaction;
  const appAddr = algosdk.getApplicationAddress(Number(config.appId));

  if (config.assetId === 0) {
    payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: sender.addr,
      receiver: appAddr,
      amount: Number(amount),
      suggestedParams: params,
    });
  } else {
    payTxn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: sender.addr,
      receiver: appAddr,
      amount: Number(amount),
      assetIndex: config.assetId,
      suggestedParams: params,
    });
  }

  // App call to shield
  const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: sender.addr,
    appIndex: Number(config.appId),
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      new TextEncoder().encode('shield'),
      commitmentBytes,
      algosdk.encodeUint64(Number(amount)),
    ],
    boxes: [
      {
        appIndex: Number(config.appId),
        name: new Uint8Array([...new TextEncoder().encode('bal:'), ...algosdk.decodeAddress(String(sender.addr)).publicKey]),
      },
    ],
    suggestedParams: params,
  });

  const grouped = algosdk.assignGroupID([payTxn, appCallTxn]);
  const signedPay = grouped[0].signTxn(sender.sk);
  const signedApp = grouped[1].signTxn(sender.sk);

  const resp1 = await algod.sendRawTransaction([signedPay, signedApp]).do();
  const txId = (resp1 as any).txid ?? (resp1 as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);

  return pc;
}

/**
 * Confidential transfer — transfer between shielded balances with hidden amount.
 *
 * Requires a range proof (ZK proof that both resulting balances are non-negative).
 *
 * @param transferAmount - Amount to transfer (known to sender, hidden on-chain)
 * @param senderCommitment - Sender's current balance commitment (with known opening)
 * @param recipient - Recipient's Algorand address
 * @param config - Contract configuration
 * @param sender - Sender's account
 * @param wasmPath - Path to range proof circuit WASM
 * @param zkeyPath - Path to range proof proving key
 */
export async function confidentialTransfer(
  transferAmount: bigint,
  senderCommitment: PedersenCommitment,
  recipient: string,
  config: ConfidentialAssetConfig,
  sender: algosdk.Account,
  wasmPath: string,
  zkeyPath: string,
): Promise<{
  senderNewCommitment: PedersenCommitment;
  transferCommitment: PedersenCommitment;
}> {
  const snarks = await loadSnarkjs();
  const algod = createAlgodClient(config.network);
  const params = await algod.getTransactionParams().do();

  // Compute new commitments
  const newSenderAmount = senderCommitment.amount - transferAmount;
  if (newSenderAmount < 0n) throw new Error('Insufficient shielded balance');

  const transferPC = commit(transferAmount);
  const senderNewPC = subtractCommitments(senderCommitment, transferPC);

  // Generate range proof for the transfer
  const inputCommitmentHash = mimcHash(senderCommitment.amount, senderCommitment.blinding);
  const outputCommitmentHash = mimcHash(senderNewPC.amount, senderNewPC.blinding);
  const feeCommitmentHash = mimcHash(transferAmount, transferPC.blinding);

  const proofInput = {
    inputAmount: senderCommitment.amount.toString(),
    inputBlinding: senderCommitment.blinding.toString(),
    outputAmount: senderNewPC.amount.toString(),
    outputBlinding: senderNewPC.blinding.toString(),
    feeAmount: transferAmount.toString(),
    inputCommitmentHash: inputCommitmentHash.toString(),
    outputCommitmentHash: outputCommitmentHash.toString(),
    feeCommitmentHash: feeCommitmentHash.toString(),
  };

  const { proof } = await snarks.groth16.fullProve(proofInput, wasmPath, zkeyPath);

  // Build LogicSig verifier transaction (ZK proof)
  // In production, this would use an AlgoPlonk-generated LogicSig
  const proofBytes = encodeProof(proof);

  // App call for confidential transfer
  const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: sender.addr,
    appIndex: Number(config.appId),
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      new TextEncoder().encode('confidentialTransfer'),
      algosdk.decodeAddress(recipient).publicKey,
      encodeCommitment(senderNewPC),
      // recipientNewCommitment would need to be computed knowing recipient's current balance
      new Uint8Array(64), // placeholder — recipient commitment update
      encodeCommitment(transferPC),
    ],
    boxes: [
      {
        appIndex: Number(config.appId),
        name: new Uint8Array([...new TextEncoder().encode('bal:'), ...algosdk.decodeAddress(String(sender.addr)).publicKey]),
      },
      {
        appIndex: Number(config.appId),
        name: new Uint8Array([...new TextEncoder().encode('bal:'), ...algosdk.decodeAddress(recipient).publicKey]),
      },
    ],
    suggestedParams: params,
  });

  const signedApp = appCallTxn.signTxn(sender.sk);
  const resp2 = await algod.sendRawTransaction(signedApp).do();
  const txId = (resp2 as any).txid ?? (resp2 as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);

  return {
    senderNewCommitment: senderNewPC,
    transferCommitment: transferPC,
  };
}

/**
 * Unshield (withdraw) — convert shielded balance back to public.
 *
 * @param amount - Amount to withdraw
 * @param currentCommitment - Current balance commitment
 * @param config - Contract configuration
 * @param sender - Sender's account
 */
export async function unshield(
  amount: bigint,
  currentCommitment: PedersenCommitment,
  config: ConfidentialAssetConfig,
  sender: algosdk.Account,
): Promise<PedersenCommitment> {
  const algod = createAlgodClient(config.network);
  const params = await algod.getTransactionParams().do();

  if (amount > currentCommitment.amount) {
    throw new Error('Insufficient shielded balance');
  }

  // Compute new commitment after withdrawal
  const withdrawPC = commit(amount, 0n); // Zero blinding for public withdrawal
  const newPC = subtractCommitments(currentCommitment, withdrawPC);

  const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: sender.addr,
    appIndex: Number(config.appId),
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      new TextEncoder().encode('unshield'),
      algosdk.encodeUint64(Number(amount)),
      encodeCommitment(newPC),
    ],
    boxes: [
      {
        appIndex: Number(config.appId),
        name: new Uint8Array([...new TextEncoder().encode('bal:'), ...algosdk.decodeAddress(String(sender.addr)).publicKey]),
      },
    ],
    suggestedParams: params,
  });

  const signedApp = appCallTxn.signTxn(sender.sk);
  const resp2 = await algod.sendRawTransaction(signedApp).do();
  const txId = (resp2 as any).txid ?? (resp2 as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);

  return newPC;
}

/** Encode a snarkjs proof as bytes */
function encodeProof(proof: any): Uint8Array {
  const parts = [
    ...proof.pi_a.slice(0, 2).map((n: string) => scalarToBytes(BigInt(n))),
    ...proof.pi_b.slice(0, 2).flatMap((row: string[]) => row.map((n: string) => scalarToBytes(BigInt(n)))),
    ...proof.pi_c.slice(0, 2).map((n: string) => scalarToBytes(BigInt(n))),
  ];
  const total = parts.reduce((s: number, p: Uint8Array) => s + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}
