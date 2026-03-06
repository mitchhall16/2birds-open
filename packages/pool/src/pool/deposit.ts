/**
 * @2birds/pool — Deposit into privacy pool
 *
 * Creates a commitment from a random (secret, nullifier) pair,
 * submits it to the pool contract with the deposit payment.
 */

import algosdk from 'algosdk';
import {
  type Scalar,
  type DepositNote,
  type PoolConfig,
  type NetworkConfig,
  randomScalar,
  mimcHash,
  mimcHashSingle,
  initMimc,
  scalarToBytes,
  createAlgodClient,
  serializeNote,
} from '@2birds/core';

/**
 * Create a new deposit commitment.
 * Returns the note (MUST be saved securely — losing it means losing funds).
 */
export async function createDeposit(denomination: bigint, assetId: number = 0): Promise<DepositNote> {
  await initMimc();
  const secret = randomScalar();
  const nullifier = randomScalar();
  const commitment = mimcHash(secret, nullifier);

  return {
    secret,
    nullifier,
    commitment,
    leafIndex: -1, // Set after deposit is confirmed
    denomination,
    assetId,
    timestamp: Date.now(),
  };
}

/**
 * Submit a deposit to the privacy pool contract.
 *
 * Creates an atomic group:
 * 1. Payment/ASA transfer of `denomination` to the pool contract
 * 2. App call to `deposit(commitment)`
 *
 * @returns The confirmed deposit note with leaf index
 */
export async function submitDeposit(
  note: DepositNote,
  pool: PoolConfig,
  sender: algosdk.Account,
  network: NetworkConfig,
): Promise<DepositNote> {
  const algod = createAlgodClient(network);
  const params = await algod.getTransactionParams().do();
  const commitmentBytes = scalarToBytes(note.commitment);

  // Transaction 1: Payment to pool
  let payTxn: algosdk.Transaction;
  if (pool.assetId === 0) {
    payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: sender.addr,
      receiver: algosdk.getApplicationAddress(Number(pool.appId)),
      amount: Number(note.denomination),
      suggestedParams: params,
    });
  } else {
    payTxn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      sender: sender.addr,
      receiver: algosdk.getApplicationAddress(Number(pool.appId)),
      amount: Number(note.denomination),
      assetIndex: pool.assetId,
      suggestedParams: params,
    });
  }

  // Transaction 2: App call to deposit
  const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: sender.addr,
    appIndex: Number(pool.appId),
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      new TextEncoder().encode('deposit'),
      commitmentBytes,
    ],
    boxes: [
      // Tree frontier boxes that may be updated
      ...Array.from({ length: pool.merkleDepth }, (_, i) => ({
        appIndex: Number(pool.appId),
        name: new Uint8Array([...new TextEncoder().encode('tree:'), ...numberToBytes8(i)]),
      })),
    ],
    suggestedParams: params,
  });

  // Group and sign
  const grouped = algosdk.assignGroupID([payTxn, appCallTxn]);
  const signedPay = grouped[0].signTxn(sender.sk);
  const signedApp = grouped[1].signTxn(sender.sk);

  const resp = await algod.sendRawTransaction([signedPay, signedApp]).do();
  const txId = (resp as any).txid ?? (resp as any).txId;
  const result = await algosdk.waitForConfirmation(algod, txId, 4);

  // Extract leaf index from logs
  // The contract logs: "deposit" + commitment + itob(leafIndex)
  const logs = result.logs || [];
  let leafIndex = 0;
  if (logs.length > 0) {
    const lastLog = logs[logs.length - 1];
    // Last 8 bytes are the leaf index
    if (lastLog.length >= 8) {
      const indexBytes = lastLog.slice(lastLog.length - 8);
      leafIndex = Number(bytesToBigint(indexBytes));
    }
  }

  return {
    ...note,
    leafIndex,
  };
}

/** Encode the deposit note for safe storage (e.g., local file, encrypted storage) */
export function encodeDepositNote(note: DepositNote): string {
  return serializeNote(note);
}

/** Convert a number to 8-byte big-endian Uint8Array */
function numberToBytes8(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  let val = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return buf;
}

/** Convert bytes to bigint */
function bytesToBigint(buf: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < buf.length; i++) {
    result = (result << 8n) | BigInt(buf[i]);
  }
  return result;
}
