#!/usr/bin/env npx tsx
/**
 * Deploy updated PrivacyPool contract (variable amounts) to Algorand testnet.
 *
 * Usage:
 *   DEPLOYER_MNEMONIC="your 25 words here" npx tsx scripts/deploy-pool-v2.ts
 */

import algosdk from 'algosdk';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ALGOD_URL = process.env.ALGOD_URL || 'https://testnet-api.algonode.cloud';
const ALGOD_TOKEN = process.env.ALGOD_TOKEN || '';
const ARTIFACTS_DIR = path.resolve(__dirname, '../contracts/artifacts');

function methodSelector(signature: string): Uint8Array {
  const hash = crypto.createHash('sha512-256').update(signature).digest();
  return new Uint8Array(hash.slice(0, 4));
}

function abiUint64(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(n));
  return buf;
}

async function main() {
  const algod = new algosdk.Algodv2(ALGOD_TOKEN, ALGOD_URL);

  if (!process.env.DEPLOYER_MNEMONIC) {
    console.error('Set DEPLOYER_MNEMONIC env variable to deploy.');
    process.exit(1);
  }

  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
  console.log(`Deployer: ${deployer.addr}`);

  const accountInfo = await algod.accountInformation(deployer.addr).do();
  console.log(`Balance: ${(Number(accountInfo.amount) / 1_000_000).toFixed(6)} ALGO`);

  // Read compiled TEAL
  const approvalTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal'), 'utf-8');
  const clearTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal'), 'utf-8');

  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();

  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));

  // Read schema from ARC-56
  const arc56 = JSON.parse(fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.arc56.json'), 'utf-8'));
  const globalInts = arc56.state?.schema?.global?.ints ?? 4;
  const globalBytes = arc56.state?.schema?.global?.bytes ?? 1;

  const params = await algod.getTransactionParams().do();

  // Create application with denomination=1_000_000 (1 ALGO max) and assetId=0 (ALGO)
  const createTxn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram: approvalBytes,
    clearProgram: clearBytes,
    numGlobalInts: globalInts,
    numGlobalByteSlices: globalBytes,
    numLocalInts: 0,
    numLocalByteSlices: 0,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      methodSelector('createApplication(uint64,uint64)void'),
      abiUint64(1_000_000), // denomination (used as reference, not enforced)
      abiUint64(0),          // ALGO
    ],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  console.log('\nDeploying PrivacyPool v2...');
  const signed = createTxn.signTxn(deployer.sk);
  const resp = await algod.sendRawTransaction(signed).do();
  const txId = (resp as any).txid ?? (resp as any).txId;
  const result = await algosdk.waitForConfirmation(algod, txId, 4);
  const appId = Number((result as any).applicationIndex);
  const appAddress = String(algosdk.getApplicationAddress(appId));

  console.log(`  App ID:      ${appId}`);
  console.log(`  App Address: ${appAddress}`);
  console.log(`  Tx ID:       ${txId}`);

  // Fund the app account with 1 ALGO for MBR + withdrawals
  console.log('\nFunding app account with 2 ALGO...');
  const fundParams = await algod.getTransactionParams().do();
  const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployer.addr,
    receiver: appAddress,
    amount: 2_000_000,
    suggestedParams: fundParams,
  });
  const signedFund = fundTxn.signTxn(deployer.sk);
  const fundResp = await algod.sendRawTransaction(signedFund).do();
  const fundTxId = (fundResp as any).txid ?? (fundResp as any).txId;
  await algosdk.waitForConfirmation(algod, fundTxId, 4);
  console.log(`  Funded: ${fundTxId}`);

  // Output config snippet
  console.log(`\n--- Update frontend/src/lib/config.ts ---`);
  console.log(`PrivacyPool: {`);
  console.log(`  appId: ${appId},`);
  console.log(`  appAddress: '${appAddress}',`);
  console.log(`},`);
}

main().catch(err => {
  console.error('Deploy failed:', err);
  process.exit(1);
});
