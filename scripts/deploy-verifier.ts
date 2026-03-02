#!/usr/bin/env npx tsx
/**
 * Deploy the budget helper + Groth16 ZK verifier as Applications on Algorand testnet.
 *
 * The budget helper is a tiny app (just approves) that the verifier calls via
 * inner transactions to pool opcode budget. AVM doesn't allow self-calls.
 *
 * Usage:
 *   DEPLOYER_MNEMONIC="..." npx tsx scripts/deploy-verifier.ts
 */

import algosdk from 'algosdk';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ALGOD_URL = process.env.ALGOD_URL || 'https://testnet-api.algonode.cloud';
const ALGOD_TOKEN = process.env.ALGOD_TOKEN || '';

async function deployApp(
  algod: algosdk.Algodv2,
  deployer: algosdk.Account,
  approvalTeal: string,
  clearTeal: string,
  label: string,
): Promise<{ appId: number; appAddress: string; txId: string }> {
  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  console.log(`  ${label} approval: ${approvalBytes.length} bytes`);

  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));

  const params = await algod.getTransactionParams().do();

  const txn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram: approvalBytes,
    clearProgram: clearBytes,
    numGlobalInts: 0,
    numGlobalByteSlices: 0,
    numLocalInts: 0,
    numLocalByteSlices: 0,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  const signed = txn.signTxn(deployer.sk);
  const resp = await algod.sendRawTransaction(signed).do();
  const txId = (resp as any).txid ?? (resp as any).txId;

  const result = await algosdk.waitForConfirmation(algod, txId, 4);
  const appId = Number((result as any).applicationIndex);
  const appAddress = String(algosdk.getApplicationAddress(appId));

  return { appId, appAddress, txId };
}

async function main() {
  const algod = new algosdk.Algodv2(ALGOD_TOKEN, ALGOD_URL);

  if (!process.env.DEPLOYER_MNEMONIC) {
    console.error('Set DEPLOYER_MNEMONIC environment variable');
    process.exit(1);
  }

  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
  console.log(`Deployer: ${deployer.addr}`);

  // --- Deploy budget helper app ---
  console.log('\nDeploying budget helper app...');
  const helperTeal = fs.readFileSync(
    path.resolve(__dirname, '../contracts/budget_helper.teal'), 'utf-8',
  );
  const clearTeal = fs.readFileSync(
    path.resolve(__dirname, '../contracts/withdraw_verifier_clear.teal'), 'utf-8',
  );
  const helper = await deployApp(algod, deployer, helperTeal, clearTeal, 'Budget helper');
  console.log(`  App ID:      ${helper.appId}`);
  console.log(`  Tx ID:       ${helper.txId}`);

  // --- Deploy verifier app ---
  console.log('\nDeploying verifier app...');
  const verifierTeal = fs.readFileSync(
    path.resolve(__dirname, '../contracts/withdraw_verifier.teal'), 'utf-8',
  );
  const verifier = await deployApp(algod, deployer, verifierTeal, clearTeal, 'Verifier');
  console.log(`  App ID:      ${verifier.appId}`);
  console.log(`  App Address: ${verifier.appAddress}`);
  console.log(`  Tx ID:       ${verifier.txId}`);

  // --- Update deployment-testnet.json ---
  const deployPath = path.resolve(__dirname, '../deployment-testnet.json');
  const deployment = JSON.parse(fs.readFileSync(deployPath, 'utf-8'));
  deployment.contracts.BudgetHelper = {
    appId: helper.appId,
    appAddress: helper.appAddress,
    txId: helper.txId,
    note: 'Tiny app that just approves — called by verifier for opcode budget padding',
  };
  deployment.contracts.ZkVerifier = {
    appId: verifier.appId,
    appAddress: verifier.appAddress,
    txId: verifier.txId,
    budgetHelperAppId: helper.appId,
    note: 'Groth16 ZK verifier app — calls BudgetHelper via inner txns for opcode budget',
  };
  fs.writeFileSync(deployPath, JSON.stringify(deployment, null, 2));
  console.log(`\nUpdated deployment-testnet.json`);

  // --- Update frontend config ---
  const configPath = path.resolve(__dirname, '../frontend/src/lib/config.ts');
  let config = fs.readFileSync(configPath, 'utf-8');
  config = config.replace(
    /ZkVerifier: \{[^}]+\}/,
    `ZkVerifier: {\n    appId: ${verifier.appId},\n    budgetHelperAppId: ${helper.appId},\n  }`,
  );
  fs.writeFileSync(configPath, config);
  console.log(`Updated frontend config: verifier=${verifier.appId}, helper=${helper.appId}`);
}

main().catch(err => {
  console.error('Deploy failed:', err);
  process.exit(1);
});
