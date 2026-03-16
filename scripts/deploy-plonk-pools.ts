#!/usr/bin/env npx tsx
/**
 * Deploy new pool contracts with PLONK support and configure verifiers.
 *
 * Creates 3 pool apps (0.1, 0.5, 1.0 ALGO), then calls setPlonkVerifiers on each.
 */

import algosdk from 'algosdk';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ALGOD_URL = process.env.ALGOD_URL || 'https://testnet-api.algonode.cloud';
const ALGOD_TOKEN = process.env.ALGOD_TOKEN || '';
const ARTIFACTS_DIR = path.resolve(__dirname, '../contracts/artifacts');
const CIRCUITS_DIR = path.resolve(__dirname, '../frontend/public/circuits');

// Existing verifier app IDs (these stay the same)
const VERIFIER_APP_ID = 756420114;       // withdraw verifier
const DEPOSIT_VERIFIER_APP_ID = 756420115; // deposit verifier
const PRIVATESEND_VERIFIER_APP_ID = 756420116; // privateSend verifier

const DENOMINATIONS = [
  // { label: '0.1 ALGO', microAlgos: 100_000 },  // Already deployed: 756813724
  { label: '0.5 ALGO', microAlgos: 500_000 },
  { label: '1.0 ALGO', microAlgos: 1_000_000 },
];

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
    console.error('DEPLOYER_MNEMONIC not set');
    process.exit(1);
  }

  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
  const deployerAddr = deployer.addr.toString();
  console.log(`Deployer: ${deployerAddr}`);

  const accountInfo = await algod.accountInformation(deployerAddr).do();
  console.log(`Balance: ${(Number(accountInfo.amount) / 1e6).toFixed(6)} ALGO`);

  // Compile contract
  const approvalTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal'), 'utf-8');
  const clearTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal'), 'utf-8');

  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));
  console.log(`Approval: ${approvalBytes.length} bytes, Clear: ${clearBytes.length} bytes`);

  // Get schema from ARC-56
  const arc56 = JSON.parse(fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.arc56.json'), 'utf-8'));
  const globalInts = arc56.state?.schema?.global?.ints ?? 8;
  const globalBytes = arc56.state?.schema?.global?.bytes ?? 8;

  // Compile PLONK verifier TEAL programs
  const circuits = ['withdraw', 'deposit', 'privateSend'];
  const plonkAddresses: Record<string, string> = {};

  for (const circuit of circuits) {
    const tealPath = path.join(CIRCUITS_DIR, `${circuit}_plonk_verifier.teal`);
    const tealSource = fs.readFileSync(tealPath, 'utf-8');
    const compiled = await algod.compile(Buffer.from(tealSource)).do();
    const program = new Uint8Array(Buffer.from(compiled.result, 'base64'));
    const lsig = new algosdk.LogicSigAccount(program);
    plonkAddresses[circuit] = String(lsig.address());
    console.log(`${circuit} PLONK verifier: ${plonkAddresses[circuit]}`);
  }

  // Deploy pool contracts
  const createSelector = methodSelector('createApplication(uint64,uint64,uint64,uint64,uint64)void');
  const setPlonkSelector = methodSelector('setPlonkVerifiers(address,address,address)void');

  const results: { label: string; appId: number; appAddress: string }[] = [];

  for (const denom of DENOMINATIONS) {
    console.log(`\nDeploying pool ${denom.label}...`);
    const params = await algod.getTransactionParams().do();

    const txn = algosdk.makeApplicationCreateTxnFromObject({
      sender: deployerAddr,
      approvalProgram: approvalBytes,
      clearProgram: clearBytes,
      numGlobalInts: globalInts,
      numGlobalByteSlices: globalBytes,
      numLocalInts: 0,
      numLocalByteSlices: 0,
      extraPages: 1,
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        createSelector,
        abiUint64(denom.microAlgos),
        abiUint64(0), // ALGO (not ASA)
        abiUint64(VERIFIER_APP_ID),
        abiUint64(DEPOSIT_VERIFIER_APP_ID),
        abiUint64(PRIVATESEND_VERIFIER_APP_ID),
      ],
      suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
    });

    const signed = txn.signTxn(deployer.sk);
    const resp = await algod.sendRawTransaction(signed).do();
    const txId = (resp as any).txid ?? (resp as any).txId;
    const result = await algosdk.waitForConfirmation(algod, txId, 4);
    const appId = Number((result as any).applicationIndex);
    const appAddress = String(algosdk.getApplicationAddress(appId));

    results.push({ label: denom.label, appId, appAddress });
    console.log(`  App ID: ${appId}`);
    console.log(`  Address: ${appAddress}`);

    // Fund the app address with min balance for boxes
    const fundParams = await algod.getTransactionParams().do();
    const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployerAddr,
      receiver: appAddress,
      amount: 1_000_000, // 1 ALGO for box storage
      suggestedParams: { ...fundParams, fee: BigInt(1000), flatFee: true },
    });
    const signedFund = fundTxn.signTxn(deployer.sk);
    const fundResp = await algod.sendRawTransaction(signedFund).do();
    const fundTxId = (fundResp as any).txid ?? (fundResp as any).txId;
    await algosdk.waitForConfirmation(algod, fundTxId, 4);
    console.log(`  Funded 1 ALGO for box storage`);

    // Set PLONK verifiers
    console.log('  Setting PLONK verifiers...');
    const params2 = await algod.getTransactionParams().do();

    const withdrawAddr = algosdk.decodeAddress(plonkAddresses.withdraw);
    const depositAddr = algosdk.decodeAddress(plonkAddresses.deposit);
    const privateSendAddr = algosdk.decodeAddress(plonkAddresses.privateSend);

    const setTxn = algosdk.makeApplicationCallTxnFromObject({
      sender: deployerAddr,
      appIndex: appId,
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [setPlonkSelector, withdrawAddr.publicKey, depositAddr.publicKey, privateSendAddr.publicKey],
      suggestedParams: { ...params2, fee: BigInt(2000), flatFee: true },
    });

    const signedSet = setTxn.signTxn(deployer.sk);
    const setResp = await algod.sendRawTransaction(signedSet).do();
    const setTxId = (setResp as any).txid ?? (setResp as any).txId;
    await algosdk.waitForConfirmation(algod, setTxId, 4);
    console.log(`  PLONK verifiers set`);
  }

  // Fund LogicSig addresses
  console.log('\nFunding LogicSig addresses...');
  for (const circuit of circuits) {
    const addr = plonkAddresses[circuit];
    try {
      const info = await algod.accountInformation(addr).do();
      if (Number(info.amount) >= 100_000) {
        console.log(`  ${circuit}: already funded (${Number(info.amount) / 1e6} ALGO)`);
        continue;
      }
    } catch {}

    const params = await algod.getTransactionParams().do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployerAddr,
      receiver: addr,
      amount: 100_000,
      suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
    });
    const signed = txn.signTxn(deployer.sk);
    const resp = await algod.sendRawTransaction(signed).do();
    const txId = (resp as any).txid ?? (resp as any).txId;
    await algosdk.waitForConfirmation(algod, txId, 4);
    console.log(`  ${circuit}: funded 0.1 ALGO`);
  }

  // Print config update
  console.log('\n\n========================================');
  console.log('UPDATE frontend/src/lib/config.ts:');
  console.log('========================================\n');
  console.log('export const POOL_CONTRACTS: Record<string, { appId: number; appAddress: string }> = {');
  for (const r of results) {
    const microAlgos = DENOMINATIONS.find(d => d.label === r.label)!.microAlgos;
    console.log(`  '${microAlgos}': { appId: ${r.appId}, appAddress: '${r.appAddress}' },`);
  }
  console.log('}');
  console.log('');
  console.log('PLONK_VERIFIER_ADDRESSES.testnet = {');
  console.log(`  withdraw: '${plonkAddresses.withdraw}',`);
  console.log(`  deposit: '${plonkAddresses.deposit}',`);
  console.log(`  privateSend: '${plonkAddresses.privateSend}',`);
  console.log('}');

  console.log('\nDone!');
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
