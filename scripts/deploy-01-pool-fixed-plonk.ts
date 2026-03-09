#!/usr/bin/env npx tsx
/**
 * Deploy a fresh 0.1 ALGO PrivacyPool with hardcoded PLONK verifier addresses.
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
const ARTIFACTS_DIR = path.resolve(__dirname, '../contracts/artifacts');

// Existing Groth16 verifier app IDs (passed to createApplication)
const VERIFIER_APP_ID = 756420114;
const DEPOSIT_VERIFIER_APP_ID = 756420115;
const PRIVATESEND_VERIFIER_APP_ID = 756420116;

// Fixed PLONK verifier addresses (provided by user)
const PLONK_WITHDRAW   = 'XXN3WO7QABM7X65RMPD4WXFWXOVUICQCBP3OZ7DYXVON6HNGIZSAL55M5Y';
const PLONK_DEPOSIT    = 'ZIZT5OX5DHYNYNNWNCPCDO34H36L46Y7V2QNKDC7AK6ITHOIHAT7ZWI7JQ';
const PLONK_PRIVATESEND = '7X45UWWAVQQEUCNPGLQ6SUBHKWNCJB7GCWMK3FPV3NERZIECCJOAZ44C4Q';

function methodSelector(signature: string): Uint8Array {
  const hash = crypto.createHash('sha512-256').update(signature).digest();
  return new Uint8Array(hash.slice(0, 4));
}

function abiUint64(n: number): Uint8Array {
  const buf = new Uint8Array(8);
  new DataView(buf.buffer).setBigUint64(0, BigInt(n));
  return buf;
}

async function main() {
  const algod = new algosdk.Algodv2('', ALGOD_URL);

  if (!process.env.DEPLOYER_MNEMONIC) {
    console.error('DEPLOYER_MNEMONIC not set');
    process.exit(1);
  }

  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
  const deployerAddr = deployer.addr.toString();
  console.log(`Deployer: ${deployerAddr}`);

  // Check balance
  const acctInfo = await algod.accountInformation(deployerAddr).do();
  const balance = Number(acctInfo.amount) / 1e6;
  const available = (Number(acctInfo.amount) - Number(acctInfo.minBalance)) / 1e6;
  console.log(`Balance: ${balance.toFixed(4)} ALGO (available: ${available.toFixed(4)} ALGO)`);

  // Compile pool contract
  const approvalTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal'), 'utf-8');
  const clearTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal'), 'utf-8');
  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));
  console.log(`Approval: ${approvalBytes.length} bytes, Clear: ${clearBytes.length} bytes`);

  // Get schema from ARC-56
  const arc56 = JSON.parse(fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.arc56.json'), 'utf-8'));
  const globalInts = arc56.state?.schema?.global?.ints ?? 7;
  const globalBytes = arc56.state?.schema?.global?.bytes ?? 4;
  console.log(`Schema: ${globalInts} ints, ${globalBytes} bytes`);

  // ========== 1. Create pool app (0.1 ALGO = 100,000 microAlgos) ==========
  console.log('\n--- Step 1: Deploy 0.1 ALGO pool ---');
  const params = await algod.getTransactionParams().do();
  const createSelector = methodSelector('createApplication(uint64,uint64,uint64,uint64,uint64)void');

  const createTxn = algosdk.makeApplicationCreateTxnFromObject({
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
      abiUint64(100_000),  // 0.1 ALGO
      abiUint64(0),         // ALGO (not ASA)
      abiUint64(VERIFIER_APP_ID),
      abiUint64(DEPOSIT_VERIFIER_APP_ID),
      abiUint64(PRIVATESEND_VERIFIER_APP_ID),
    ],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  const signed = createTxn.signTxn(deployer.sk);
  const resp = await algod.sendRawTransaction(signed).do();
  const createTxId = (resp as any).txid ?? (resp as any).txId;
  console.log(`  Create txId: ${createTxId}`);
  const result = await algosdk.waitForConfirmation(algod, createTxId, 4);
  const appId = Number((result as any).applicationIndex ?? (result as any)['application-index']);
  const appAddress = String(algosdk.getApplicationAddress(appId));
  console.log(`  App ID: ${appId}`);
  console.log(`  App Address: ${appAddress}`);

  // ========== 2. Fund pool with 1 ALGO for box storage ==========
  console.log('\n--- Step 2: Fund pool (1 ALGO) ---');
  const fundParams = await algod.getTransactionParams().do();
  const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployerAddr,
    receiver: appAddress,
    amount: 1_000_000,
    suggestedParams: { ...fundParams, fee: BigInt(1000), flatFee: true },
  });
  const signedFund = fundTxn.signTxn(deployer.sk);
  const fundResp = await algod.sendRawTransaction(signedFund).do();
  const fundTxId = (fundResp as any).txid ?? (fundResp as any).txId;
  await algosdk.waitForConfirmation(algod, fundTxId, 4);
  console.log(`  Fund txId: ${fundTxId}`);
  console.log(`  Funded 1 ALGO`);

  // ========== 3. Set PLONK verifiers ==========
  console.log('\n--- Step 3: Set PLONK verifiers ---');
  console.log(`  withdraw:    ${PLONK_WITHDRAW}`);
  console.log(`  deposit:     ${PLONK_DEPOSIT}`);
  console.log(`  privateSend: ${PLONK_PRIVATESEND}`);

  const params2 = await algod.getTransactionParams().do();
  const setPlonkSelector = methodSelector('setPlonkVerifiers(address,address,address)void');
  const withdrawPk = algosdk.decodeAddress(PLONK_WITHDRAW).publicKey;
  const depositPk = algosdk.decodeAddress(PLONK_DEPOSIT).publicKey;
  const privateSendPk = algosdk.decodeAddress(PLONK_PRIVATESEND).publicKey;

  const setTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: deployerAddr,
    appIndex: appId,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [setPlonkSelector, withdrawPk, depositPk, privateSendPk],
    suggestedParams: { ...params2, fee: BigInt(2000), flatFee: true },
  });
  const signedSet = setTxn.signTxn(deployer.sk);
  const setResp = await algod.sendRawTransaction(signedSet).do();
  const setTxId = (setResp as any).txid ?? (setResp as any).txId;
  await algosdk.waitForConfirmation(algod, setTxId, 4);
  console.log(`  setPlonkVerifiers txId: ${setTxId}`);
  console.log(`  PLONK verifiers set!`);

  // ========== 4. Check/fund PLONK LogicSig addresses ==========
  console.log('\n--- Step 4: Check/fund PLONK LogicSig addresses ---');
  for (const [label, addr] of [['withdraw', PLONK_WITHDRAW], ['deposit', PLONK_DEPOSIT], ['privateSend', PLONK_PRIVATESEND]]) {
    try {
      const info = await algod.accountInformation(addr).do();
      const bal = Number(info.amount);
      if (bal >= 100_000) {
        console.log(`  ${label}: already funded (${(bal / 1e6).toFixed(4)} ALGO)`);
        continue;
      }
    } catch {}

    console.log(`  ${label}: funding with 0.3 ALGO...`);
    const p = await algod.getTransactionParams().do();
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployerAddr,
      receiver: addr,
      amount: 300_000,
      suggestedParams: { ...p, fee: BigInt(1000), flatFee: true },
    });
    const s = txn.signTxn(deployer.sk);
    const r = await algod.sendRawTransaction(s).do();
    const tid = (r as any).txid ?? (r as any).txId;
    await algosdk.waitForConfirmation(algod, tid, 4);
    console.log(`  ${label}: funded (txId: ${tid})`);
  }

  // ========== Summary ==========
  console.log('\n========================================');
  console.log('DEPLOYMENT COMPLETE');
  console.log('========================================');
  console.log(`Pool App ID:      ${appId}`);
  console.log(`Pool App Address: ${appAddress}`);
  console.log(`Create TxId:      ${createTxId}`);
  console.log(`Fund TxId:        ${fundTxId}`);
  console.log(`SetPlonk TxId:    ${setTxId}`);
  console.log(`Denomination:     100000 (0.1 ALGO)`);
  console.log('');
  console.log('UPDATE frontend/src/lib/config.ts:');
  console.log(`  '100000': { appId: ${appId}, appAddress: '${appAddress}' },`);
  console.log('========================================');
}

main().catch(err => {
  console.error('FAILED:', err.message || err);
  if (err.response?.body) {
    console.error('Response:', JSON.stringify(err.response.body));
  }
  process.exit(1);
});
