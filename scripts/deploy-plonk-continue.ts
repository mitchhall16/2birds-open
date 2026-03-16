#!/usr/bin/env npx tsx
/**
 * Continue PLONK pool deployment — fund 0.5 pool, deploy 1.0 pool, set verifiers.
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
const CIRCUITS_DIR = path.resolve(__dirname, '../circuits/build');

const VERIFIER_APP_ID = 756420114;
const DEPOSIT_VERIFIER_APP_ID = 756420115;
const PRIVATESEND_VERIFIER_APP_ID = 756420116;

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
  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC!);
  console.log(`Deployer: ${deployer.addr}`);

  const info = await algod.accountInformation(deployer.addr).do();
  console.log(`Balance: ${(Number(info.amount) / 1e6).toFixed(3)} ALGO (available: ${((Number(info.amount) - Number(info.minBalance)) / 1e6).toFixed(3)})`);

  // Get PLONK verifier addresses
  const plonkAddresses: Record<string, string> = {};
  for (const circuit of ['withdraw', 'deposit', 'privateSend']) {
    const tealPath = path.join(CIRCUITS_DIR, `${circuit}_plonk_verifier.teal`);
    const tealSource = fs.readFileSync(tealPath, 'utf-8');
    const compiled = await algod.compile(Buffer.from(tealSource)).do();
    const program = new Uint8Array(Buffer.from(compiled.result, 'base64'));
    const lsig = new algosdk.LogicSigAccount(program);
    plonkAddresses[circuit] = String(lsig.address());
  }
  console.log('PLONK addresses:', plonkAddresses);

  const setPlonkSelector = methodSelector('setPlonkVerifiers(address,address,address)void');
  const withdrawPK = algosdk.decodeAddress(plonkAddresses.withdraw).publicKey;
  const depositPK = algosdk.decodeAddress(plonkAddresses.deposit).publicKey;
  const privateSendPK = algosdk.decodeAddress(plonkAddresses.privateSend).publicKey;

  // --- 0.5 ALGO pool (already created as 756862750) ---
  const pool05AppId = 756862750;
  const pool05Addr = String(algosdk.getApplicationAddress(pool05AppId));
  console.log(`\n--- 0.5 ALGO pool (${pool05AppId}) ---`);

  // Fund it minimally
  let params = await algod.getTransactionParams().do();
  const fund05 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployer.addr,
    receiver: pool05Addr,
    amount: 200_000, // 0.2 ALGO
    suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
  });
  let signed = fund05.signTxn(deployer.sk);
  let resp = await algod.sendRawTransaction(signed).do();
  let txId = (resp as any).txid ?? (resp as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);
  console.log('Funded 0.2 ALGO');

  // Set PLONK verifiers
  params = await algod.getTransactionParams().do();
  const set05 = algosdk.makeApplicationCallTxnFromObject({
    sender: deployer.addr,
    appIndex: pool05AppId,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [setPlonkSelector, withdrawPK, depositPK, privateSendPK],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });
  signed = set05.signTxn(deployer.sk);
  resp = await algod.sendRawTransaction(signed).do();
  txId = (resp as any).txid ?? (resp as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);
  console.log('PLONK verifiers set');

  // --- 1.0 ALGO pool (new) ---
  console.log('\n--- Deploying 1.0 ALGO pool ---');
  const approvalTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal'), 'utf-8');
  const clearTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal'), 'utf-8');
  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));

  const arc56 = JSON.parse(fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.arc56.json'), 'utf-8'));
  const globalInts = arc56.state?.schema?.global?.ints ?? 8;
  const globalBytes = arc56.state?.schema?.global?.bytes ?? 8;

  const createSelector = methodSelector('createApplication(uint64,uint64,uint64,uint64,uint64)void');
  params = await algod.getTransactionParams().do();
  const create10 = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram: approvalBytes,
    clearProgram: clearBytes,
    numGlobalInts: globalInts,
    numGlobalByteSlices: globalBytes,
    numLocalInts: 0,
    numLocalByteSlices: 0,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      createSelector,
      abiUint64(1_000_000),
      abiUint64(0),
      abiUint64(VERIFIER_APP_ID),
      abiUint64(DEPOSIT_VERIFIER_APP_ID),
      abiUint64(PRIVATESEND_VERIFIER_APP_ID),
    ],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });
  signed = create10.signTxn(deployer.sk);
  resp = await algod.sendRawTransaction(signed).do();
  txId = (resp as any).txid ?? (resp as any).txId;
  const result = await algosdk.waitForConfirmation(algod, txId, 4);
  const pool10AppId = Number((result as any).applicationIndex);
  const pool10Addr = String(algosdk.getApplicationAddress(pool10AppId));
  console.log(`App ID: ${pool10AppId}, Address: ${pool10Addr}`);

  // Fund 1.0 pool
  params = await algod.getTransactionParams().do();
  const fund10 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployer.addr,
    receiver: pool10Addr,
    amount: 200_000,
    suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
  });
  signed = fund10.signTxn(deployer.sk);
  resp = await algod.sendRawTransaction(signed).do();
  txId = (resp as any).txid ?? (resp as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);
  console.log('Funded 0.2 ALGO');

  // Set PLONK verifiers on 1.0 pool
  params = await algod.getTransactionParams().do();
  const set10 = algosdk.makeApplicationCallTxnFromObject({
    sender: deployer.addr,
    appIndex: pool10AppId,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [setPlonkSelector, withdrawPK, depositPK, privateSendPK],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });
  signed = set10.signTxn(deployer.sk);
  resp = await algod.sendRawTransaction(signed).do();
  txId = (resp as any).txid ?? (resp as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);
  console.log('PLONK verifiers set');

  // Fund PLONK LogicSig addresses if needed
  console.log('\nFunding PLONK LogicSig addresses...');
  for (const circuit of ['withdraw', 'deposit', 'privateSend']) {
    const addr = plonkAddresses[circuit];
    try {
      const acctInfo = await algod.accountInformation(addr).do();
      if (Number(acctInfo.amount) >= 100_000) {
        console.log(`  ${circuit}: already funded (${Number(acctInfo.amount) / 1e6} ALGO)`);
        continue;
      }
    } catch {}
    params = await algod.getTransactionParams().do();
    const fund = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployer.addr,
      receiver: addr,
      amount: 100_000,
      suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
    });
    signed = fund.signTxn(deployer.sk);
    resp = await algod.sendRawTransaction(signed).do();
    txId = (resp as any).txid ?? (resp as any).txId;
    await algosdk.waitForConfirmation(algod, txId, 4);
    console.log(`  ${circuit}: funded 0.1 ALGO`);
  }

  // Print final config
  console.log('\n\n========================================');
  console.log('UPDATE frontend/src/lib/config.ts:');
  console.log('========================================');
  console.log(`
export const POOL_CONTRACTS: Record<string, { appId: number; appAddress: string }> = {
  '100000': { appId: 756478534, appAddress: 'KKBAABJWKQADOM6HG4JPDQDQMCD5JSMJR2HCNDQGQRW4KL5UDVVUWGMU5E' },
  '500000': { appId: ${pool05AppId}, appAddress: '${pool05Addr}' },
  '1000000': { appId: ${pool10AppId}, appAddress: '${pool10Addr}' },
}

PLONK_VERIFIER_ADDRESSES testnet:
  withdraw: '${plonkAddresses.withdraw}',
  deposit: '${plonkAddresses.deposit}',
  privateSend: '${plonkAddresses.privateSend}',
`);
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
