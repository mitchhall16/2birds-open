#!/usr/bin/env npx tsx
/**
 * Deploy a fresh 0.1 ALGO PrivacyPool with correct PLONK verifier addresses.
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
const CIRCUITS_DIR = path.resolve(__dirname, '../frontend/public/circuits');

// Existing Groth16 verifier app IDs (unchanged)
const VERIFIER_APP_ID = 756420114;
const DEPOSIT_VERIFIER_APP_ID = 756420115;
const PRIVATESEND_VERIFIER_APP_ID = 756420116;

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

  // Compile pool contract
  const approvalTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal'), 'utf-8');
  const clearTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal'), 'utf-8');
  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));
  console.log(`Approval: ${approvalBytes.length} bytes`);

  // Get schema
  const arc56 = JSON.parse(fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.arc56.json'), 'utf-8'));
  const globalInts = arc56.state?.schema?.global?.ints ?? 8;
  const globalBytes = arc56.state?.schema?.global?.bytes ?? 8;

  // Compile PLONK verifier TEALs to get addresses
  const plonkAddresses: Record<string, string> = {};
  for (const circuit of ['withdraw', 'deposit', 'privateSend']) {
    const tealPath = path.join(CIRCUITS_DIR, `${circuit}_plonk_verifier.teal`);
    const tealSource = fs.readFileSync(tealPath, 'utf-8');
    const compiled = await algod.compile(Buffer.from(tealSource)).do();
    const program = new Uint8Array(Buffer.from(compiled.result, 'base64'));
    const lsig = new algosdk.LogicSigAccount(program);
    plonkAddresses[circuit] = String(lsig.address());
    console.log(`${circuit} verifier: ${plonkAddresses[circuit]}`);
  }

  // 1. Create pool app (0.1 ALGO = 100,000 microAlgos)
  console.log('\nDeploying 0.1 ALGO pool...');
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
  const txId = (resp as any).txid ?? (resp as any).txId;
  const result = await algosdk.waitForConfirmation(algod, txId, 4);
  const appId = Number((result as any).applicationIndex);
  const appAddress = String(algosdk.getApplicationAddress(appId));
  console.log(`  App ID: ${appId}`);
  console.log(`  Address: ${appAddress}`);

  // 2. Fund pool with 1 ALGO for box storage
  console.log('Funding pool...');
  const fundParams = await algod.getTransactionParams().do();
  const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployerAddr,
    receiver: appAddress,
    amount: 1_000_000,
    suggestedParams: { ...fundParams, fee: BigInt(1000), flatFee: true },
  });
  const signedFund = fundTxn.signTxn(deployer.sk);
  const fundResp = await algod.sendRawTransaction(signedFund).do();
  await algosdk.waitForConfirmation(algod, (fundResp as any).txid ?? (fundResp as any).txId, 4);
  console.log('  Funded 1 ALGO');

  // 3. Set PLONK verifiers
  console.log('Setting PLONK verifiers...');
  const params2 = await algod.getTransactionParams().do();
  const setPlonkSelector = methodSelector('setPlonkVerifiers(address,address,address)void');
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
  await algosdk.waitForConfirmation(algod, (setResp as any).txid ?? (setResp as any).txId, 4);
  console.log('  PLONK verifiers set');

  // 4. Fund deposit verifier LogicSig address if needed
  const depositVerifierAddr = plonkAddresses.deposit;
  const verifierInfo = await algod.accountInformation(depositVerifierAddr).do();
  if (Number(verifierInfo.amount) < 100_000) {
    console.log('Funding deposit verifier LogicSig...');
    const params3 = await algod.getTransactionParams().do();
    const fundVerifierTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployerAddr,
      receiver: depositVerifierAddr,
      amount: 300_000, // 0.3 ALGO for safety
      suggestedParams: { ...params3, fee: BigInt(1000), flatFee: true },
    });
    const signedFundV = fundVerifierTxn.signTxn(deployer.sk);
    const fundVResp = await algod.sendRawTransaction(signedFundV).do();
    await algosdk.waitForConfirmation(algod, (fundVResp as any).txid ?? (fundVResp as any).txId, 4);
    console.log('  Funded deposit verifier 0.3 ALGO');
  } else {
    console.log(`  Deposit verifier already funded: ${Number(verifierInfo.amount) / 1e6} ALGO`);
  }

  // 5. Fund withdraw verifier LogicSig address if needed
  const withdrawVerifierAddr = plonkAddresses.withdraw;
  const wVerifierInfo = await algod.accountInformation(withdrawVerifierAddr).do();
  if (Number(wVerifierInfo.amount) < 100_000) {
    console.log('Funding withdraw verifier LogicSig...');
    const params4 = await algod.getTransactionParams().do();
    const fundWVerifierTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: deployerAddr,
      receiver: withdrawVerifierAddr,
      amount: 300_000, // 0.3 ALGO for safety
      suggestedParams: { ...params4, fee: BigInt(1000), flatFee: true },
    });
    const signedFundWV = fundWVerifierTxn.signTxn(deployer.sk);
    const fundWVResp = await algod.sendRawTransaction(signedFundWV).do();
    await algosdk.waitForConfirmation(algod, (fundWVResp as any).txid ?? (fundWVResp as any).txId, 4);
    console.log('  Funded withdraw verifier 0.3 ALGO');
  } else {
    console.log(`  Withdraw verifier already funded: ${Number(wVerifierInfo.amount) / 1e6} ALGO`);
  }

  // Print what needs updating
  console.log('\n========================================');
  console.log('UPDATE THESE IN frontend/src/lib/config.ts:');
  console.log('========================================');
  console.log(`'100000': { appId: ${appId}, appAddress: '${appAddress}' },`);
  console.log(`\ndeposit verifier:  '${plonkAddresses.deposit}'`);
  console.log(`withdraw verifier: '${plonkAddresses.withdraw}'`);
  console.log('\nDone!');
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
