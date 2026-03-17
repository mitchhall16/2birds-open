#!/usr/bin/env npx tsx
/**
 * Pool Rotation Script
 *
 * When a pool's Merkle tree approaches capacity (65,536 deposits), this script:
 * 1. Deploys a new pool contract for the specified denomination
 * 2. Sets up PLONK verifiers on the new pool
 * 3. Funds the new pool address for box storage
 * 4. Outputs the config update to add the new pool and mark the old one as 'full'
 *
 * Usage:
 *   DEPLOYER_MNEMONIC="..." npx tsx scripts/rotate-pool.ts <denomination_microalgos>
 *
 * Example:
 *   DEPLOYER_MNEMONIC="..." npx tsx scripts/rotate-pool.ts 1000000
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
const CONFIG_PATH = path.resolve(__dirname, '../frontend/src/lib/config.ts');

// Existing verifier app IDs (shared across all pools)
const VERIFIER_APP_ID = 756420114;         // withdraw verifier
const DEPOSIT_VERIFIER_APP_ID = 756420115; // deposit verifier
const PRIVATESEND_VERIFIER_APP_ID = 756420116; // privateSend verifier

const TREE_CAPACITY = 65536; // 2^16
const NEAR_FULL_THRESHOLD = 0.9; // 90%

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

async function readPoolNextIndex(algod: algosdk.Algodv2, appId: number): Promise<number> {
  const appInfo = await algod.getApplicationByID(appId).do();
  const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || [];
  for (const kv of globalState) {
    const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key);
    if (key === 'next_idx') return Number(kv.value?.uint ?? kv.value?.ui ?? 0);
  }
  return 0;
}

async function main() {
  const denomArg = process.argv[2];
  if (!denomArg) {
    console.error('Usage: npx tsx scripts/rotate-pool.ts <denomination_microalgos>');
    console.error('Example: npx tsx scripts/rotate-pool.ts 1000000');
    process.exit(1);
  }

  const denomination = parseInt(denomArg, 10);
  if (isNaN(denomination) || denomination <= 0) {
    console.error(`Invalid denomination: ${denomArg}`);
    process.exit(1);
  }

  if (!process.env.DEPLOYER_MNEMONIC) {
    console.error('DEPLOYER_MNEMONIC not set');
    process.exit(1);
  }

  const algod = new algosdk.Algodv2(ALGOD_TOKEN, ALGOD_URL);
  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
  const deployerAddr = deployer.addr.toString();

  console.log(`Deployer: ${deployerAddr}`);
  console.log(`Denomination: ${denomination} microAlgos (${denomination / 1_000_000} ALGO)`);

  // Read current config to find existing pools for this denomination
  const configSource = fs.readFileSync(CONFIG_PATH, 'utf-8');
  const registryMatch = configSource.match(/export const POOL_REGISTRY[\s\S]*?^}/m);
  if (!registryMatch) {
    console.error('Could not find POOL_REGISTRY in config.ts');
    process.exit(1);
  }

  // Find current pools for this denomination by parsing the POOL_REGISTRY
  // We look for lines matching the denomination key
  const denomKey = denomination.toString();
  const denomRegex = new RegExp(`'${denomKey}':\\s*\\[([\\s\\S]*?)\\]`, 'm');
  const denomMatch = configSource.match(denomRegex);

  if (!denomMatch) {
    console.error(`No pools found for denomination ${denomKey} in config.ts`);
    process.exit(1);
  }

  // Extract existing appIds for this denomination
  const appIdMatches = [...denomMatch[1].matchAll(/appId:\s*(\d+)/g)];
  const existingAppIds = appIdMatches.map(m => parseInt(m[1], 10));

  if (existingAppIds.length === 0) {
    console.error(`No existing pool app IDs found for denomination ${denomKey}`);
    process.exit(1);
  }

  // Check capacity of the most recent (last) pool
  const currentAppId = existingAppIds[existingAppIds.length - 1];
  console.log(`\nCurrent active pool: App ID ${currentAppId}`);

  let nextIndex: number;
  try {
    nextIndex = await readPoolNextIndex(algod, currentAppId);
  } catch (err) {
    console.error(`Failed to read pool state for app ${currentAppId}:`, err);
    process.exit(1);
  }

  const percentFull = (nextIndex / TREE_CAPACITY) * 100;
  console.log(`  Deposits: ${nextIndex.toLocaleString()} / ${TREE_CAPACITY.toLocaleString()} (${percentFull.toFixed(1)}%)`);

  if (percentFull < NEAR_FULL_THRESHOLD * 100) {
    console.log(`\nPool is only ${percentFull.toFixed(1)}% full. Rotation not needed yet.`);
    console.log(`Rotation recommended when pool reaches ${(NEAR_FULL_THRESHOLD * 100).toFixed(0)}% capacity.`);
    const forceFlag = process.argv.includes('--force');
    if (!forceFlag) {
      console.log('Use --force to deploy anyway.');
      process.exit(0);
    }
    console.log('--force flag detected, proceeding with deployment...');
  }

  // Compile contract
  console.log('\nCompiling contract...');
  const approvalTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal'), 'utf-8');
  const clearTeal = fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal'), 'utf-8');

  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));
  console.log(`  Approval: ${approvalBytes.length} bytes, Clear: ${clearBytes.length} bytes`);

  // Get schema from ARC-56
  const arc56 = JSON.parse(fs.readFileSync(path.join(ARTIFACTS_DIR, 'PrivacyPool.arc56.json'), 'utf-8'));
  const globalInts = arc56.state?.schema?.global?.ints ?? 8;
  const globalBytes = arc56.state?.schema?.global?.bytes ?? 8;

  // Compile PLONK verifier TEAL programs (reuses same verifiers)
  console.log('\nResolving PLONK verifier addresses...');
  const circuits = ['withdraw', 'deposit', 'privateSend'];
  const plonkAddresses: Record<string, string> = {};

  for (const circuit of circuits) {
    const tealPath = path.join(CIRCUITS_DIR, `${circuit}_plonk_verifier.teal`);
    const tealSource = fs.readFileSync(tealPath, 'utf-8');
    const compiled = await algod.compile(Buffer.from(tealSource)).do();
    const program = new Uint8Array(Buffer.from(compiled.result, 'base64'));
    const lsig = new algosdk.LogicSigAccount(program);
    plonkAddresses[circuit] = String(lsig.address());
    console.log(`  ${circuit}: ${plonkAddresses[circuit]}`);
  }

  // Deploy new pool contract
  console.log(`\nDeploying new pool for ${denomination / 1_000_000} ALGO...`);
  const createSelector = methodSelector('createApplication(uint64,uint64,uint64,uint64,uint64)void');
  const setPlonkSelector = methodSelector('setPlonkVerifiers(address,address,address)void');

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
      abiUint64(denomination),
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
  const newAppId = Number((result as any).applicationIndex);
  const newAppAddress = String(algosdk.getApplicationAddress(newAppId));

  console.log(`  New App ID: ${newAppId}`);
  console.log(`  New Address: ${newAppAddress}`);

  // Fund the app address
  console.log('  Funding pool address...');
  const fundParams = await algod.getTransactionParams().do();
  const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployerAddr,
    receiver: newAppAddress,
    amount: 1_000_000, // 1 ALGO for box storage
    suggestedParams: { ...fundParams, fee: BigInt(1000), flatFee: true },
  });
  const signedFund = fundTxn.signTxn(deployer.sk);
  const fundResp = await algod.sendRawTransaction(signedFund).do();
  const fundTxId = (fundResp as any).txid ?? (fundResp as any).txId;
  await algosdk.waitForConfirmation(algod, fundTxId, 4);
  console.log('  Funded 1 ALGO for box storage');

  // Set PLONK verifiers
  console.log('  Setting PLONK verifiers...');
  const params2 = await algod.getTransactionParams().do();
  const withdrawAddr = algosdk.decodeAddress(plonkAddresses.withdraw);
  const depositAddr = algosdk.decodeAddress(plonkAddresses.deposit);
  const privateSendAddr = algosdk.decodeAddress(plonkAddresses.privateSend);

  const setTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: deployerAddr,
    appIndex: newAppId,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [setPlonkSelector, withdrawAddr.publicKey, depositAddr.publicKey, privateSendAddr.publicKey],
    suggestedParams: { ...params2, fee: BigInt(2000), flatFee: true },
  });

  const signedSet = setTxn.signTxn(deployer.sk);
  const setResp = await algod.sendRawTransaction(signedSet).do();
  const setTxId = (setResp as any).txid ?? (setResp as any).txId;
  await algosdk.waitForConfirmation(algod, setTxId, 4);
  console.log('  PLONK verifiers set');

  // Print config update instructions
  const generation = existingAppIds.length + 1;
  console.log('\n========================================');
  console.log('CONFIG UPDATE REQUIRED');
  console.log('========================================\n');
  console.log(`In frontend/src/lib/config.ts, update POOL_REGISTRY['${denomKey}']:\n`);
  console.log(`  '${denomKey}': [`);

  // Print existing entries with old ones marked as 'full'
  for (let i = 0; i < existingAppIds.length; i++) {
    const isLast = i === existingAppIds.length - 1;
    const status = isLast ? 'full' : 'retiring';
    // We need to find the appAddress for existing pools from the config
    const appAddrMatch = configSource.match(new RegExp(`appId:\\s*${existingAppIds[i]}[^}]*appAddress:\\s*'([^']+)'`));
    const appAddr = appAddrMatch ? appAddrMatch[1] : '(LOOKUP FROM CONFIG)';
    console.log(`    { appId: ${existingAppIds[i]}, appAddress: '${appAddr}', status: '${status}' },`);
  }

  // Print the new pool entry
  console.log(`    { appId: ${newAppId}, appAddress: '${newAppAddress}', status: 'active' },`);
  console.log('  ],');

  console.log(`\nPool rotation complete!`);
  console.log(`  Old pool (${currentAppId}): mark as 'full' — withdrawals still work`);
  console.log(`  New pool (${newAppId}): generation #${generation} — now accepting deposits`);
  console.log(`\nExisting deposits in pool ${currentAppId} can still be withdrawn normally.`);
  console.log(`New deposits will be routed to pool ${newAppId}.`);
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
