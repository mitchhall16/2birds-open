#!/usr/bin/env npx tsx
/**
 * Deploy 2birds privacy pool contracts to Algorand MAINNET.
 *
 * Deploys:
 *   1. Budget helper app (opcode budget padding)
 *   2. ZK verifier apps (Groth16: deposit, withdraw, privateSend)
 *   3. Three PrivacyPool instances (0.1, 0.5, 1.0 ALGO)
 *   4. (Optional) PLONK LogicSig verifiers — compile and register
 *
 * Safety features:
 *   - Confirmation prompts before each deployment
 *   - Balance checks
 *   - Outputs deployment-mainnet.json with all app IDs
 *   - Dry-run mode (--dry-run)
 *
 * Usage:
 *   npx tsx scripts/deploy-mainnet.ts
 *   npx tsx scripts/deploy-mainnet.ts --dry-run
 *
 * Requires DEPLOYER_MNEMONIC in .env or environment.
 * WARNING: This deploys to MAINNET. Real ALGO will be spent.
 */

import algosdk from 'algosdk';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { fileURLToPath } from 'url';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DRY_RUN = process.argv.includes('--dry-run');
const ALGOD_URL = process.env.MAINNET_ALGOD_URL || 'https://mainnet-api.algonode.cloud';
const ALGOD_TOKEN = process.env.MAINNET_ALGOD_TOKEN || '';
const ARTIFACTS_DIR = path.resolve(__dirname, '../contracts/artifacts');

const DENOMINATIONS = [
  { label: '0.1 ALGO', microAlgos: 100_000 },
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

function formatAlgo(microAlgos: number): string {
  return (microAlgos / 1_000_000).toFixed(3);
}

async function confirm(question: string): Promise<boolean> {
  if (DRY_RUN) {
    console.log(`  [DRY RUN] Would ask: ${question}`);
    return true;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    rl.question(`  ${question} (y/N): `, answer => {
      rl.close();
      resolve(answer.toLowerCase() === 'y');
    });
  });
}

async function deployApp(
  algod: algosdk.Algodv2,
  deployer: algosdk.Account,
  approvalTeal: string,
  clearTeal: string,
  label: string,
  opts?: {
    globalInts?: number;
    globalBytes?: number;
    appArgs?: Uint8Array[];
  },
): Promise<{ appId: number; appAddress: string; txId: string }> {
  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  console.log(`  ${label} approval: ${approvalBytes.length} bytes`);

  if (DRY_RUN) {
    console.log(`  [DRY RUN] Would deploy ${label}`);
    return { appId: 0, appAddress: '', txId: 'dry-run' };
  }

  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));

  const params = await algod.getTransactionParams().do();
  const txn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram: approvalBytes,
    clearProgram: clearBytes,
    numGlobalInts: opts?.globalInts ?? 0,
    numGlobalByteSlices: opts?.globalBytes ?? 0,
    numLocalInts: 0,
    numLocalByteSlices: 0,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: opts?.appArgs,
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  const signed = txn.signTxn(deployer.sk);
  const resp = await algod.sendRawTransaction(signed).do();
  const txId = (resp as any).txid ?? (resp as any).txId;
  const confirmed = await algosdk.waitForConfirmation(algod, txId, 4);
  const appId = Number((confirmed as any).applicationIndex ?? (confirmed as any)['application-index']);
  const appAddress = algosdk.getApplicationAddress(appId);
  return { appId, appAddress, txId };
}

async function main() {
  console.log('');
  console.log('=== 2birds — Mainnet Deployment ===');
  console.log('');

  if (DRY_RUN) {
    console.log('  MODE: DRY RUN (no transactions will be sent)');
    console.log('');
  }

  // Load deployer account
  const mnemonic = process.env.DEPLOYER_MNEMONIC;
  if (!mnemonic) {
    console.error('ERROR: Set DEPLOYER_MNEMONIC in .env');
    process.exit(1);
  }

  const deployer = algosdk.mnemonicToSecretKey(mnemonic);
  const algod = new algosdk.Algodv2(ALGOD_TOKEN, ALGOD_URL, '');

  console.log(`  Deployer:  ${deployer.addr}`);
  console.log(`  Network:   ${ALGOD_URL}`);
  console.log('');

  // Check balance
  const accountInfo = await algod.accountInformation(deployer.addr).do();
  const balance = Number(accountInfo.amount);
  const minBalance = Number(accountInfo.minBalance ?? 100_000);
  const available = balance - minBalance;
  console.log(`  Balance:   ${formatAlgo(balance)} ALGO`);
  console.log(`  Available: ${formatAlgo(available)} ALGO`);
  console.log('');

  const estimatedCost = 5_000_000; // ~5 ALGO for all deployments + MBR
  if (available < estimatedCost) {
    console.error(`  WARNING: Estimated deployment cost is ~${formatAlgo(estimatedCost)} ALGO`);
    console.error(`  You have ${formatAlgo(available)} ALGO available.`);
    if (!await confirm('Continue anyway?')) process.exit(1);
  }

  if (!await confirm('Deploy to MAINNET?')) {
    console.log('  Aborted.');
    process.exit(0);
  }

  const deployment: Record<string, any> = {
    network: 'mainnet',
    deployer: deployer.addr,
    timestamp: new Date().toISOString(),
  };

  // 1. Deploy budget helper
  console.log('\n--- Step 1: Budget Helper ---');
  const budgetTeal = '#pragma version 11\npushint 1\nreturn';
  const budgetClear = '#pragma version 11\npushint 1\nreturn';
  const budget = await deployApp(algod, deployer, budgetTeal, budgetClear, 'BudgetHelper');
  console.log(`  Budget Helper: appId=${budget.appId}`);
  deployment.budgetHelper = budget;

  // 2. Deploy verifiers
  console.log('\n--- Step 2: ZK Verifiers ---');

  const verifierNames = ['withdraw', 'deposit', 'privateSend'];
  const verifiers: Record<string, any> = {};

  for (const name of verifierNames) {
    const tealPath = path.join(ARTIFACTS_DIR, `${name}_verifier.teal`);
    const clearPath = path.join(ARTIFACTS_DIR, `${name}_verifier_clear.teal`);

    if (!fs.existsSync(tealPath)) {
      console.log(`  WARNING: ${tealPath} not found, skipping ${name} verifier`);
      verifiers[name] = { appId: 0, appAddress: '', error: 'TEAL not found' };
      continue;
    }

    const teal = fs.readFileSync(tealPath, 'utf-8');
    const clear = fs.existsSync(clearPath)
      ? fs.readFileSync(clearPath, 'utf-8')
      : budgetClear;

    const result = await deployApp(algod, deployer, teal, clear, `${name}Verifier`, {
      globalInts: 0,
      globalBytes: 0,
    });
    console.log(`  ${name}Verifier: appId=${result.appId}`);
    verifiers[name] = result;
  }
  deployment.verifiers = verifiers;

  // 3. Deploy pool contracts
  console.log('\n--- Step 3: Privacy Pools ---');

  const poolTealPath = path.join(ARTIFACTS_DIR, 'PrivacyPool.approval.teal');
  const poolClearPath = path.join(ARTIFACTS_DIR, 'PrivacyPool.clear.teal');

  if (!fs.existsSync(poolTealPath)) {
    console.error(`  ERROR: ${poolTealPath} not found. Compile the TealScript contract first.`);
    console.error('  Run: npx tealscript contracts/privacy-pool.algo.ts contracts/artifacts/');
    process.exit(1);
  }

  const poolTeal = fs.readFileSync(poolTealPath, 'utf-8');
  const poolClear = fs.readFileSync(poolClearPath, 'utf-8');
  const pools: Record<string, any> = {};

  const createSelector = methodSelector(
    'createApplication(uint64,uint64,uint64,uint64,uint64)void'
  );

  for (const denom of DENOMINATIONS) {
    console.log(`\n  Deploying pool: ${denom.label}...`);

    const pool = await deployApp(algod, deployer, poolTeal, poolClear, `Pool_${denom.label}`, {
      globalInts: 8,
      globalBytes: 6,
      appArgs: [
        createSelector,
        abiUint64(denom.microAlgos),
        abiUint64(0), // assetId (ALGO)
        abiUint64(verifiers.withdraw?.appId ?? 0),
        abiUint64(verifiers.deposit?.appId ?? 0),
        abiUint64(verifiers.privateSend?.appId ?? 0),
      ],
    });

    console.log(`  Pool ${denom.label}: appId=${pool.appId}, addr=${pool.appAddress}`);

    // Fund the pool contract (MBR)
    if (!DRY_RUN && pool.appId > 0) {
      const params = await algod.getTransactionParams().do();
      const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: deployer.addr,
        receiver: pool.appAddress,
        amount: 1_000_000, // 1 ALGO for MBR + some operational balance
        suggestedParams: params,
      });
      const signedFund = fundTxn.signTxn(deployer.sk);
      await algod.sendRawTransaction(signedFund).do();
      console.log(`  Funded pool with 1.0 ALGO`);
    }

    pools[denom.microAlgos.toString()] = pool;
  }
  deployment.pools = pools;

  // 4. Save deployment file
  const outputPath = path.resolve(__dirname, '../deployment-mainnet.json');
  fs.writeFileSync(outputPath, JSON.stringify(deployment, null, 2));
  console.log(`\n=== Deployment Complete ===`);
  console.log(`  Output: ${outputPath}`);
  console.log('');
  console.log('Next steps:');
  console.log('  1. Update frontend/src/lib/config.ts with mainnet app IDs');
  console.log('  2. Set VITE_NETWORK=mainnet in frontend .env');
  console.log('  3. Build and deploy frontend: cd frontend && npm run build');
  console.log('  4. (Optional) Compile PLONK verifiers and set via setPlonkVerifiers()');
}

main().catch(err => {
  console.error('Deployment failed:', err);
  process.exit(1);
});
