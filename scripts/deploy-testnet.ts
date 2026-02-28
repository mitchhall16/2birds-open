#!/usr/bin/env npx tsx
/**
 * Deploy all privacy-sdk contracts to Algorand testnet.
 *
 * Usage:
 *   npx tsx scripts/deploy-testnet.ts
 *
 * Environment variables:
 *   DEPLOYER_MNEMONIC — 25-word Algorand mnemonic (if not set, generates a new account)
 *   ALGOD_URL         — Algod API URL (default: https://testnet-api.algonode.cloud)
 *   ALGOD_TOKEN       — Algod API token (default: empty for algonode)
 */

import algosdk from 'algosdk';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ALGOD_URL = process.env.ALGOD_URL || 'https://testnet-api.algonode.cloud';
const ALGOD_TOKEN = process.env.ALGOD_TOKEN || '';
const ARTIFACTS_DIR = path.resolve(__dirname, '../contracts/artifacts');

interface DeployResult {
  name: string;
  appId: number;
  appAddress: string;
  txId: string;
}

async function main() {
  const algod = new algosdk.Algodv2(ALGOD_TOKEN, ALGOD_URL);

  // Get or create deployer account
  let deployer: algosdk.Account;
  if (process.env.DEPLOYER_MNEMONIC) {
    deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
    console.log(`Using existing account: ${deployer.addr}`);
  } else {
    deployer = algosdk.generateAccount();
    const mnemonic = algosdk.secretKeyToMnemonic(deployer.sk);
    console.log(`\nGenerated new deployer account:`);
    console.log(`  Address:  ${deployer.addr}`);
    console.log(`  Mnemonic: ${mnemonic}`);
    console.log(`\nFund this account using the Algorand testnet faucet:`);
    console.log(`  https://bank.testnet.algorand.network/?account=${deployer.addr}`);
    console.log(`\nThen re-run with:`);
    console.log(`  DEPLOYER_MNEMONIC="${mnemonic}" npx tsx scripts/deploy-testnet.ts`);
    return;
  }

  // Check balance
  const accountInfo = await algod.accountInformation(deployer.addr).do();
  const balance = accountInfo.amount;
  console.log(`Account balance: ${(Number(balance) / 1e6).toFixed(6)} ALGO`);

  if (balance < 5_000_000) {
    console.error(`\nInsufficient balance. Need at least 5 ALGO for deployment.`);
    console.log(`Fund at: https://bank.testnet.algorand.network/?account=${deployer.addr}`);
    process.exit(1);
  }

  const results: DeployResult[] = [];

  // Deploy contracts in order
  const contracts = [
    {
      name: 'StealthRegistry',
      createArgs: () => [
        // createApplication() — no args
      ],
    },
    {
      name: 'PrivacyPool',
      createArgs: () => [
        // createApplication(denomination, assetId)
        algosdk.encodeUint64(1_000_000), // 1 ALGO denomination
        algosdk.encodeUint64(0),          // ALGO (not ASA)
      ],
    },
    {
      name: 'ShieldedPool',
      createArgs: () => [
        // createApplication(assetId)
        algosdk.encodeUint64(0), // ALGO
      ],
    },
    {
      name: 'ConfidentialAsset',
      createArgs: () => [
        // createApplication(assetId)
        algosdk.encodeUint64(0), // ALGO
      ],
    },
  ];

  for (const contract of contracts) {
    console.log(`\nDeploying ${contract.name}...`);
    try {
      const result = await deployContract(
        algod,
        deployer,
        contract.name,
        contract.createArgs(),
      );
      results.push(result);
      console.log(`  App ID:      ${result.appId}`);
      console.log(`  App Address: ${result.appAddress}`);
      console.log(`  Tx ID:       ${result.txId}`);
    } catch (err: any) {
      console.error(`  FAILED: ${err.message}`);
    }
  }

  // Write deployment info to file
  if (results.length > 0) {
    const deploymentInfo = {
      network: 'testnet',
      deployer: String(deployer.addr),
      timestamp: new Date().toISOString(),
      contracts: Object.fromEntries(results.map(r => [r.name, {
        appId: r.appId,
        appAddress: r.appAddress,
        txId: r.txId,
      }])),
    };

    const outPath = path.resolve(__dirname, '../deployment-testnet.json');
    fs.writeFileSync(outPath, JSON.stringify(deploymentInfo, null, 2));
    console.log(`\nDeployment info saved to: deployment-testnet.json`);
  }

  console.log(`\n${results.length}/${contracts.length} contracts deployed successfully.`);
}

async function deployContract(
  algod: algosdk.Algodv2,
  deployer: algosdk.Account,
  name: string,
  createArgs: Uint8Array[],
): Promise<DeployResult> {
  const approvalPath = path.join(ARTIFACTS_DIR, `${name}.approval.teal`);
  const clearPath = path.join(ARTIFACTS_DIR, `${name}.clear.teal`);

  const approvalTeal = fs.readFileSync(approvalPath, 'utf-8');
  const clearTeal = fs.readFileSync(clearPath, 'utf-8');

  // Compile TEAL to bytecode
  const approvalCompiled = await algod.compile(Buffer.from(approvalTeal)).do();
  const clearCompiled = await algod.compile(Buffer.from(clearTeal)).do();

  const approvalBytes = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearBytes = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));

  // Read ARC-56 spec for schema info
  const arc56Path = path.join(ARTIFACTS_DIR, `${name}.arc56.json`);
  let globalInts = 4;
  let globalBytes = 4;
  let localInts = 0;
  let localBytes = 0;

  if (fs.existsSync(arc56Path)) {
    const arc56 = JSON.parse(fs.readFileSync(arc56Path, 'utf-8'));
    if (arc56.state?.schema) {
      globalInts = arc56.state.schema.global?.ints ?? globalInts;
      globalBytes = arc56.state.schema.global?.bytes ?? globalBytes;
      localInts = arc56.state.schema.local?.ints ?? localInts;
      localBytes = arc56.state.schema.local?.bytes ?? localBytes;
    }
  }

  const params = await algod.getTransactionParams().do();

  const txn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram: approvalBytes,
    clearProgram: clearBytes,
    numGlobalInts: globalInts,
    numGlobalByteSlices: globalBytes,
    numLocalInts: localInts,
    numLocalByteSlices: localBytes,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: createArgs,
    suggestedParams: { ...params, fee: 2000, flatFee: true },
  });

  const signed = txn.signTxn(deployer.sk);
  const resp = await algod.sendRawTransaction(signed).do();
  const txId = (resp as any).txid ?? (resp as any).txId;
  const result = await algosdk.waitForConfirmation(algod, txId, 4);
  const appId = (result as any)['application-index'];
  const appAddress = algosdk.getApplicationAddress(appId);

  return { name, appId, appAddress: String(appAddress), txId };
}

main().catch(err => {
  console.error('Deployment failed:', err);
  process.exit(1);
});
