#!/usr/bin/env npx tsx
/**
 * Privacy SDK — Live Testnet Interaction
 *
 * Run with:
 *   DEPLOYER_MNEMONIC="..." npx tsx test-testnet.ts
 *
 * This script interacts with the LIVE deployed contracts on Algorand testnet.
 * It demonstrates:
 * 1. Connecting to testnet and checking the deployed contracts
 * 2. Creating a deposit commitment (local crypto)
 * 3. Submitting the deposit on-chain
 * 4. Generating a ZK proof for withdrawal
 * 5. Querying pool state
 */

import algosdk from 'algosdk';
import crypto from 'crypto';
import fs from 'fs';
import { initMimc, mimcHash, randomScalar, scalarToBytes } from './packages/core/src/index.js';

// ─── Config ───

const ALGOD_URL = 'https://testnet-api.algonode.cloud';
const algod = new algosdk.Algodv2('', ALGOD_URL);

const deployment = JSON.parse(fs.readFileSync('./deployment-testnet.json', 'utf-8'));

function header(title: string) {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${'═'.repeat(60)}\n`);
}

function ok(msg: string) { console.log(`  ✅ ${msg}`); }
function info(msg: string) { console.log(`  ℹ️  ${msg}`); }
function warn(msg: string) { console.log(`  ⚠️  ${msg}`); }

// ─── 1. Check deployed contracts ───

async function checkContracts() {
  header('1. Checking Deployed Contracts on Testnet');

  for (const [name, data] of Object.entries(deployment.contracts) as any) {
    try {
      const appInfo = await algod.getApplicationByID(data.appId).do();
      const appAddr = algosdk.getApplicationAddress(data.appId);
      const acctInfo = await algod.accountInformation(String(appAddr)).do();
      const balance = Number(acctInfo.amount) / 1_000_000;

      ok(`${name} (app ${data.appId})`);
      info(`  Address: ${String(appAddr).slice(0, 12)}...`);
      info(`  Balance: ${balance.toFixed(6)} ALGO`);
    } catch (err: any) {
      warn(`${name} (app ${data.appId}): ${err.message}`);
    }
  }
}

// ─── 2. Check pool state ───

async function checkPoolState() {
  header('2. Privacy Pool State');

  const poolAppId = deployment.contracts.PrivacyPool.appId;
  const appInfo = await algod.getApplicationByID(poolAppId).do();
  const globalState = appInfo.params?.['global-state'] || [];

  const state: Record<string, any> = {};
  for (const kv of globalState) {
    const key = Buffer.from(kv.key, 'base64').toString('utf-8');
    if (kv.value.type === 2) {
      state[key] = kv.value.uint;
    } else {
      state[key] = Buffer.from(kv.value.bytes, 'base64').toString('hex');
    }
  }

  info(`Pool App ID:     ${poolAppId}`);
  info(`Denomination:    ${state['denom'] || 'unknown'} microALGO`);
  info(`Asset ID:        ${state['asset_id'] ?? 'ALGO'}`);
  info(`Next Leaf Index: ${state['next_idx'] ?? 0}`);
  info(`Root History:    ${state['rhi'] ?? 0} entries`);
  info(`Merkle Root:     ${state['root']?.slice(0, 40) ?? 'none'}...`);
  ok(`Pool has ${state['next_idx'] ?? 0} total deposits`);
}

// ─── 3. Check deployer account ───

async function checkAccount() {
  header('3. Deployer Account');

  const mnemonic = process.env.DEPLOYER_MNEMONIC;
  if (!mnemonic) {
    warn('No DEPLOYER_MNEMONIC set — skipping account check');
    info('Set it to interact with testnet:');
    info('  DEPLOYER_MNEMONIC="your 25 words" npx tsx test-testnet.ts');
    return null;
  }

  const account = algosdk.mnemonicToSecretKey(mnemonic);
  const acctInfo = await algod.accountInformation(account.addr).do();
  const balance = Number(acctInfo.amount) / 1_000_000;

  info(`Address: ${String(account.addr)}`);
  info(`Balance: ${balance.toFixed(6)} ALGO`);

  if (balance < 1.1) {
    warn(`Need at least 1.1 ALGO to deposit. Fund at:`);
    info(`https://bank.testnet.algorand.network/?account=${account.addr}`);
    return null;
  }

  ok(`Account ready (${balance.toFixed(2)} ALGO)`);
  return account;
}

// ─── 4. Create deposit commitment (local crypto) ───

async function createDepositDemo() {
  header('4. Creating Deposit Commitment (Local Crypto)');

  await initMimc();

  const secret = randomScalar();
  const nullifier = randomScalar();
  const commitment = mimcHash(secret, nullifier);
  const nullifierHash = mimcHash(nullifier, 0n);

  info('Generated random secret and nullifier');
  info(`Secret:         ${secret.toString().slice(0, 20)}...`);
  info(`Nullifier:      ${nullifier.toString().slice(0, 20)}...`);
  info(`Commitment:     ${commitment.toString().slice(0, 20)}...`);
  info(`Nullifier Hash: ${nullifierHash.toString().slice(0, 20)}...`);

  ok('Commitment created — this would be submitted on-chain');
  info('The secret and nullifier stay with YOU (never shared)');
  info('Only the commitment goes on-chain (hiding what you deposited)');

  return { secret, nullifier, commitment, nullifierHash };
}

// ─── 5. Live deposit to testnet ───

async function liveDeposit(account: algosdk.Account) {
  header('5. LIVE Deposit to Testnet Privacy Pool');

  await initMimc();

  // Create the commitment
  const secret = randomScalar();
  const nullifier = randomScalar();
  const commitment = mimcHash(secret, nullifier);
  const commitmentBytes = scalarToBytes(commitment);

  info('Commitment created locally');
  info(`Commitment: ${commitment.toString().slice(0, 20)}...`);

  const poolAppId = deployment.contracts.PrivacyPool.appId;
  const poolAddr = algosdk.getApplicationAddress(poolAppId);
  const params = await algod.getTransactionParams().do();

  // ARC-4 method selector for deposit(byte[])void
  const depositSelector = new Uint8Array(
    crypto.createHash('sha512-256').update('deposit(byte[])void').digest().slice(0, 4)
  );

  // ABI encode bytes: 2-byte length prefix + data
  const abiCommitment = new Uint8Array(2 + commitmentBytes.length);
  abiCommitment[0] = (commitmentBytes.length >> 8) & 0xff;
  abiCommitment[1] = commitmentBytes.length & 0xff;
  abiCommitment.set(commitmentBytes, 2);

  // Transaction 1: Pay 1 ALGO to pool
  const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: account.addr,
    receiver: String(poolAddr),
    amount: 1_000_000, // 1 ALGO
    suggestedParams: params,
  });

  // Transaction 2: App call deposit(commitment)
  const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: account.addr,
    appIndex: poolAppId,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [depositSelector, abiCommitment],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  // Group and sign
  const grouped = algosdk.assignGroupID([payTxn, appCallTxn]);
  const signedPay = grouped[0].signTxn(account.sk);
  const signedApp = grouped[1].signTxn(account.sk);

  info('Submitting deposit transaction to testnet...');

  try {
    const resp = await algod.sendRawTransaction([signedPay, signedApp]).do();
    const txId = (resp as any).txid ?? (resp as any).txId;
    info(`TX ID: ${txId}`);
    info('Waiting for confirmation...');

    const result = await algosdk.waitForConfirmation(algod, txId, 4);
    const confirmedRound = result.confirmedRound;

    ok(`Deposit confirmed in round ${confirmedRound}!`);
    info(`View on explorer: https://testnet.explorer.perawallet.app/tx/${txId}`);

    // Save the note
    const note = {
      secret: secret.toString(),
      nullifier: nullifier.toString(),
      commitment: commitment.toString(),
      denomination: '1000000',
      assetId: 0,
      timestamp: Date.now(),
      txId,
      round: Number(confirmedRound),
    };

    fs.writeFileSync('./last-deposit-note.json', JSON.stringify(note, null, 2));
    ok('Deposit note saved to last-deposit-note.json');
    warn('SAVE THIS FILE — losing it means losing your deposited ALGO!');

    return note;
  } catch (err: any) {
    warn(`Deposit failed: ${err.message}`);
    if (err.response?.body?.message) {
      info(`Detail: ${err.response.body.message}`);
    }
    return null;
  }
}

// ─── 6. Query all contracts ───

async function queryAllContracts() {
  header('6. Full Contract Status');

  const contracts = [
    { name: 'StealthRegistry', desc: 'Stealth address announcements' },
    { name: 'PrivacyPool', desc: 'Tornado-style deposit/withdraw' },
    { name: 'ShieldedPool', desc: 'Full UTXO privacy (2-in/2-out)' },
    { name: 'ConfidentialAsset', desc: 'Hidden amount transfers' },
  ];

  for (const c of contracts) {
    const appId = deployment.contracts[c.name].appId;
    try {
      const appInfo = await algod.getApplicationByID(appId).do();
      const globalState = appInfo.params?.['global-state'] || [];
      const stateCount = globalState.length;
      const appAddr = algosdk.getApplicationAddress(appId);
      const acctInfo = await algod.accountInformation(String(appAddr)).do();
      const balance = Number(acctInfo.amount) / 1_000_000;

      console.log(`  ${c.name} (${c.desc})`);
      console.log(`    App ID:      ${appId}`);
      console.log(`    Balance:     ${balance.toFixed(6)} ALGO`);
      console.log(`    State keys:  ${stateCount}`);
      console.log('');
    } catch (err: any) {
      console.log(`  ${c.name}: ERROR — ${err.message}\n`);
    }
  }
}

// ─── Main ───

async function main() {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║      Privacy SDK — Live Testnet Interaction               ║
║                                                           ║
║  Connected to: Algorand Testnet (algonode.cloud)          ║
╚═══════════════════════════════════════════════════════════╝`);

  try {
    await checkContracts();
    await checkPoolState();
    const account = await checkAccount();
    await createDepositDemo();

    if (account) {
      await liveDeposit(account);
    }

    await queryAllContracts();

    header('Done!');
    if (!account) {
      info('To do a live deposit, run with your mnemonic:');
      info('  DEPLOYER_MNEMONIC="..." npx tsx test-testnet.ts');
    }
  } catch (err: any) {
    console.error('\n❌ Error:', err.message);
    if (err.response?.body) console.error(err.response.body);
  }
}

main();
