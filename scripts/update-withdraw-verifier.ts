#!/usr/bin/env npx tsx
/**
 * Update only the withdraw PLONK verifier address on pool contracts.
 * Keeps deposit and privateSend addresses unchanged.
 */
import algosdk from 'algosdk';
import crypto from 'crypto';
import 'dotenv/config';

const ALGOD_URL = 'https://testnet-api.algonode.cloud';
const algod = new algosdk.Algodv2('', ALGOD_URL);

// Current verifier addresses (deposit and privateSend unchanged)
const DEPOSIT_ADDR = 'ZIZT5OX5DHYNYNNWNCPCDO34H36L46Y7V2QNKDC7AK6ITHOIHAT7ZWI7JQ';
const PRIVATE_SEND_ADDR = '7X45UWWAVQQEUCNPGLQ6SUBHKWNCJB7GCWMK3FPV3NERZIECCJOAZ44C4Q';
// NEW withdraw verifier (fixed emitModMul squaring bug)
const NEW_WITHDRAW_ADDR = 'XXN3WO7QABM7X65RMPD4WXFWXOVUICQCBP3OZ7DYXVON6HNGIZSAL55M5Y';

// Pool contracts to update
const POOLS = [
  { label: '0.1 ALGO', appId: 756770804 },
  { label: '0.5 ALGO', appId: 756862750 },
  { label: '1.0 ALGO', appId: 756862851 },
];

function methodSelector(sig: string): Uint8Array {
  return new Uint8Array(crypto.createHash('sha512-256').update(sig).digest().slice(0, 4));
}

async function main() {
  if (!process.env.DEPLOYER_MNEMONIC) {
    console.error('DEPLOYER_MNEMONIC not set in .env');
    process.exit(1);
  }

  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC);
  console.log(`Deployer: ${deployer.addr}`);
  console.log(`\nNew withdraw verifier: ${NEW_WITHDRAW_ADDR}`);
  console.log(`Deposit verifier:     ${DEPOSIT_ADDR} (unchanged)`);
  console.log(`PrivateSend verifier: ${PRIVATE_SEND_ADDR} (unchanged)`);

  const selector = methodSelector('setPlonkVerifiers(address,address,address)void');

  for (const pool of POOLS) {
    console.log(`\nUpdating ${pool.label} pool (app ${pool.appId})...`);

    const params = await algod.getTransactionParams().do();
    const txn = algosdk.makeApplicationCallTxnFromObject({
      sender: deployer.addr,
      appIndex: pool.appId,
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        selector,
        algosdk.decodeAddress(NEW_WITHDRAW_ADDR).publicKey,
        algosdk.decodeAddress(DEPOSIT_ADDR).publicKey,
        algosdk.decodeAddress(PRIVATE_SEND_ADDR).publicKey,
      ],
      suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
    });

    const signed = txn.signTxn(deployer.sk);
    const resp = await algod.sendRawTransaction(signed).do();
    const txId = (resp as any).txid ?? (resp as any).txId;
    await algosdk.waitForConfirmation(algod, txId, 4);
    console.log(`  Confirmed! tx: ${txId}`);
  }

  console.log('\nDone! Withdraw PLONK verifier updated on all pools.');
}

main().catch(e => { console.error('Failed:', e); process.exit(1); });
