import algosdk from 'algosdk';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const algod = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud');

function methodSelector(sig: string): Uint8Array {
  return new Uint8Array(crypto.createHash('sha512-256').update(sig).digest().slice(0, 4));
}

async function main() {
  const deployer = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC!);
  console.log('Deployer:', deployer.addr);

  // Read contract artifacts
  const approval = fs.readFileSync(path.join(__dirname, '../contracts/artifacts/PrivacyPool.approval.teal'), 'utf-8');
  const clear = fs.readFileSync(path.join(__dirname, '../contracts/artifacts/PrivacyPool.clear.teal'), 'utf-8');

  const approvalCompiled = await algod.compile(Buffer.from(approval)).do();
  const clearCompiled = await algod.compile(Buffer.from(clear)).do();
  const approvalProgram = new Uint8Array(Buffer.from(approvalCompiled.result, 'base64'));
  const clearProgram = new Uint8Array(Buffer.from(clearCompiled.result, 'base64'));

  // Create pool with denomination 100000 (0.1 ALGO)
  const params = await algod.getTransactionParams().do();
  const createTxn = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram, clearProgram,
    numGlobalInts: 8, numGlobalByteSlices: 8,
    numLocalInts: 0, numLocalByteSlices: 0,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      new Uint8Array(Buffer.from('createApplication(uint64,uint64)void'.slice(0, 4))),
      // Actually need ARC-4 selector
      methodSelector('createApplication(uint64,uint64)void'),
    ],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  // Hmm, the create method args depend on the contract. Let me use a simpler approach.
  // Actually, AlgoKit contracts usually use bare create + bootstrap pattern.
  // Let me look at the existing deploy script.

  // Use the existing deploy script pattern
  const createTxn2 = algosdk.makeApplicationCreateTxnFromObject({
    sender: deployer.addr,
    approvalProgram, clearProgram,
    numGlobalInts: 8, numGlobalByteSlices: 8,
    numLocalInts: 0, numLocalByteSlices: 0,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      methodSelector('createApplication(uint64,uint64)void'),
      algosdk.encodeUint64(100000),  // denomination
      algosdk.encodeUint64(0),       // asset_id (0 = ALGO)
    ],
    suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
  });

  const signedCreate = createTxn2.signTxn(deployer.sk);
  const createResp = await algod.sendRawTransaction(signedCreate).do();
  const createTxId = (createResp as any).txid ?? (createResp as any).txId;
  const createResult = await algosdk.waitForConfirmation(algod, createTxId, 4) as any;
  const appId = createResult.applicationIndex ?? createResult['application-index'];
  const appAddress = algosdk.getApplicationAddress(appId);
  console.log('Pool created! appId:', appId, 'address:', appAddress);

  // Fund pool
  const params2 = await algod.getTransactionParams().do();
  const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: deployer.addr, receiver: appAddress, amount: 1_000_000,
    suggestedParams: params2,
  });
  const signedFund = fundTxn.signTxn(deployer.sk);
  const fundResp = await algod.sendRawTransaction(signedFund).do();
  await algosdk.waitForConfirmation(algod, (fundResp as any).txid ?? (fundResp as any).txId, 4);
  console.log('Pool funded with 1 ALGO');

  // Set PLONK verifiers
  const WITHDRAW = 'YFJMO54UP57APAW27ABKKGBCVJH36D7R3LREGDQMUYOZTRWDFMEXRYFPUQ';
  const DEPOSIT = 'ZIZT5OX5DHYNYNNWNCPCDO34H36L46Y7V2QNKDC7AK6ITHOIHAT7ZWI7JQ';
  const PRIVATE_SEND = '7X45UWWAVQQEUCNPGLQ6SUBHKWNCJB7GCWMK3FPV3NERZIECCJOAZ44C4Q';

  const params3 = await algod.getTransactionParams().do();
  const setTxn = algosdk.makeApplicationCallTxnFromObject({
    sender: deployer.addr, appIndex: appId,
    onComplete: algosdk.OnApplicationComplete.NoOpOC,
    appArgs: [
      methodSelector('setPlonkVerifiers(address,address,address)void'),
      algosdk.decodeAddress(WITHDRAW).publicKey,
      algosdk.decodeAddress(DEPOSIT).publicKey,
      algosdk.decodeAddress(PRIVATE_SEND).publicKey,
    ],
    suggestedParams: { ...params3, fee: BigInt(2000), flatFee: true },
  });
  const signedSet = setTxn.signTxn(deployer.sk);
  const setResp = await algod.sendRawTransaction(signedSet).do();
  const setTxId = (setResp as any).txid ?? (setResp as any).txId;
  await algosdk.waitForConfirmation(algod, setTxId, 4);
  console.log('PLONK verifiers set! txId:', setTxId);

  console.log('\n=== CONFIG UPDATE ===');
  console.log("appId:", appId);
  console.log("appAddress:", appAddress);
  console.log("withdraw:", WITHDRAW);
}

main().catch(e => { console.error(e); process.exit(1); });
