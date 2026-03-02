import algosdk from 'algosdk';

async function main() {
  const algod = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud');
  const acct = algosdk.mnemonicToSecretKey(process.env.DEPLOYER_MNEMONIC!);
  const poolAddr = 'FMRABDCQUIZAVWTKIYAZEQZUWC6546MZZTOI2A3YG34PVY3SXBZH4NHQNY';
  const params = await algod.getTransactionParams().do();
  const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: acct.addr,
    receiver: poolAddr,
    amount: 500_000,
    suggestedParams: params,
  });
  const signed = txn.signTxn(acct.sk);
  const resp = await algod.sendRawTransaction(signed).do();
  const txId = (resp as any).txid ?? (resp as any).txId;
  await algosdk.waitForConfirmation(algod, txId, 4);
  console.log('Funded pool with 0.5 ALGO. TX: ' + txId);
}
main();
