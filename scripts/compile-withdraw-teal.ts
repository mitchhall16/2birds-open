import algosdk from 'algosdk';
import fs from 'fs';
import path from 'path';

const algod = new algosdk.Algodv2('', 'https://testnet-api.algonode.cloud', '');

async function main() {
  const tealPath = path.join(__dirname, '..', 'circuits', 'build', 'withdraw_plonk_verifier.teal');
  const tealSource = fs.readFileSync(tealPath, 'utf-8');

  console.log(`Compiling ${tealPath}...`);
  console.log(`TEAL source: ${tealSource.length} chars, ${tealSource.split('\n').length} lines`);

  const compiled = await algod.compile(Buffer.from(tealSource)).do();
  const program = new Uint8Array(Buffer.from(compiled.result, 'base64'));
  const lsig = new algosdk.LogicSigAccount(program);
  const addr = String(lsig.address());

  console.log(`\nCompiled program: ${program.length} bytes`);
  console.log(`Base64: ${compiled.result.length} chars`);
  console.log(`LogicSig address: ${addr}`);

  // Save compiled base64
  const outPath = '/tmp/withdraw_plonk_compiled_fixed.b64';
  fs.writeFileSync(outPath, compiled.result);
  console.log(`Saved to ${outPath}`);
}

main().catch(e => { console.error(e); process.exit(1); });
