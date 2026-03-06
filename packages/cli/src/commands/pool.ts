/**
 * CLI commands for privacy pool operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { createDeposit, submitDeposit, encodeDepositNote } from '@2birds/pool';
import { deserializeNote } from '@2birds/core';
import { loadConfig, loadAccount } from '../utils.js';

export function poolCommands(): Command {
  const pool = new Command('pool')
    .description('Privacy pool operations — break sender/receiver link');

  pool
    .command('deposit')
    .description('Deposit into a privacy pool')
    .argument('<amount>', 'Deposit amount in base units')
    .option('-a, --asset <id>', 'ASA ID (0 for ALGO)', '0')
    .action(async (amount: string, opts: { asset: string }) => {
      try {
        const config = loadConfig();
        const account = await loadAccount();
        const assetId = parseInt(opts.asset);
        const denomination = BigInt(amount);

        // Find matching pool config
        const poolConfig = config.pools.find(
          (p: any) => p.denomination === denomination.toString() && p.assetId === assetId
        );
        if (!poolConfig) {
          console.log(chalk.red(`No pool configured for denomination ${amount} asset ${assetId}`));
          console.log('Available pools:');
          for (const p of config.pools) {
            console.log(`  ${p.denomination} (asset ${p.assetId}) - app ${p.appId}`);
          }
          return;
        }

        console.log(chalk.blue('Creating deposit commitment...'));
        const note = createDeposit(denomination, assetId);

        console.log(chalk.blue('Submitting deposit transaction...'));
        const confirmedNote = await submitDeposit(
          note,
          {
            appId: BigInt(poolConfig.appId),
            assetId: poolConfig.assetId,
            denomination: BigInt(poolConfig.denomination),
            merkleDepth: 20,
            verifierLsig: new Uint8Array(0),
          },
          account,
          config.network,
        );

        const encodedNote = encodeDepositNote(confirmedNote);

        console.log(chalk.green('\nDeposit successful!\n'));
        console.log(chalk.bold('Deposit note (SAVE THIS — losing it means losing funds):'));
        console.log(chalk.yellow(encodedNote));
        console.log(`\nLeaf index: ${confirmedNote.leafIndex}`);
        console.log(`Denomination: ${denomination} (asset ${assetId})`);
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  pool
    .command('withdraw')
    .description('Withdraw from a privacy pool')
    .argument('<note>', 'Deposit note (JSON string)')
    .argument('<recipient>', 'Recipient Algorand address')
    .option('-r, --relayer <url>', 'Relayer URL (for IP privacy)')
    .option('-f, --fee <amount>', 'Relayer fee', '0')
    .action(async (noteJson: string, recipient: string, opts: { relayer?: string; fee: string }) => {
      try {
        const config = loadConfig();
        const note = deserializeNote(noteJson);

        console.log(chalk.blue('Building Merkle tree state...'));
        const { IncrementalMerkleTree } = await import('@2birds/pool');
        const tree = new IncrementalMerkleTree(20);
        // In production, tree would be synced from on-chain state

        console.log(chalk.blue('Generating ZK proof (this may take 10-30 seconds)...'));
        const { generateWithdrawProof, submitWithdrawal } = await import('@2birds/pool');

        const relayerAddr = opts.relayer
          ? 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ' // placeholder
          : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ';

        const proof = await generateWithdrawProof(
          note as any,
          tree,
          recipient,
          relayerAddr,
          BigInt(opts.fee),
          config.circuitPaths.withdrawWasm,
          config.circuitPaths.withdrawZkey,
        );

        if (opts.relayer) {
          console.log(chalk.blue('Submitting via relayer for IP privacy...'));
          const { RelayerClient } = await import('@2birds/pool');
          const relayer = new RelayerClient({
            url: opts.relayer,
            feePercent: 0,
            minFee: 0n,
          });
          const result = await relayer.submitWithdrawal(proof, {
            appId: BigInt(config.pools[0].appId),
            assetId: note.assetId,
            denomination: note.denomination,
            merkleDepth: 20,
            verifierLsig: new Uint8Array(0),
          });
          console.log(chalk.green(`Withdrawal successful! TX: ${result.txId}`));
        } else {
          const account = await loadAccount();
          const txId = await submitWithdrawal(
            proof,
            {
              appId: BigInt(config.pools[0].appId),
              assetId: note.assetId,
              denomination: note.denomination,
              merkleDepth: 20,
              verifierLsig: new Uint8Array(0),
            },
            config.network,
            account,
          );
          console.log(chalk.green(`Withdrawal successful! TX: ${txId}`));
        }
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  pool
    .command('info')
    .description('Show privacy pool information')
    .option('-a, --asset <id>', 'ASA ID filter', '0')
    .action(async (opts: { asset: string }) => {
      const config = loadConfig();
      const pools = config.pools.filter((p: any) => p.assetId === parseInt(opts.asset));

      if (pools.length === 0) {
        console.log(chalk.yellow('No pools configured for this asset.'));
        return;
      }

      console.log(chalk.bold('Privacy Pools:\n'));
      for (const p of pools) {
        console.log(`  Denomination: ${p.denomination}`);
        console.log(`  Asset ID:     ${p.assetId}`);
        console.log(`  App ID:       ${p.appId}`);
        console.log('');
      }
    });

  return pool;
}
