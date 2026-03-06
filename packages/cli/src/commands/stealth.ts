/**
 * CLI commands for stealth addresses
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { generateStealthKeys, encodeMetaAddress, decodeMetaAddress } from '@2birds/stealth';
import { loadConfig, loadAccount } from '../utils.js';

export function stealthCommands(): Command {
  const stealth = new Command('stealth')
    .description('Stealth address operations — receiver privacy');

  stealth
    .command('keygen')
    .description('Generate a new stealth keypair (spending + viewing keys)')
    .action(async () => {
      const keys = generateStealthKeys();
      const encoded = encodeMetaAddress(keys.metaAddress);

      console.log(chalk.green('Stealth keypair generated!\n'));
      console.log(chalk.bold('Meta-address (share this publicly):'));
      console.log(`  ${encoded}\n`);
      console.log(chalk.bold('Spending key (KEEP SECRET):'));
      console.log(`  ${keys.spendingKey.toString()}\n`);
      console.log(chalk.bold('Viewing key (for optional disclosure):'));
      console.log(`  ${keys.viewingKey.toString()}\n`);
      console.log(chalk.yellow('WARNING: Save these keys securely. Losing the spending key means losing access to received funds.'));
    });

  stealth
    .command('register')
    .description('Register your meta-address on-chain')
    .argument('<label>', 'Label to register under (e.g., your address or name)')
    .option('-m, --meta-address <addr>', 'Meta-address to register')
    .action(async (label: string, opts: { metaAddress?: string }) => {
      if (!opts.metaAddress) {
        console.log(chalk.red('Error: --meta-address is required'));
        console.log('Generate one with: algo-privacy stealth keygen');
        return;
      }

      try {
        const config = loadConfig();
        const account = await loadAccount();
        const { StealthRegistry } = await import('@2birds/stealth');

        const registry = new StealthRegistry({
          appId: BigInt(config.stealthRegistryAppId),
          network: config.network,
        });

        const meta = decodeMetaAddress(opts.metaAddress);
        const txId = await registry.registerMetaAddress(account, meta, label);

        console.log(chalk.green(`Meta-address registered for "${label}"!`));
        console.log(`Transaction: ${txId}`);
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  stealth
    .command('send')
    .description('Send funds to a stealth address')
    .argument('<label>', 'Recipient label or meta-address')
    .argument('<amount>', 'Amount to send (in base units)')
    .option('-a, --asset <id>', 'ASA ID (0 for ALGO)', '0')
    .action(async (label: string, amount: string, opts: { asset: string }) => {
      try {
        const config = loadConfig();
        const account = await loadAccount();
        const { StealthRegistry } = await import('@2birds/stealth');

        const registry = new StealthRegistry({
          appId: BigInt(config.stealthRegistryAppId),
          network: config.network,
        });

        let meta;
        if (label.startsWith('st:algo:')) {
          meta = decodeMetaAddress(label);
        } else {
          meta = await registry.resolve(label);
          if (!meta) {
            console.log(chalk.red(`No meta-address found for "${label}"`));
            return;
          }
        }

        const result = await registry.stealthSend(
          account,
          meta,
          BigInt(amount),
          parseInt(opts.asset),
        );

        console.log(chalk.green('Stealth payment sent!'));
        console.log(`Stealth address: ${result.stealthAddress}`);
        console.log(`Transaction: ${result.txId}`);
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  stealth
    .command('scan')
    .description('Scan for incoming stealth payments')
    .option('-s, --spending-key <key>', 'Spending private key')
    .option('-v, --viewing-key <key>', 'Viewing private key')
    .option('--from-round <round>', 'Start scanning from this round', '0')
    .action(async (opts: { spendingKey?: string; viewingKey?: string; fromRound: string }) => {
      if (!opts.spendingKey || !opts.viewingKey) {
        console.log(chalk.red('Error: --spending-key and --viewing-key are required'));
        return;
      }

      try {
        const config = loadConfig();
        const { StealthScanner } = await import('@2birds/stealth');

        const scanner = new StealthScanner({
          registry: {
            appId: BigInt(config.stealthRegistryAppId),
            network: config.network,
          },
          keys: {
            spendingKey: BigInt(opts.spendingKey),
            viewingKey: BigInt(opts.viewingKey),
          },
          startRound: BigInt(opts.fromRound),
        });

        console.log(chalk.blue('Scanning for stealth payments...'));
        const payments = await scanner.scanAll(BigInt(opts.fromRound));

        if (payments.length === 0) {
          console.log('No payments found.');
        } else {
          console.log(chalk.green(`Found ${payments.length} payment(s):\n`));
          for (const p of payments) {
            console.log(`  Address: ${p.stealthAddress}`);
            console.log(`  Stealth key: ${p.stealthPrivKey.toString()}`);
            console.log('');
          }
        }
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  return stealth;
}
