/**
 * CLI commands for shielded wallet operations
 */

import { Command } from 'commander';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';
import { loadConfig, loadAccount, getWalletPath } from '../utils.js';

export function walletCommands(): Command {
  const wallet = new Command('wallet')
    .description('Shielded wallet operations — full privacy');

  wallet
    .command('create')
    .description('Create a new shielded wallet')
    .option('-o, --output <file>', 'Output file for wallet state')
    .action(async (opts: { output?: string }) => {
      try {
        const { ShieldedWallet } = await import('@2birds/shielded');
        const wallet = new ShieldedWallet();

        const outPath = opts.output || getWalletPath();
        const state = wallet.serialize();

        // Ensure directory exists
        const dir = path.dirname(outPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        fs.writeFileSync(outPath, state, 'utf-8');

        console.log(chalk.green('Shielded wallet created!\n'));
        console.log(chalk.bold('Public key (share for receiving):'));
        console.log(`  x: ${wallet.publicKey.x.toString()}`);
        console.log(`  y: ${wallet.publicKey.y.toString()}\n`);
        console.log(`Wallet saved to: ${outPath}`);
        console.log(chalk.yellow('\nWARNING: This file contains your spending key. Encrypt it!'));
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  wallet
    .command('balance')
    .description('Show shielded wallet balance')
    .option('-a, --asset <id>', 'ASA ID (0 for ALGO)', '0')
    .option('-w, --wallet <file>', 'Wallet file path')
    .action(async (opts: { asset: string; wallet?: string }) => {
      try {
        const walletPath = opts.wallet || getWalletPath();
        if (!fs.existsSync(walletPath)) {
          console.log(chalk.red('No wallet found. Create one with: algo-privacy wallet create'));
          return;
        }

        const { ShieldedWallet } = await import('@2birds/shielded');
        const walletData = fs.readFileSync(walletPath, 'utf-8');
        const w = ShieldedWallet.deserialize(walletData);
        const assetId = parseInt(opts.asset);

        const balance = w.getBalance(assetId);
        const notes = w.getUnspentNotes(assetId);

        console.log(chalk.bold('Shielded Balance:\n'));
        console.log(`  Asset: ${assetId === 0 ? 'ALGO' : `ASA #${assetId}`}`);
        console.log(`  Balance: ${balance.toString()} base units`);
        console.log(`  Unspent notes: ${notes.length}\n`);

        if (notes.length > 0) {
          console.log('  Notes:');
          for (const note of notes) {
            console.log(`    [${note.index}] ${note.amount.toString()} (${note.spent ? 'spent' : 'unspent'})`);
          }
        }
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  wallet
    .command('send')
    .description('Send a shielded transfer')
    .argument('<amount>', 'Amount to send (base units)')
    .argument('<pubkey-x>', 'Recipient public key x-coordinate')
    .argument('<pubkey-y>', 'Recipient public key y-coordinate')
    .option('-a, --asset <id>', 'ASA ID (0 for ALGO)', '0')
    .option('-w, --wallet <file>', 'Wallet file path')
    .action(async (amount: string, pubkeyX: string, pubkeyY: string, opts: { asset: string; wallet?: string }) => {
      try {
        const config = loadConfig();
        const account = await loadAccount();
        const walletPath = opts.wallet || getWalletPath();

        const { ShieldedWallet } = await import('@2birds/shielded');
        const walletData = fs.readFileSync(walletPath, 'utf-8');
        const w = ShieldedWallet.deserialize(walletData);

        const recipientPubKey = { x: BigInt(pubkeyX), y: BigInt(pubkeyY) };

        console.log(chalk.blue('Generating shielded transfer proof (10-30 seconds)...'));

        const poolConfig = {
          appId: BigInt(config.shieldedPoolAppId),
          assetId: parseInt(opts.asset),
          network: config.network,
          verifierLsig: new Uint8Array(0), // loaded from config in production
        };

        const txId = await w.send(
          BigInt(amount),
          recipientPubKey,
          poolConfig,
          account,
          config.circuitPaths.shieldedWasm,
          config.circuitPaths.shieldedZkey,
        );

        // Save updated wallet state
        fs.writeFileSync(walletPath, w.serialize(), 'utf-8');

        console.log(chalk.green(`Shielded transfer sent! TX: ${txId}`));
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  wallet
    .command('consolidate')
    .description('Merge small notes into larger ones')
    .option('-a, --asset <id>', 'ASA ID (0 for ALGO)', '0')
    .option('-w, --wallet <file>', 'Wallet file path')
    .action(async (opts: { asset: string; wallet?: string }) => {
      try {
        const config = loadConfig();
        const account = await loadAccount();
        const walletPath = opts.wallet || getWalletPath();

        const { ShieldedWallet } = await import('@2birds/shielded');
        const walletData = fs.readFileSync(walletPath, 'utf-8');
        const w = ShieldedWallet.deserialize(walletData);

        const poolConfig = {
          appId: BigInt(config.shieldedPoolAppId),
          assetId: parseInt(opts.asset),
          network: config.network,
          verifierLsig: new Uint8Array(0),
        };

        console.log(chalk.blue('Consolidating notes...'));
        const txId = await w.consolidate(
          parseInt(opts.asset),
          poolConfig,
          account,
          config.circuitPaths.shieldedWasm,
          config.circuitPaths.shieldedZkey,
        );

        fs.writeFileSync(walletPath, w.serialize(), 'utf-8');
        console.log(chalk.green(`Notes consolidated! TX: ${txId}`));
      } catch (err: any) {
        console.log(chalk.red(`Error: ${err.message}`));
      }
    });

  wallet
    .command('export')
    .description('Export wallet state')
    .option('-w, --wallet <file>', 'Wallet file path')
    .option('-o, --output <file>', 'Output file')
    .action(async (opts: { wallet?: string; output?: string }) => {
      const walletPath = opts.wallet || getWalletPath();
      if (!fs.existsSync(walletPath)) {
        console.log(chalk.red('No wallet found.'));
        return;
      }

      const data = fs.readFileSync(walletPath, 'utf-8');
      const outPath = opts.output || `wallet-export-${Date.now()}.json`;
      fs.writeFileSync(outPath, data, 'utf-8');
      console.log(chalk.green(`Wallet exported to: ${outPath}`));
      console.log(chalk.yellow('WARNING: This file contains your private keys. Handle with care!'));
    });

  wallet
    .command('import')
    .description('Import wallet state from file')
    .argument('<file>', 'Wallet export file')
    .option('-w, --wallet <file>', 'Destination wallet file path')
    .action(async (file: string, opts: { wallet?: string }) => {
      if (!fs.existsSync(file)) {
        console.log(chalk.red(`File not found: ${file}`));
        return;
      }

      const data = fs.readFileSync(file, 'utf-8');

      // Validate it's a valid wallet
      try {
        const { ShieldedWallet } = await import('@2birds/shielded');
        ShieldedWallet.deserialize(data);
      } catch {
        console.log(chalk.red('Invalid wallet file.'));
        return;
      }

      const walletPath = opts.wallet || getWalletPath();
      const dir = path.dirname(walletPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      fs.writeFileSync(walletPath, data, 'utf-8');
      console.log(chalk.green(`Wallet imported to: ${walletPath}`));
    });

  return wallet;
}
