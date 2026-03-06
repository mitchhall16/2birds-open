#!/usr/bin/env node

/**
 * @2birds/cli — Command-line tool for Algorand privacy operations
 *
 * Usage:
 *   algo-privacy stealth keygen              Generate stealth keypair
 *   algo-privacy stealth register <label>    Register meta-address on-chain
 *   algo-privacy stealth send <label> <amt>  Send to a stealth address
 *   algo-privacy stealth scan                Scan for incoming payments
 *
 *   algo-privacy pool deposit <amt> [--asset <id>]   Deposit into privacy pool
 *   algo-privacy pool withdraw <note> <addr>         Withdraw from privacy pool
 *   algo-privacy pool balance                        Show pool deposit count
 *
 *   algo-privacy shield <amt> [--asset <id>]         Shield (deposit) funds
 *   algo-privacy transfer <amt> <pubkey>             Confidential transfer
 *   algo-privacy unshield <amt>                      Unshield (withdraw) funds
 *
 *   algo-privacy wallet create                       Create shielded wallet
 *   algo-privacy wallet balance                      Show shielded balance
 *   algo-privacy wallet send <amt> <pubkey>          Send shielded transfer
 *   algo-privacy wallet consolidate                  Merge small notes
 *   algo-privacy wallet export                       Export wallet state
 *   algo-privacy wallet import <file>                Import wallet state
 */

import { Command } from 'commander';
import { stealthCommands } from './commands/stealth.js';
import { poolCommands } from './commands/pool.js';
import { walletCommands } from './commands/wallet.js';
import { configCommands } from './commands/config.js';

const program = new Command();

program
  .name('algo-privacy')
  .description('Algorand Privacy SDK — CLI tool for private transactions')
  .version('0.1.0');

// Register command groups
program.addCommand(stealthCommands());
program.addCommand(poolCommands());
program.addCommand(walletCommands());
program.addCommand(configCommands());

program.parse();
