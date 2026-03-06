/**
 * CLI utility functions — config loading, account management
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import algosdk from 'algosdk';
import type { NetworkConfig } from '@2birds/core';

/** Default config directory */
const CONFIG_DIR = path.join(os.homedir(), '.algo-privacy');

/** Get config file path */
export function getConfigPath(): string {
  return path.join(CONFIG_DIR, 'config.json');
}

/** Get wallet file path */
export function getWalletPath(): string {
  return path.join(CONFIG_DIR, 'wallet.json');
}

/** Default configuration */
export const defaultConfig = {
  network: {
    algodUrl: 'https://testnet-api.algonode.cloud',
    algodToken: '',
    indexerUrl: 'https://testnet-idx.algonode.cloud',
    indexerToken: '',
    network: 'testnet' as const,
  },
  stealthRegistryAppId: '0',
  shieldedPoolAppId: '0',
  confidentialAssetAppId: '0',
  pools: [] as Array<{
    appId: string;
    assetId: number;
    denomination: string;
  }>,
  circuitPaths: {
    withdrawWasm: path.join(CONFIG_DIR, 'circuits', 'withdraw_js', 'withdraw.wasm'),
    withdrawZkey: path.join(CONFIG_DIR, 'circuits', 'withdraw_final.zkey'),
    withdrawVkey: path.join(CONFIG_DIR, 'circuits', 'withdraw_vkey.json'),
    rangeProofWasm: path.join(CONFIG_DIR, 'circuits', 'range_proof_js', 'range_proof.wasm'),
    rangeProofZkey: path.join(CONFIG_DIR, 'circuits', 'range_proof_final.zkey'),
    shieldedWasm: path.join(CONFIG_DIR, 'circuits', 'shielded_transfer_js', 'shielded_transfer.wasm'),
    shieldedZkey: path.join(CONFIG_DIR, 'circuits', 'shielded_transfer_final.zkey'),
  },
  accountMnemonic: '', // Set via environment variable ALGO_PRIVACY_MNEMONIC
};

/** Load configuration */
export function loadConfig(): typeof defaultConfig {
  const configPath = getConfigPath();
  if (!fs.existsSync(configPath)) {
    console.error('No configuration found. Run: algo-privacy config init');
    process.exit(1);
  }

  const data = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  return { ...defaultConfig, ...data };
}

/** Load Algorand account from mnemonic (env var or config) */
export async function loadAccount(): Promise<algosdk.Account> {
  const mnemonic = process.env.ALGO_PRIVACY_MNEMONIC || loadConfig().accountMnemonic;
  if (!mnemonic) {
    console.error('No account configured. Set ALGO_PRIVACY_MNEMONIC environment variable.');
    process.exit(1);
  }

  return algosdk.mnemonicToSecretKey(mnemonic);
}
