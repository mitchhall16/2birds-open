#!/usr/bin/env node

/**
 * @algo-privacy/relayer — Relayer Node
 *
 * HTTP server that accepts withdrawal requests, verifies ZK proofs,
 * and submits transactions on behalf of users to preserve their IP privacy.
 *
 * The relayer:
 * 1. Receives a withdrawal proof + pool info from a user
 * 2. Verifies the proof locally (prevents spam/invalid submissions)
 * 3. Submits the atomic group (LogicSig verifier + app call) on-chain
 * 4. Pays transaction fees from its own account
 * 5. Deducts a small fee from the withdrawal amount (encoded in the proof)
 *
 * The relayer CANNOT steal funds because:
 * - The recipient is a public input in the ZK proof (can't be changed)
 * - The fee is a public input in the ZK proof (can't be inflated)
 * - The proof is verified by the on-chain LogicSig (can't be faked)
 */

import express from 'express';
import { RelayerServer } from './server.js';

const PORT = parseInt(process.env.RELAYER_PORT || '3001');
const ALGOD_URL = process.env.ALGOD_URL || 'https://testnet-api.algonode.cloud';
const ALGOD_TOKEN = process.env.ALGOD_TOKEN || '';
const RELAYER_MNEMONIC = process.env.RELAYER_MNEMONIC;
const FEE_PERCENT = parseInt(process.env.FEE_PERCENT || '50'); // basis points
const MIN_FEE = BigInt(process.env.MIN_FEE || '10000'); // minimum fee in base units
const VKEY_PATH = process.env.VKEY_PATH || ''; // path to verification key JSON

if (!RELAYER_MNEMONIC) {
  console.error('ERROR: RELAYER_MNEMONIC environment variable is required');
  console.error('This is the mnemonic for the relayer account that pays transaction fees.');
  process.exit(1);
}

const server = new RelayerServer({
  network: {
    algodUrl: ALGOD_URL,
    algodToken: ALGOD_TOKEN,
    network: ALGOD_URL.includes('mainnet') ? 'mainnet' : ALGOD_URL.includes('localhost') ? 'localnet' : 'testnet',
  },
  relayerMnemonic: RELAYER_MNEMONIC,
  feePercent: FEE_PERCENT,
  minFee: MIN_FEE,
  port: PORT,
  vkeyPaths: VKEY_PATH ? { default: VKEY_PATH } : undefined,
});

server.start();
