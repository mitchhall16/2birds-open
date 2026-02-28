/**
 * @algo-privacy/relayer — HTTP Server
 */

import express, { type Request, type Response } from 'express';
import algosdk from 'algosdk';
import {
  type NetworkConfig,
  type WithdrawProof,
  type PoolConfig,
  createAlgodClient,
  scalarToBytes,
} from '@algo-privacy/core';
import { submitWithdrawal, verifyWithdrawProof } from '@algo-privacy/pool';

export interface RelayerServerConfig {
  network: NetworkConfig;
  relayerMnemonic: string;
  feePercent: number;
  minFee: bigint;
  port: number;
  supportedPools?: PoolConfig[];
  vkeyPaths?: Record<string, string>; // poolAppId -> vkey path
}

interface WithdrawRequest {
  proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
    root: string;
    nullifierHash: string;
    recipient: string;
    relayer: string;
    fee: string;
  };
  poolAppId: string;
  poolAssetId: number;
}

export class RelayerServer {
  private app: express.Application;
  private config: RelayerServerConfig;
  private relayerAccount: algosdk.Account;
  private algod: algosdk.Algodv2;
  private pendingWithdrawals = 0;
  private processedNullifiers = new Set<string>();

  constructor(config: RelayerServerConfig) {
    this.config = config;
    this.relayerAccount = algosdk.mnemonicToSecretKey(config.relayerMnemonic);
    this.algod = createAlgodClient(config.network);
    this.app = express();
    this.setupRoutes();
  }

  private setupRoutes(): void {
    this.app.use(express.json({ limit: '1mb' }));

    // CORS headers for browser clients
    this.app.use((_req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Headers', 'Content-Type');
      res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      next();
    });

    // Health check / status
    this.app.get('/status', this.handleStatus.bind(this));

    // Submit withdrawal
    this.app.post('/withdraw', this.handleWithdraw.bind(this));

    // Relayer info
    this.app.get('/info', this.handleInfo.bind(this));
  }

  private async handleStatus(_req: Request, res: Response): Promise<void> {
    try {
      // Check relayer account balance
      const accountInfo = await this.algod.accountInformation(this.relayerAccount.addr).do();
      const balance = accountInfo.amount;

      res.json({
        available: balance > 1_000_000, // Need at least 1 ALGO for fees
        feePercent: this.config.feePercent,
        minFee: this.config.minFee.toString(),
        supportedPools: (this.config.supportedPools || []).map(p => p.appId.toString()),
        pendingWithdrawals: this.pendingWithdrawals,
        relayerAddress: this.relayerAccount.addr,
        relayerBalance: balance,
        network: this.config.network.network,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  }

  private async handleWithdraw(req: Request, res: Response): Promise<void> {
    try {
      const body = req.body as WithdrawRequest;

      // 1. Parse and validate the proof
      const proof = this.parseProof(body);

      // 2. Check nullifier hasn't been processed by this relayer
      const nullifierKey = proof.publicInputs.nullifierHash.toString();
      if (this.processedNullifiers.has(nullifierKey)) {
        res.status(400).json({ error: 'Nullifier already processed' });
        return;
      }

      // 3. Verify the relayer address in the proof matches us
      // (Prevents proof reuse with a different relayer)
      if (String(proof.publicInputs.relayer) !== String(this.relayerAccount.addr)) {
        res.status(400).json({ error: 'Proof relayer address does not match this relayer' });
        return;
      }

      // 4. Verify the fee is acceptable
      const poolConfig = this.findPool(BigInt(body.poolAppId), body.poolAssetId);
      if (!poolConfig) {
        res.status(400).json({ error: 'Unsupported pool' });
        return;
      }

      const expectedFee = this.calculateFee(poolConfig.denomination);
      if (proof.publicInputs.fee < expectedFee) {
        res.status(400).json({
          error: `Fee too low. Minimum: ${expectedFee.toString()}, got: ${proof.publicInputs.fee.toString()}`,
        });
        return;
      }

      // 5. Verify the ZK proof locally (prevents wasting gas on invalid proofs)
      const vkeyPath = this.config.vkeyPaths?.[body.poolAppId];
      if (vkeyPath) {
        const valid = await verifyWithdrawProof(proof, vkeyPath);
        if (!valid) {
          res.status(400).json({ error: 'Invalid ZK proof' });
          return;
        }
      }

      // 6. Submit the withdrawal on-chain
      this.pendingWithdrawals++;
      try {
        const txId = await submitWithdrawal(
          proof,
          poolConfig,
          this.config.network,
          this.relayerAccount,
        );

        // Record nullifier
        this.processedNullifiers.add(nullifierKey);

        res.json({ success: true, txId });
      } finally {
        this.pendingWithdrawals--;
      }
    } catch (err: any) {
      console.error('Withdrawal error:', err);
      res.status(500).json({ error: err.message });
    }
  }

  private async handleInfo(_req: Request, res: Response): Promise<void> {
    res.json({
      name: 'algo-privacy-relayer',
      version: '0.1.0',
      network: this.config.network.network,
      feePercent: this.config.feePercent,
      minFee: this.config.minFee.toString(),
      relayerAddress: this.relayerAccount.addr,
      supportedPools: (this.config.supportedPools || []).map(p => ({
        appId: p.appId.toString(),
        assetId: p.assetId,
        denomination: p.denomination.toString(),
      })),
    });
  }

  private parseProof(body: WithdrawRequest): WithdrawProof {
    const p = body.proof;
    return {
      proof: {
        pi_a: [BigInt(p.pi_a[0]), BigInt(p.pi_a[1])],
        pi_b: [
          [BigInt(p.pi_b[0][0]), BigInt(p.pi_b[0][1])],
          [BigInt(p.pi_b[1][0]), BigInt(p.pi_b[1][1])],
        ],
        pi_c: [BigInt(p.pi_c[0]), BigInt(p.pi_c[1])],
      },
      publicInputs: {
        root: BigInt(p.root),
        nullifierHash: BigInt(p.nullifierHash),
        recipient: p.recipient,
        relayer: p.relayer,
        fee: BigInt(p.fee),
      },
    };
  }

  private findPool(appId: bigint, assetId: number): PoolConfig | undefined {
    return (this.config.supportedPools || []).find(
      p => p.appId === appId && p.assetId === assetId
    );
  }

  private calculateFee(denomination: bigint): bigint {
    const percentFee = (denomination * BigInt(this.config.feePercent)) / 10000n;
    return percentFee > this.config.minFee ? percentFee : this.config.minFee;
  }

  start(): void {
    this.app.listen(this.config.port, () => {
      console.log(`
╔═══════════════════════════════════════════════════╗
║         Algorand Privacy Relayer v0.1.0           ║
╠═══════════════════════════════════════════════════╣
║  Network:  ${this.config.network.network.padEnd(38)}║
║  Port:     ${this.config.port.toString().padEnd(38)}║
║  Address:  ${this.relayerAccount.addr.slice(0, 20)}...${' '.repeat(15)}║
║  Fee:      ${this.config.feePercent} bps (min ${this.config.minFee.toString()})${' '.repeat(Math.max(0, 26 - this.config.minFee.toString().length))}║
╚═══════════════════════════════════════════════════╝
      `);
      console.log('Relayer is ready to accept withdrawal requests.');
      console.log(`Status: http://localhost:${this.config.port}/status`);
    });
  }
}
