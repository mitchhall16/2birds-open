/**
 * @2birds/pool — Relayer Client
 *
 * Submits withdrawals through a relayer node to preserve IP privacy.
 * The relayer pays transaction fees and deducts a small fee from the withdrawal.
 */

import {
  type WithdrawProof,
  type PoolConfig,
  type AlgorandAddress,
  type RelayerConfig,
  retry,
} from '@2birds/core';

/** Response from the relayer after submitting a withdrawal */
export interface RelayerResponse {
  success: boolean;
  txId?: string;
  error?: string;
}

/** Status of a relayer */
export interface RelayerStatus {
  url: string;
  available: boolean;
  feePercent: number;
  minFee: bigint;
  supportedPools: bigint[]; // App IDs
  pendingWithdrawals: number;
}

/**
 * RelayerClient — submits withdrawals through a relayer for IP privacy.
 */
export class RelayerClient {
  private config: RelayerConfig;

  constructor(config: RelayerConfig) {
    this.config = config;
  }

  /** Check relayer status and availability */
  async getStatus(): Promise<RelayerStatus> {
    const response = await fetch(`${this.config.url}/status`);
    if (!response.ok) {
      throw new Error(`Relayer status check failed: ${response.status}`);
    }
    const data = await response.json() as any;
    return {
      url: this.config.url,
      available: data.available,
      feePercent: data.feePercent,
      minFee: BigInt(data.minFee),
      supportedPools: (data.supportedPools || []).map((id: string) => BigInt(id)),
      pendingWithdrawals: data.pendingWithdrawals || 0,
    };
  }

  /**
   * Submit a withdrawal through the relayer.
   *
   * The relayer will:
   * 1. Verify the proof locally
   * 2. Submit the atomic group (LogicSig verifier + app call)
   * 3. Pay the transaction fees
   * 4. Deduct the relayer fee from the withdrawal amount
   */
  async submitWithdrawal(
    proof: WithdrawProof,
    pool: PoolConfig,
  ): Promise<RelayerResponse> {
    return retry(async () => {
      const response = await fetch(`${this.config.url}/withdraw`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proof: serializeProof(proof),
          poolAppId: pool.appId.toString(),
          poolAssetId: pool.assetId,
        }),
      });

      const data = await response.json() as any;

      if (!response.ok) {
        throw new Error(data.error || `Relayer error: ${response.status}`);
      }

      return {
        success: true,
        txId: data.txId,
      };
    }, 2, 2000);
  }

  /** Calculate the relayer fee for a given denomination */
  calculateFee(denomination: bigint): bigint {
    const percentFee = (denomination * BigInt(this.config.feePercent)) / 10000n;
    return percentFee > this.config.minFee ? percentFee : this.config.minFee;
  }
}

/** Serialize a proof for JSON transport */
function serializeProof(proof: WithdrawProof): object {
  return {
    pi_a: proof.proof.pi_a.map(n => n.toString()),
    pi_b: proof.proof.pi_b.map(row => row.map(n => n.toString())),
    pi_c: proof.proof.pi_c.map(n => n.toString()),
    root: proof.publicInputs.root.toString(),
    nullifierHash: proof.publicInputs.nullifierHash.toString(),
    recipient: proof.publicInputs.recipient,
    relayer: proof.publicInputs.relayer,
    fee: proof.publicInputs.fee.toString(),
  };
}

/**
 * Find the best available relayer from a list.
 * Picks the cheapest one that supports the target pool.
 */
export async function findBestRelayer(
  relayerUrls: string[],
  poolAppId: bigint,
): Promise<RelayerClient | null> {
  const candidates: { client: RelayerClient; fee: number }[] = [];

  for (const url of relayerUrls) {
    try {
      const client = new RelayerClient({ url, feePercent: 0, minFee: 0n });
      const status = await client.getStatus();
      if (status.available && status.supportedPools.includes(poolAppId)) {
        candidates.push({
          client: new RelayerClient({ url, feePercent: status.feePercent, minFee: status.minFee }),
          fee: status.feePercent,
        });
      }
    } catch {
      // Skip unavailable relayers
    }
  }

  if (candidates.length === 0) return null;

  // Sort by fee (ascending) and return cheapest
  candidates.sort((a, b) => a.fee - b.fee);
  return candidates[0].client;
}
