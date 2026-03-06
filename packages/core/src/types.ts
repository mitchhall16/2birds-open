/**
 * @2birds/core — Shared types for the Algorand Privacy SDK
 */

/** A point on the BN254 curve (affine coordinates) */
export interface BN254Point {
  x: bigint;
  y: bigint;
}

/** Compressed representation — x coordinate + sign bit */
export type CompressedPoint = Uint8Array; // 33 bytes

/** A scalar field element (mod r where r is BN254 scalar field order) */
export type Scalar = bigint;

/** 32-byte hash output */
export type Hash = Uint8Array;

/** Algorand 32-byte address (raw public key) */
export type AlgorandAddress = string;

/** Stealth meta-address: spending pubkey + viewing pubkey */
export interface StealthMetaAddress {
  spendingPubKey: BN254Point;
  viewingPubKey: BN254Point;
}

/** Stealth address keypair (derived for a specific payment) */
export interface StealthKeys {
  spendingKey: Scalar;
  viewingKey: Scalar;
}

/** Announcement published to the registry when a stealth payment is made */
export interface StealthAnnouncement {
  ephemeralPubKey: BN254Point;
  stealthAddress: AlgorandAddress;
  viewTag: number; // 1-byte optimization for scanning
  metadata: Uint8Array; // optional extra data (e.g., ASA ID)
  txnId: string;
  round: bigint;
}

/** Deposit note for privacy pool — MUST be saved securely by the user */
export interface DepositNote {
  secret: Scalar;
  nullifier: Scalar;
  commitment: Scalar;
  leafIndex: number;
  denomination: bigint;
  assetId: number; // 0 = ALGO
  timestamp: number;
}

/** Withdrawal proof for privacy pool */
export interface WithdrawProof {
  proof: Groth16Proof;
  publicInputs: {
    root: Scalar;
    nullifierHash: Scalar;
    recipient: AlgorandAddress;
    relayer: AlgorandAddress;
    fee: bigint;
  };
}

/** Groth16 proof (3 curve points) */
export interface Groth16Proof {
  pi_a: [bigint, bigint]; // G1 point
  pi_b: [[bigint, bigint], [bigint, bigint]]; // G2 point
  pi_c: [bigint, bigint]; // G1 point
}

/** PLONK proof */
export interface PlonkProof {
  proof: Uint8Array;
  publicInputs: bigint[];
}

/** Pedersen commitment: C = amount * G + blinding * H */
export interface PedersenCommitment {
  commitment: BN254Point;
  amount: bigint;
  blinding: Scalar;
}

/** Range proof (proves value in [0, 2^64)) */
export interface RangeProof {
  proof: Groth16Proof;
  commitment: BN254Point;
}

/** Shielded note (UTXO model) */
export interface ShieldedNote {
  amount: bigint;
  ownerPubKey: BN254Point;
  blinding: Scalar;
  nullifier: Scalar;
  commitment: Scalar;
  index: number;
  assetId: number;
  spent: boolean;
}

/** Shielded transfer — consumes old notes, creates new ones */
export interface ShieldedTransfer {
  inputNotes: ShieldedNote[];
  outputNotes: ShieldedNote[];
  proof: Groth16Proof;
  publicInputs: {
    oldRoot: Scalar;
    newRoot: Scalar;
    nullifierHashes: Scalar[];
    outputCommitments: Scalar[];
  };
}

/** Merkle tree path for proving membership */
export interface MerklePath {
  pathElements: Scalar[];
  pathIndices: number[]; // 0 = left, 1 = right
}

/** Privacy pool configuration */
export interface PoolConfig {
  appId: bigint;
  assetId: number; // 0 = ALGO
  denomination: bigint;
  merkleDepth: number;
  verifierLsig: Uint8Array;
}

/** Network configuration */
export interface NetworkConfig {
  algodUrl: string;
  algodToken: string;
  indexerUrl?: string;
  indexerToken?: string;
  network: 'mainnet' | 'testnet' | 'localnet';
}

/** Relayer configuration */
export interface RelayerConfig {
  url: string;
  feePercent: number; // basis points (e.g., 50 = 0.5%)
  minFee: bigint;
}
