/**
 * @2birds/shielded — Shielded Wallet
 *
 * Manages the user's shielded notes (UTXOs), tracks balances,
 * selects notes for spending, and synchronizes with on-chain state.
 */

import {
  type ShieldedNote,
  type Scalar,
  type BN254Point,
  type NetworkConfig,
  randomScalar,
  derivePubKey,
  createAlgodClient,
} from '@2birds/core';
import { IncrementalMerkleTree } from '@2birds/pool';
import {
  createNote,
  serializeShieldedNote,
  deserializeShieldedNote,
  computeNullifierHash,
} from './note.js';
import { shieldedTransfer, submitShieldedTransfer, type ShieldedPoolConfig } from './transfer.js';

/** Wallet state that must be persisted (encrypted!) */
export interface WalletState {
  spendingKey: Scalar;
  viewingKey: Scalar;
  notes: ShieldedNote[];
  treeState: string; // serialized Merkle tree
  lastSyncedRound: bigint;
}

/**
 * ShieldedWallet — manages shielded notes and facilitates transfers.
 */
export class ShieldedWallet {
  private spendingKey: Scalar;
  private viewingKey: Scalar;
  private spendingPubKey: BN254Point;
  private notes: ShieldedNote[] = [];
  private tree: IncrementalMerkleTree;
  private lastSyncedRound: bigint = 0n;

  private constructor(spendingKey: Scalar, viewingKey: Scalar, tree: IncrementalMerkleTree) {
    this.spendingKey = spendingKey;
    this.viewingKey = viewingKey;
    this.spendingPubKey = derivePubKey(this.spendingKey);
    this.tree = tree;
  }

  static async create(spendingKey?: Scalar, viewingKey?: Scalar): Promise<ShieldedWallet> {
    const tree = await IncrementalMerkleTree.create(20);
    return new ShieldedWallet(spendingKey ?? randomScalar(), viewingKey ?? randomScalar(), tree);
  }

  /** Get the wallet's public key (for receiving) */
  get publicKey(): BN254Point {
    return this.spendingPubKey;
  }

  /** Get the viewing key (for optional disclosure / compliance) */
  get viewKey(): Scalar {
    return this.viewingKey;
  }

  /**
   * Get total shielded balance for a given asset.
   */
  getBalance(assetId: number = 0): bigint {
    return this.notes
      .filter(n => !n.spent && n.assetId === assetId)
      .reduce((sum, n) => sum + n.amount, 0n);
  }

  /**
   * Get all unspent notes for a given asset.
   */
  getUnspentNotes(assetId: number = 0): ShieldedNote[] {
    return this.notes.filter(n => !n.spent && n.assetId === assetId);
  }

  /**
   * Select notes for spending a given amount (coin selection).
   * Uses a simple greedy algorithm — largest notes first.
   */
  selectNotes(amount: bigint, assetId: number = 0): ShieldedNote[] {
    const unspent = this.getUnspentNotes(assetId)
      .sort((a, b) => (b.amount > a.amount ? 1 : b.amount < a.amount ? -1 : 0));

    const selected: ShieldedNote[] = [];
    let total = 0n;

    for (const note of unspent) {
      if (total >= amount) break;
      selected.push(note);
      total += note.amount;
    }

    if (total < amount) {
      throw new Error(`Insufficient balance: have ${total}, need ${amount}`);
    }

    // Limit to 2 inputs (circuit constraint)
    if (selected.length > 2) {
      throw new Error(
        `Need to consolidate notes first — selected ${selected.length} notes but max is 2. ` +
        `Consider running a self-transfer to merge notes.`
      );
    }

    return selected;
  }

  /**
   * Send a shielded transfer.
   *
   * @param amount - Amount to send
   * @param recipientPubKey - Recipient's BN254 public key
   * @param config - Pool configuration
   * @param sender - Algorand account for transaction signing
   * @param wasmPath - Path to circuit WASM
   * @param zkeyPath - Path to proving key
   */
  async send(
    amount: bigint,
    recipientPubKey: BN254Point,
    config: ShieldedPoolConfig,
    sender: import('algosdk').Account,
    wasmPath: string,
    zkeyPath: string,
  ): Promise<string> {
    // Select input notes
    const inputNotes = this.selectNotes(amount, config.assetId);

    // Generate transfer proof
    const transfer = await shieldedTransfer(
      inputNotes,
      amount,
      recipientPubKey,
      this.spendingPubKey,
      this.spendingKey,
      this.tree,
      config,
      wasmPath,
      zkeyPath,
    );

    // Submit on-chain
    const txId = await submitShieldedTransfer(transfer, config, sender);

    // Update local state
    for (const note of inputNotes) {
      note.spent = true;
    }

    // Add change note to wallet
    const changeNote = transfer.outputNotes[1]; // Index 1 is change
    if (changeNote.amount > 0n) {
      changeNote.index = this.tree.nextIndex;
      this.tree.insert(changeNote.commitment);
      this.notes.push(changeNote);
    }

    // Also insert recipient note into tree (we track full tree state)
    const recipientNote = transfer.outputNotes[0];
    recipientNote.index = this.tree.nextIndex;
    this.tree.insert(recipientNote.commitment);

    return txId;
  }

  /**
   * Consolidate notes — merge multiple small notes into fewer larger ones.
   * This is a self-transfer that reduces the number of UTXOs.
   */
  async consolidate(
    assetId: number,
    config: ShieldedPoolConfig,
    sender: import('algosdk').Account,
    wasmPath: string,
    zkeyPath: string,
  ): Promise<string> {
    const unspent = this.getUnspentNotes(assetId);
    if (unspent.length <= 1) throw new Error('Nothing to consolidate');

    // Take the two smallest notes and merge them
    const sorted = [...unspent].sort((a, b) =>
      a.amount > b.amount ? 1 : a.amount < b.amount ? -1 : 0
    );

    const toMerge = sorted.slice(0, 2);
    const totalAmount = toMerge.reduce((s, n) => s + n.amount, 0n);

    return this.send(totalAmount, this.spendingPubKey, config, sender, wasmPath, zkeyPath);
  }

  /**
   * Add a received note to the wallet.
   * Called when the scanner finds a note addressed to this wallet.
   */
  addReceivedNote(note: ShieldedNote): void {
    // Verify the note is addressed to us
    if (note.ownerPubKey.x !== this.spendingPubKey.x ||
        note.ownerPubKey.y !== this.spendingPubKey.y) {
      throw new Error('Note not addressed to this wallet');
    }
    this.notes.push(note);
  }

  /**
   * Export wallet state for encrypted persistence.
   */
  exportState(): WalletState {
    return {
      spendingKey: this.spendingKey,
      viewingKey: this.viewingKey,
      notes: this.notes,
      treeState: this.tree.serialize(),
      lastSyncedRound: this.lastSyncedRound,
    };
  }

  /**
   * Import wallet state from encrypted persistence.
   */
  static async importState(state: WalletState): Promise<ShieldedWallet> {
    const tree = await IncrementalMerkleTree.deserialize(state.treeState);
    const wallet = new ShieldedWallet(state.spendingKey, state.viewingKey, tree);
    wallet.notes = state.notes;
    wallet.lastSyncedRound = state.lastSyncedRound;
    return wallet;
  }

  /**
   * Serialize wallet for storage (JSON format — ENCRYPT before saving!).
   */
  serialize(): string {
    const state = this.exportState();
    return JSON.stringify({
      spendingKey: state.spendingKey.toString(),
      viewingKey: state.viewingKey.toString(),
      notes: state.notes.map(n => serializeShieldedNote(n)),
      treeState: state.treeState,
      lastSyncedRound: state.lastSyncedRound.toString(),
    });
  }

  /**
   * Deserialize wallet from storage.
   */
  static async deserialize(json: string): Promise<ShieldedWallet> {
    const obj = JSON.parse(json);
    const tree = await IncrementalMerkleTree.deserialize(obj.treeState);
    const wallet = new ShieldedWallet(BigInt(obj.spendingKey), BigInt(obj.viewingKey), tree);
    wallet.notes = obj.notes.map((n: string) => deserializeShieldedNote(n));
    wallet.lastSyncedRound = BigInt(obj.lastSyncedRound);
    return wallet;
  }
}
