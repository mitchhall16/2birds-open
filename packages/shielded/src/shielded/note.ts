/**
 * @2birds/shielded — Shielded Note Management
 *
 * UTXO-style notes for the shielded pool.
 * Each note represents a discrete amount of value with hidden ownership.
 *
 * Note structure:
 * { amount, ownerPubKey (x-coord), blinding, nullifier }
 * Commitment = MiMC(amount, ownerPubKey, blinding, nullifier)
 * NullifierHash = MiMC(nullifier, spendingKey)
 */

import {
  type ShieldedNote,
  type Scalar,
  type BN254Point,
  randomScalar,
  mimcHashMulti,
  mimcHash,
  derivePubKey,
  scalarMod,
  BN254_SCALAR_ORDER,
} from '@2birds/core';

/**
 * Create a new shielded note.
 *
 * @param amount - Note value
 * @param ownerPubKey - Owner's BN254 public key (spending key * G)
 * @param assetId - 0 for ALGO, ASA ID for tokens
 */
export function createNote(
  amount: bigint,
  ownerPubKey: BN254Point,
  assetId: number = 0,
): ShieldedNote {
  const blinding = randomScalar();
  const nullifier = randomScalar();

  const commitment = computeNoteCommitment(amount, ownerPubKey.x, blinding, nullifier);

  return {
    amount,
    ownerPubKey,
    blinding,
    nullifier,
    commitment,
    index: -1, // Set when inserted into Merkle tree
    assetId,
    spent: false,
  };
}

/** Compute a note's commitment: MiMC(amount, ownerPubKey.x, blinding, nullifier) */
export function computeNoteCommitment(
  amount: bigint,
  ownerPubKeyX: Scalar,
  blinding: Scalar,
  nullifier: Scalar,
): Scalar {
  return mimcHashMulti(amount, ownerPubKeyX, blinding, nullifier);
}

/** Compute a note's nullifier hash: MiMC(nullifier, spendingKey) */
export function computeNullifierHash(nullifier: Scalar, spendingKey: Scalar): Scalar {
  return mimcHash(nullifier, spendingKey);
}

/**
 * Create output notes for a transfer.
 * Splits a transfer into recipient note + change note.
 *
 * @param transferAmount - Amount to send
 * @param totalInput - Total input amount (sum of input notes)
 * @param recipientPubKey - Recipient's BN254 public key
 * @param senderPubKey - Sender's BN254 public key (for change)
 * @param assetId - Asset ID
 */
export function createTransferOutputs(
  transferAmount: bigint,
  totalInput: bigint,
  recipientPubKey: BN254Point,
  senderPubKey: BN254Point,
  assetId: number = 0,
): { recipientNote: ShieldedNote; changeNote: ShieldedNote } {
  if (transferAmount > totalInput) {
    throw new Error('Insufficient input amount');
  }

  const changeAmount = totalInput - transferAmount;

  const recipientNote = createNote(transferAmount, recipientPubKey, assetId);
  const changeNote = createNote(changeAmount, senderPubKey, assetId);

  return { recipientNote, changeNote };
}

/**
 * Serialize a note for secure storage.
 * WARNING: This contains secret values — encrypt before saving!
 */
export function serializeShieldedNote(note: ShieldedNote): string {
  return JSON.stringify({
    amount: note.amount.toString(),
    ownerPubKey: { x: note.ownerPubKey.x.toString(), y: note.ownerPubKey.y.toString() },
    blinding: note.blinding.toString(),
    nullifier: note.nullifier.toString(),
    commitment: note.commitment.toString(),
    index: note.index,
    assetId: note.assetId,
    spent: note.spent,
  });
}

/** Deserialize a note */
export function deserializeShieldedNote(json: string): ShieldedNote {
  const obj = JSON.parse(json);
  return {
    amount: BigInt(obj.amount),
    ownerPubKey: { x: BigInt(obj.ownerPubKey.x), y: BigInt(obj.ownerPubKey.y) },
    blinding: BigInt(obj.blinding),
    nullifier: BigInt(obj.nullifier),
    commitment: BigInt(obj.commitment),
    index: obj.index,
    assetId: obj.assetId,
    spent: obj.spent,
  };
}
