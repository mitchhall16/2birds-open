import { describe, it, expect, beforeAll } from 'vitest';
import {
  createNote,
  computeNoteCommitment,
  computeNullifierHash,
  createTransferOutputs,
  serializeShieldedNote,
  deserializeShieldedNote,
} from '../shielded/note.js';
import { ShieldedWallet } from '../shielded/wallet.js';
import {
  randomScalar,
  derivePubKey,
  mimcHashMulti,
  mimcHash,
  initMimc,
} from '@algo-privacy/core';

beforeAll(async () => {
  await initMimc();
});

// -------------------------------------------------------------------------
// createNote
// -------------------------------------------------------------------------

describe('createNote', () => {
  it('creates a note with correct amount and owner', () => {
    const spendingKey = randomScalar();
    const pubKey = derivePubKey(spendingKey);
    const note = createNote(1000n, pubKey);

    expect(note.amount).toBe(1000n);
    expect(note.ownerPubKey.x).toBe(pubKey.x);
    expect(note.ownerPubKey.y).toBe(pubKey.y);
    expect(note.assetId).toBe(0);
    expect(note.spent).toBe(false);
    expect(note.index).toBe(-1);
  });

  it('generates random blinding and nullifier', () => {
    const pubKey = derivePubKey(randomScalar());
    const n1 = createNote(100n, pubKey);
    const n2 = createNote(100n, pubKey);
    expect(n1.blinding).not.toBe(n2.blinding);
    expect(n1.nullifier).not.toBe(n2.nullifier);
  });

  it('sets assetId when provided', () => {
    const pubKey = derivePubKey(randomScalar());
    const note = createNote(100n, pubKey, 31566704);
    expect(note.assetId).toBe(31566704);
  });

  it('commitment is non-zero', () => {
    const pubKey = derivePubKey(randomScalar());
    const note = createNote(100n, pubKey);
    expect(note.commitment).not.toBe(0n);
  });

  it('different notes produce different commitments', () => {
    const pubKey = derivePubKey(randomScalar());
    const n1 = createNote(100n, pubKey);
    const n2 = createNote(100n, pubKey);
    expect(n1.commitment).not.toBe(n2.commitment);
  });
});

// -------------------------------------------------------------------------
// computeNoteCommitment
// -------------------------------------------------------------------------

describe('computeNoteCommitment', () => {
  it('matches MiMC hash of (amount, pubKeyX, blinding, nullifier)', () => {
    const amount = 500n;
    const pubKeyX = randomScalar();
    const blinding = randomScalar();
    const nullifier = randomScalar();

    const commitment = computeNoteCommitment(amount, pubKeyX, blinding, nullifier);
    const expected = mimcHashMulti(amount, pubKeyX, blinding, nullifier);
    expect(commitment).toBe(expected);
  });

  it('is deterministic', () => {
    const amount = 100n;
    const pubKeyX = 42n;
    const blinding = 123n;
    const nullifier = 456n;

    const c1 = computeNoteCommitment(amount, pubKeyX, blinding, nullifier);
    const c2 = computeNoteCommitment(amount, pubKeyX, blinding, nullifier);
    expect(c1).toBe(c2);
  });

  it('changes when any input changes', () => {
    const base = [100n, 200n, 300n, 400n] as const;
    const c0 = computeNoteCommitment(...base);

    // Change each input
    expect(computeNoteCommitment(101n, base[1], base[2], base[3])).not.toBe(c0);
    expect(computeNoteCommitment(base[0], 201n, base[2], base[3])).not.toBe(c0);
    expect(computeNoteCommitment(base[0], base[1], 301n, base[3])).not.toBe(c0);
    expect(computeNoteCommitment(base[0], base[1], base[2], 401n)).not.toBe(c0);
  });

  it('note commitment matches createNote output', () => {
    const pubKey = derivePubKey(randomScalar());
    const note = createNote(100n, pubKey);
    const recomputed = computeNoteCommitment(
      note.amount,
      note.ownerPubKey.x,
      note.blinding,
      note.nullifier,
    );
    expect(recomputed).toBe(note.commitment);
  });
});

// -------------------------------------------------------------------------
// computeNullifierHash
// -------------------------------------------------------------------------

describe('computeNullifierHash', () => {
  it('returns MiMC hash of (nullifier, spendingKey)', () => {
    const nullifier = randomScalar();
    const spendingKey = randomScalar();
    const hash = computeNullifierHash(nullifier, spendingKey);
    const expected = mimcHash(nullifier, spendingKey);
    expect(hash).toBe(expected);
  });

  it('is deterministic', () => {
    const nullifier = 123n;
    const spendingKey = 456n;
    expect(computeNullifierHash(nullifier, spendingKey)).toBe(
      computeNullifierHash(nullifier, spendingKey),
    );
  });

  it('different nullifiers produce different hashes', () => {
    const spendingKey = randomScalar();
    const h1 = computeNullifierHash(1n, spendingKey);
    const h2 = computeNullifierHash(2n, spendingKey);
    expect(h1).not.toBe(h2);
  });

  it('different spending keys produce different hashes', () => {
    const nullifier = randomScalar();
    const h1 = computeNullifierHash(nullifier, 1n);
    const h2 = computeNullifierHash(nullifier, 2n);
    expect(h1).not.toBe(h2);
  });
});

// -------------------------------------------------------------------------
// createTransferOutputs
// -------------------------------------------------------------------------

describe('createTransferOutputs', () => {
  it('creates recipient and change notes with correct amounts', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    const { recipientNote, changeNote } = createTransferOutputs(
      300n,
      500n,
      recipientPub,
      senderPub,
    );

    expect(recipientNote.amount).toBe(300n);
    expect(changeNote.amount).toBe(200n);
  });

  it('recipient note has recipient pubkey', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    const { recipientNote } = createTransferOutputs(
      100n,
      100n,
      recipientPub,
      senderPub,
    );
    expect(recipientNote.ownerPubKey.x).toBe(recipientPub.x);
    expect(recipientNote.ownerPubKey.y).toBe(recipientPub.y);
  });

  it('change note has sender pubkey', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    const { changeNote } = createTransferOutputs(
      100n,
      500n,
      recipientPub,
      senderPub,
    );
    expect(changeNote.ownerPubKey.x).toBe(senderPub.x);
    expect(changeNote.ownerPubKey.y).toBe(senderPub.y);
  });

  it('throws on insufficient input', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    expect(() => createTransferOutputs(600n, 500n, recipientPub, senderPub)).toThrow(
      'Insufficient input amount',
    );
  });

  it('zero change when exact amount', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    const { changeNote } = createTransferOutputs(
      500n,
      500n,
      recipientPub,
      senderPub,
    );
    expect(changeNote.amount).toBe(0n);
  });

  it('sets assetId on both outputs', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    const { recipientNote, changeNote } = createTransferOutputs(
      100n,
      500n,
      recipientPub,
      senderPub,
      31566704,
    );
    expect(recipientNote.assetId).toBe(31566704);
    expect(changeNote.assetId).toBe(31566704);
  });

  it('amounts sum to total input', () => {
    const recipientPub = derivePubKey(randomScalar());
    const senderPub = derivePubKey(randomScalar());
    const totalInput = 1000n;
    const transferAmount = 350n;
    const { recipientNote, changeNote } = createTransferOutputs(
      transferAmount,
      totalInput,
      recipientPub,
      senderPub,
    );
    expect(recipientNote.amount + changeNote.amount).toBe(totalInput);
  });
});

// -------------------------------------------------------------------------
// Note serialization
// -------------------------------------------------------------------------

describe('note serialization', () => {
  it('roundtrips correctly', () => {
    const pubKey = derivePubKey(randomScalar());
    const note = createNote(1000n, pubKey, 42);
    note.index = 5;

    const json = serializeShieldedNote(note);
    const recovered = deserializeShieldedNote(json);

    expect(recovered.amount).toBe(note.amount);
    expect(recovered.ownerPubKey.x).toBe(note.ownerPubKey.x);
    expect(recovered.ownerPubKey.y).toBe(note.ownerPubKey.y);
    expect(recovered.blinding).toBe(note.blinding);
    expect(recovered.nullifier).toBe(note.nullifier);
    expect(recovered.commitment).toBe(note.commitment);
    expect(recovered.index).toBe(5);
    expect(recovered.assetId).toBe(42);
    expect(recovered.spent).toBe(false);
  });

  it('preserves spent flag', () => {
    const pubKey = derivePubKey(randomScalar());
    const note = createNote(100n, pubKey);
    note.spent = true;

    const recovered = deserializeShieldedNote(serializeShieldedNote(note));
    expect(recovered.spent).toBe(true);
  });

  it('handles large bigint values', () => {
    const pubKey = derivePubKey(randomScalar());
    const note = createNote(999_999_999_999_999n, pubKey);

    const recovered = deserializeShieldedNote(serializeShieldedNote(note));
    expect(recovered.amount).toBe(999_999_999_999_999n);
    expect(recovered.commitment).toBe(note.commitment);
  });
});

// -------------------------------------------------------------------------
// ShieldedWallet — offline operations (no network needed)
// -------------------------------------------------------------------------

describe('ShieldedWallet', () => {
  it('creates a wallet with random keys', async () => {
    const wallet = await ShieldedWallet.create();
    expect(wallet.publicKey.x).not.toBe(0n);
    expect(wallet.publicKey.y).not.toBe(0n);
  });

  it('creates a wallet with explicit keys', async () => {
    const sk = randomScalar();
    const vk = randomScalar();
    const wallet = await ShieldedWallet.create(sk, vk);
    const expectedPub = derivePubKey(sk);
    expect(wallet.publicKey.x).toBe(expectedPub.x);
    expect(wallet.publicKey.y).toBe(expectedPub.y);
    expect(wallet.viewKey).toBe(vk);
  });

  it('empty wallet has zero balance', async () => {
    const wallet = await ShieldedWallet.create();
    expect(wallet.getBalance()).toBe(0n);
  });

  it('tracks balance after adding notes', async () => {
    const sk = randomScalar();
    const wallet = await ShieldedWallet.create(sk);

    const note1 = createNote(500n, wallet.publicKey);
    note1.index = 0;
    const note2 = createNote(300n, wallet.publicKey);
    note2.index = 1;

    wallet.addReceivedNote(note1);
    wallet.addReceivedNote(note2);

    expect(wallet.getBalance()).toBe(800n);
  });

  it('getUnspentNotes returns only unspent', async () => {
    const sk = randomScalar();
    const wallet = await ShieldedWallet.create(sk);

    const note1 = createNote(500n, wallet.publicKey);
    note1.index = 0;
    const note2 = createNote(300n, wallet.publicKey);
    note2.index = 1;
    note2.spent = true;

    wallet.addReceivedNote(note1);
    wallet.addReceivedNote(note2);

    const unspent = wallet.getUnspentNotes();
    expect(unspent.length).toBe(1);
    expect(unspent[0].amount).toBe(500n);
  });

  it('getBalance filters by assetId', async () => {
    const sk = randomScalar();
    const wallet = await ShieldedWallet.create(sk);

    const algoNote = createNote(1000n, wallet.publicKey, 0);
    algoNote.index = 0;
    const usdcNote = createNote(500n, wallet.publicKey, 31566704);
    usdcNote.index = 1;

    wallet.addReceivedNote(algoNote);
    wallet.addReceivedNote(usdcNote);

    expect(wallet.getBalance(0)).toBe(1000n);
    expect(wallet.getBalance(31566704)).toBe(500n);
  });

  it('selectNotes picks largest notes first', async () => {
    const sk = randomScalar();
    const wallet = await ShieldedWallet.create(sk);

    const notes = [100n, 500n, 200n].map((amt, i) => {
      const n = createNote(amt, wallet.publicKey);
      n.index = i;
      return n;
    });
    notes.forEach(n => wallet.addReceivedNote(n));

    const selected = wallet.selectNotes(600n);
    expect(selected.length).toBe(2);
    // Should pick 500 + 200 (largest first)
    expect(selected[0].amount).toBe(500n);
    expect(selected[1].amount).toBe(200n);
  });

  it('selectNotes throws on insufficient balance', async () => {
    const sk = randomScalar();
    const wallet = await ShieldedWallet.create(sk);

    const note = createNote(100n, wallet.publicKey);
    note.index = 0;
    wallet.addReceivedNote(note);

    expect(() => wallet.selectNotes(200n)).toThrow('Insufficient balance');
  });

  it('selectNotes throws when too many notes needed', async () => {
    const sk = randomScalar();
    const wallet = await ShieldedWallet.create(sk);

    // Add 3 small notes that sum to enough but need >2 inputs
    for (let i = 0; i < 3; i++) {
      const n = createNote(100n, wallet.publicKey);
      n.index = i;
      wallet.addReceivedNote(n);
    }

    expect(() => wallet.selectNotes(250n)).toThrow('consolidate');
  });

  it('addReceivedNote rejects notes not addressed to wallet', async () => {
    const wallet = await ShieldedWallet.create();
    const otherPubKey = derivePubKey(randomScalar());
    const note = createNote(100n, otherPubKey);

    expect(() => wallet.addReceivedNote(note)).toThrow('not addressed');
  });

  it('serialization roundtrip preserves wallet state', async () => {
    const sk = randomScalar();
    const vk = randomScalar();
    const wallet = await ShieldedWallet.create(sk, vk);

    const note = createNote(1000n, wallet.publicKey);
    note.index = 0;
    wallet.addReceivedNote(note);

    const json = wallet.serialize();
    const restored = await ShieldedWallet.deserialize(json);

    expect(restored.publicKey.x).toBe(wallet.publicKey.x);
    expect(restored.publicKey.y).toBe(wallet.publicKey.y);
    expect(restored.viewKey).toBe(vk);
    expect(restored.getBalance()).toBe(1000n);
  });
});
