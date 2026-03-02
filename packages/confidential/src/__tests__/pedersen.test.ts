import { describe, it, expect } from 'vitest';
import {
  commit,
  verifyCommitment,
  addCommitments,
  subtractCommitments,
  verifyBalance,
  zeroCommitment,
  encodeCommitment,
  deriveTransferBlindings,
} from '../confidential/pedersen.js';
import {
  BN254_G,
  BN254_H,
  ecMul,
  ecAdd,
  randomScalar,
  isOnCurve,
  scalarMod,
  BN254_SCALAR_ORDER,
} from '@algo-privacy/core';

// -------------------------------------------------------------------------
// commit
// -------------------------------------------------------------------------

describe('commit', () => {
  it('creates a commitment with given amount', () => {
    const pc = commit(100n);
    expect(pc.amount).toBe(100n);
    expect(pc.blinding).not.toBe(0n);
    expect(pc.commitment.x).not.toBe(0n);
    expect(pc.commitment.y).not.toBe(0n);
  });

  it('creates a commitment with explicit blinding', () => {
    const blinding = randomScalar();
    const pc = commit(42n, blinding);
    expect(pc.amount).toBe(42n);
    expect(pc.blinding).toBe(blinding);
  });

  it('commitment point is on the curve', () => {
    const pc = commit(1000n);
    expect(isOnCurve(pc.commitment)).toBe(true);
  });

  it('same amount with different blinding gives different commitments', () => {
    const pc1 = commit(100n);
    const pc2 = commit(100n);
    // Overwhelmingly likely to differ (random blindings)
    expect(
      pc1.commitment.x !== pc2.commitment.x || pc1.commitment.y !== pc2.commitment.y,
    ).toBe(true);
  });

  it('different amounts with same blinding give different commitments', () => {
    const blinding = randomScalar();
    const pc1 = commit(100n, blinding);
    const pc2 = commit(200n, blinding);
    expect(
      pc1.commitment.x !== pc2.commitment.x || pc1.commitment.y !== pc2.commitment.y,
    ).toBe(true);
  });

  it('commitment equals amount*G + blinding*H', () => {
    const blinding = randomScalar();
    const amount = 500n;
    const pc = commit(amount, blinding);

    const expected = ecAdd(ecMul(BN254_G, amount), ecMul(BN254_H, blinding));
    expect(pc.commitment.x).toBe(expected.x);
    expect(pc.commitment.y).toBe(expected.y);
  });
});

// -------------------------------------------------------------------------
// verifyCommitment
// -------------------------------------------------------------------------

describe('verifyCommitment', () => {
  it('verifies a valid commitment', () => {
    const pc = commit(100n);
    expect(verifyCommitment(pc)).toBe(true);
  });

  it('rejects a commitment with wrong amount', () => {
    const pc = commit(100n);
    const tampered = { ...pc, amount: 200n };
    expect(verifyCommitment(tampered)).toBe(false);
  });

  it('rejects a commitment with wrong blinding', () => {
    const pc = commit(100n);
    const tampered = { ...pc, blinding: randomScalar() };
    expect(verifyCommitment(tampered)).toBe(false);
  });

  it('verifies zero amount commitment', () => {
    const pc = commit(0n);
    expect(verifyCommitment(pc)).toBe(true);
  });

  it('verifies large amount commitment', () => {
    const pc = commit(1_000_000_000_000n);
    expect(verifyCommitment(pc)).toBe(true);
  });
});

// -------------------------------------------------------------------------
// addCommitments (homomorphic addition)
// -------------------------------------------------------------------------

describe('addCommitments', () => {
  it('sum amounts match', () => {
    const c1 = commit(100n);
    const c2 = commit(200n);
    const sum = addCommitments(c1, c2);
    expect(sum.amount).toBe(300n);
  });

  it('sum commitment verifies', () => {
    const c1 = commit(100n);
    const c2 = commit(200n);
    const sum = addCommitments(c1, c2);
    expect(verifyCommitment(sum)).toBe(true);
  });

  it('sum blinding is c1.blinding + c2.blinding mod order', () => {
    const b1 = randomScalar();
    const b2 = randomScalar();
    const c1 = commit(100n, b1);
    const c2 = commit(200n, b2);
    const sum = addCommitments(c1, c2);
    expect(sum.blinding).toBe(scalarMod(b1 + b2));
  });

  it('adding zero commitment is identity', () => {
    const c1 = commit(100n);
    const zero = zeroCommitment();
    const sum = addCommitments(c1, zero);
    expect(sum.amount).toBe(100n);
    // Point should be the same (adding identity point)
    expect(sum.commitment.x).toBe(c1.commitment.x);
    expect(sum.commitment.y).toBe(c1.commitment.y);
  });

  it('addition is commutative', () => {
    const c1 = commit(100n);
    const c2 = commit(200n);
    const sum1 = addCommitments(c1, c2);
    const sum2 = addCommitments(c2, c1);
    expect(sum1.commitment.x).toBe(sum2.commitment.x);
    expect(sum1.commitment.y).toBe(sum2.commitment.y);
  });
});

// -------------------------------------------------------------------------
// subtractCommitments
// -------------------------------------------------------------------------

describe('subtractCommitments', () => {
  it('difference amounts match', () => {
    const c1 = commit(300n);
    const c2 = commit(100n);
    const diff = subtractCommitments(c1, c2);
    expect(diff.amount).toBe(200n);
  });

  it('difference commitment verifies', () => {
    const c1 = commit(300n);
    const c2 = commit(100n);
    const diff = subtractCommitments(c1, c2);
    expect(verifyCommitment(diff)).toBe(true);
  });

  it('subtracting from self gives zero amount', () => {
    const c1 = commit(100n);
    const diff = subtractCommitments(c1, c1);
    expect(diff.amount).toBe(0n);
  });
});

// -------------------------------------------------------------------------
// verifyBalance
// -------------------------------------------------------------------------

describe('verifyBalance', () => {
  it('balanced transfer verifies: C_in = C_out + C_fee', () => {
    const inputAmount = 1000n;
    const outputAmount = 900n;
    const feeAmount = 100n;

    const inputBlinding = randomScalar();
    const feeBlinding = randomScalar();
    // b_out = b_in - b_fee
    const outputBlinding = scalarMod(inputBlinding - feeBlinding);

    const cIn = commit(inputAmount, inputBlinding);
    const cOut = commit(outputAmount, outputBlinding);
    const cFee = commit(feeAmount, feeBlinding);

    expect(verifyBalance(cIn.commitment, cOut.commitment, cFee.commitment)).toBe(true);
  });

  it('unbalanced transfer fails verification', () => {
    const cIn = commit(1000n);
    const cOut = commit(800n);
    const cFee = commit(100n); // 800 + 100 ≠ 1000 (different blindings too)

    // Almost certainly fails (would need a blinding collision)
    expect(verifyBalance(cIn.commitment, cOut.commitment, cFee.commitment)).toBe(false);
  });
});

// -------------------------------------------------------------------------
// zeroCommitment
// -------------------------------------------------------------------------

describe('zeroCommitment', () => {
  it('has zero amount', () => {
    const z = zeroCommitment();
    expect(z.amount).toBe(0n);
  });

  it('has zero blinding', () => {
    const z = zeroCommitment();
    expect(z.blinding).toBe(0n);
  });

  it('commitment is identity point', () => {
    const z = zeroCommitment();
    expect(z.commitment.x).toBe(0n);
    expect(z.commitment.y).toBe(0n);
  });
});

// -------------------------------------------------------------------------
// encodeCommitment
// -------------------------------------------------------------------------

describe('encodeCommitment', () => {
  it('encodes to 64 bytes (BN254 point)', () => {
    const pc = commit(100n);
    const encoded = encodeCommitment(pc);
    expect(encoded.length).toBe(64);
  });

  it('different commitments produce different encodings', () => {
    const c1 = commit(100n);
    const c2 = commit(200n);
    const e1 = encodeCommitment(c1);
    const e2 = encodeCommitment(c2);
    expect(e1).not.toEqual(e2);
  });

  it('same commitment encodes deterministically', () => {
    const blinding = randomScalar();
    const c1 = commit(100n, blinding);
    const c2 = commit(100n, blinding);
    const e1 = encodeCommitment(c1);
    const e2 = encodeCommitment(c2);
    expect(e1).toEqual(e2);
  });
});

// -------------------------------------------------------------------------
// deriveTransferBlindings
// -------------------------------------------------------------------------

describe('deriveTransferBlindings', () => {
  it('output blinding ensures balance: b_out = b_in - b_fee', () => {
    const inputBlinding = randomScalar();
    const feeBlinding = randomScalar();
    const { outputBlinding } = deriveTransferBlindings(inputBlinding, feeBlinding);
    expect(outputBlinding).toBe(scalarMod(inputBlinding - feeBlinding));
  });

  it('with zero fee blinding, output blinding equals input blinding', () => {
    const inputBlinding = randomScalar();
    const { outputBlinding } = deriveTransferBlindings(inputBlinding, 0n);
    expect(outputBlinding).toBe(inputBlinding);
  });

  it('derived blindings produce balanced commitments', () => {
    const inputAmount = 1000n;
    const outputAmount = 700n;
    const feeAmount = 300n;
    const inputBlinding = randomScalar();
    const feeBlinding = randomScalar();

    const { outputBlinding } = deriveTransferBlindings(inputBlinding, feeBlinding);

    const cIn = commit(inputAmount, inputBlinding);
    const cOut = commit(outputAmount, outputBlinding);
    const cFee = commit(feeAmount, feeBlinding);

    expect(verifyBalance(cIn.commitment, cOut.commitment, cFee.commitment)).toBe(true);
  });
});
