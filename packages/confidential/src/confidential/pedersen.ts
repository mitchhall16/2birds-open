/**
 * @2birds/confidential — Pedersen Commitments on BN254
 *
 * Pedersen commitment: C = amount * G + blinding * H
 *
 * Properties:
 * - Computationally hiding: C reveals nothing about amount
 * - Computationally binding: can't open C to a different (amount, blinding)
 * - Homomorphic: C1 + C2 = commit(a1 + a2, b1 + b2)
 *
 * The homomorphic property enables confidential transfers:
 * If C_in = C_out + C_fee, then amounts balance without revealing them.
 *
 * On-chain: uses BN254 ec_scalar_mul and ec_add opcodes (AVM v10+).
 */

import {
  type BN254Point,
  type Scalar,
  type PedersenCommitment,
  BN254_G,
  BN254_H,
  ecMul,
  ecAdd,
  ecNeg,
  randomScalar,
  scalarMod,
  BN254_SCALAR_ORDER,
  isOnCurve,
  encodePoint,
} from '@2birds/core';

/**
 * Create a Pedersen commitment: C = amount * G + blinding * H
 *
 * @param amount - The value to commit to
 * @param blinding - Random blinding factor (optional, generated if not provided)
 */
export function commit(amount: bigint, blinding?: Scalar): PedersenCommitment {
  const b = blinding ?? randomScalar();

  // C = amount * G + blinding * H
  const aG = ecMul(BN254_G, amount);
  const bH = ecMul(BN254_H, b);
  const commitment = ecAdd(aG, bH);

  return { commitment, amount, blinding: b };
}

/**
 * Verify a Pedersen commitment opening.
 * Checks that C == amount * G + blinding * H
 */
export function verifyCommitment(c: PedersenCommitment): boolean {
  const aG = ecMul(BN254_G, c.amount);
  const bH = ecMul(BN254_H, c.blinding);
  const expected = ecAdd(aG, bH);
  return expected.x === c.commitment.x && expected.y === c.commitment.y;
}

/**
 * Add two commitments (homomorphic addition).
 * commit(a1, b1) + commit(a2, b2) = commit(a1 + a2, b1 + b2)
 */
export function addCommitments(c1: PedersenCommitment, c2: PedersenCommitment): PedersenCommitment {
  return {
    commitment: ecAdd(c1.commitment, c2.commitment),
    amount: c1.amount + c2.amount,
    blinding: scalarMod(c1.blinding + c2.blinding),
  };
}

/**
 * Subtract two commitments.
 * commit(a1, b1) - commit(a2, b2) = commit(a1 - a2, b1 - b2)
 */
export function subtractCommitments(c1: PedersenCommitment, c2: PedersenCommitment): PedersenCommitment {
  const negC2 = ecNeg(c2.commitment);
  return {
    commitment: ecAdd(c1.commitment, negC2),
    amount: c1.amount - c2.amount,
    blinding: scalarMod(c1.blinding - c2.blinding),
  };
}

/**
 * Verify that commitments balance: C_in = C_out + C_fee
 * (Checks the EC point equation without knowing the amounts)
 */
export function verifyBalance(
  inputCommitment: BN254Point,
  outputCommitment: BN254Point,
  feeCommitment: BN254Point,
): boolean {
  // C_out + C_fee should equal C_in
  const sum = ecAdd(outputCommitment, feeCommitment);
  return sum.x === inputCommitment.x && sum.y === inputCommitment.y;
}

/**
 * Create a commitment to zero amount with zero blinding (identity commitment).
 * Useful for padding transaction inputs/outputs.
 */
export function zeroCommitment(): PedersenCommitment {
  return {
    commitment: { x: 0n, y: 0n },
    amount: 0n,
    blinding: 0n,
  };
}

/**
 * Encode a commitment for on-chain storage (64 bytes — BN254 point).
 */
export function encodeCommitment(c: PedersenCommitment): Uint8Array {
  return encodePoint(c.commitment);
}

/**
 * Create blinding factors for a transfer that ensures the commitments balance.
 *
 * Given input blinding b_in and output amount, compute:
 * b_out such that C_in - C_out = C_fee with known fee blinding.
 *
 * @param inputBlinding - blinding of the input commitment
 * @param feeBlinding - desired blinding for the fee commitment (can be 0 for public fees)
 */
export function deriveTransferBlindings(
  inputBlinding: Scalar,
  feeBlinding: Scalar = 0n,
): { outputBlinding: Scalar } {
  // b_in = b_out + b_fee => b_out = b_in - b_fee
  const outputBlinding = scalarMod(inputBlinding - feeBlinding);
  return { outputBlinding };
}
