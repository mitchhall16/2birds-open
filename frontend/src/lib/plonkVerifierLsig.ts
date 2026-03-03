/**
 * PLONK LogicSig Verifier — Transaction Group Builder
 *
 * Constructs the transaction group for PLONK proof verification via LogicSig.
 * Instead of calling a verifier smart contract (~100 inner calls, ~0.1 ALGO),
 * the proof is verified by a LogicSig program (4 txns × 0.001 ALGO = 0.004 ALGO).
 *
 * Group structure:
 *   [0] Payment $0 (LogicSig) — proof + signals as args, signals in Note for pool contract
 *   [1] Payment $0 (LogicSig) — VK chunk 1 in Note (budget padding)
 *   [2] Payment $0 (LogicSig) — VK chunk 2 in Note (budget padding)
 *   [3] Payment $0 (LogicSig) — VK chunk 3 in Note (budget padding)
 *
 * These 4 txns are prepended to the pool app call (and payment if deposit/privateSend).
 */

import algosdk from 'algosdk'

/** VK chunks data loaded from the build output */
export interface PlonkVKChunks {
  hash: string       // hex SHA256 of serialized VK
  chunks: string[]   // hex-encoded VK chunks for Note fields
  nPublic: number
  power: number
}

/** Compiled PLONK verifier LogicSig (loaded once per circuit) */
export interface PlonkVerifierProgram {
  lsig: algosdk.LogicSigAccount
  programBytes: Uint8Array
  vkChunks: PlonkVKChunks
  address: string
}

/** Number of LogicSig transactions in a PLONK verification group */
export const PLONK_LSIG_GROUP_SIZE = 4

/** Fee for PLONK LogicSig verification (4 txns × min fee) */
export const PLONK_LSIG_FEE = 4_000n // 0.004 ALGO

/**
 * Compile a PLONK verifier LogicSig from TEAL source.
 * Call this once per circuit type (deposit, withdraw, privateSend).
 */
export async function compilePlonkVerifier(
  client: algosdk.Algodv2,
  tealSource: string,
  vkChunks: PlonkVKChunks,
): Promise<PlonkVerifierProgram> {
  const compiled = await client.compile(Buffer.from(tealSource)).do()
  const program = new Uint8Array(Buffer.from(compiled.result, 'base64'))
  const lsig = new algosdk.LogicSigAccount(program)
  return {
    lsig,
    programBytes: program,
    vkChunks,
    address: lsig.address() as unknown as string,
  }
}

/**
 * Encode a PLONK proof for the LogicSig verifier (arg 0).
 *
 * snarkjs PLONK proof format → 768-byte packed format:
 *   A(64) || B(64) || C(64) || Z(64) || T1(64) || T2(64) || T3(64) ||
 *   eval_a(32) || eval_b(32) || eval_c(32) || eval_s1(32) || eval_s2(32) || eval_zw(32) ||
 *   Wxi(64) || Wxiw(64)
 */
export function encodePlonkProof(proof: any): Uint8Array {
  const result = new Uint8Array(768)

  // Helper to encode a G1 point (affine, x and y as 32-byte BE)
  function encodeG1(point: string[], offset: number) {
    const x = BigInt(point[0])
    const y = BigInt(point[1])
    for (let i = 31; i >= 0; i--) {
      result[offset + i] = Number(x >> BigInt((31 - i) * 8) & 0xffn)
      result[offset + 32 + i] = Number(y >> BigInt((31 - i) * 8) & 0xffn)
    }
  }

  // Helper to encode a scalar (32-byte BE)
  function encodeScalar(value: string, offset: number) {
    const n = BigInt(value)
    for (let i = 31; i >= 0; i--) {
      result[offset + i] = Number(n >> BigInt((31 - i) * 8) & 0xffn)
    }
  }

  encodeG1(proof.A, 0)
  encodeG1(proof.B, 64)
  encodeG1(proof.C, 128)
  encodeG1(proof.Z, 192)
  encodeG1(proof.T1, 256)
  encodeG1(proof.T2, 320)
  encodeG1(proof.T3, 384)
  encodeScalar(proof.eval_a, 448)
  encodeScalar(proof.eval_b, 480)
  encodeScalar(proof.eval_c, 512)
  encodeScalar(proof.eval_s1, 544)
  encodeScalar(proof.eval_s2, 576)
  encodeScalar(proof.eval_zw, 608)
  encodeG1(proof.Wxi, 640)
  encodeG1(proof.Wxiw, 704)

  return result
}

/**
 * Build the LogicSig verification transaction group.
 *
 * Returns 4 transactions that should be prepended to the pool app call group.
 * The verifier txn at index 0 carries signals in its Note field so the pool
 * contract can read them (matching how the app-based verifier passes signals).
 */
export function buildPlonkVerifierGroup(
  verifier: PlonkVerifierProgram,
  proofBytes: Uint8Array,
  signalsBytes: Uint8Array,
  sender: string,
  params: algosdk.SuggestedParams,
): algosdk.Transaction[] {
  const vkChunkBytes = verifier.vkChunks.chunks.map(hex => {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
    }
    return bytes
  })

  // Txns 0-2: VK chunk carriers + opcode budget padding
  const chunkTxns = vkChunkBytes.map(chunk =>
    algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: verifier.address,
      receiver: verifier.address,
      amount: 0,
      suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
      note: chunk,
    })
  )

  // Txn 3 (last): verifier — carries signals in Note field.
  // Must be last of the 4 so it lands at poolAppCallIndex - 2 (deposit/privateSend)
  // or poolAppCallIndex - 1 (withdraw) in the final transaction group.
  const verifierTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
    sender: verifier.address,
    receiver: verifier.address,
    amount: 0,
    suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
    note: signalsBytes,
  })

  return [...chunkTxns, verifierTxn]
}

/**
 * Sign the LogicSig transactions in a group.
 * Call this after assignGroupID on the full transaction group.
 * Returns signed transaction bytes for the LogicSig txns (indices 0..3).
 *
 * @param proofBytes — PLONK proof bytes passed as LogicSig arg[0] so the
 *   verification program can read the proof via `arg 0`.
 */
export function signPlonkVerifierTxns(
  verifier: PlonkVerifierProgram,
  txns: algosdk.Transaction[],
  proofBytes: Uint8Array,
): Uint8Array[] {
  // Create LogicSig with proof as arg 0 for verification computation
  const lsigWithProof = new algosdk.LogicSigAccount(verifier.programBytes, [proofBytes])
  return txns.slice(0, PLONK_LSIG_GROUP_SIZE).map(txn =>
    algosdk.signLogicSigTransaction(txn, lsigWithProof).blob
  )
}

/**
 * Check if PLONK LogicSig verification is available for a circuit type.
 * Falls back to app-based verification if not configured.
 */
export function isPlonkLsigAvailable(
  verifierAddress: string | undefined,
): boolean {
  if (!verifierAddress) return false
  // Zero address means not configured
  return verifierAddress !== 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'
}
