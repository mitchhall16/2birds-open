import { DENOMINATION_TIERS, FEES, PROTOCOL_FEE, TREASURY_ADDRESS, isTierDeployed } from './config'
import type { DepositNote } from './privacy'
import { formatAlgo } from './privacy'

export interface PlanStep {
  type: 'deposit' | 'withdraw' | 'privateSend' | 'split'
  tierMicroAlgos: bigint
  count: number
  fee: bigint           // fee per operation
  batchWindow: boolean  // true for privateSend (needs separate batch windows)
}

export interface Plan {
  steps: PlanStep[]
  totalFees: bigint
  totalAmount: bigint
  estimatedWindows: number  // how many batch windows needed
  warnings: string[]
}

const protocolFee = !!TREASURY_ADDRESS && PROTOCOL_FEE > 0n ? PROTOCOL_FEE : 0n

/** Plan a deposit — break target amount into optimal denomination mix (greedy largest-first) */
export function planDeposit(targetMicroAlgos: bigint): Plan {
  const steps: PlanStep[] = []
  const warnings: string[] = []
  let remaining = targetMicroAlgos

  // Sort deployed tiers descending
  const deployedTiers = DENOMINATION_TIERS
    .filter(t => isTierDeployed(t.microAlgos))
    .sort((a, b) => (b.microAlgos > a.microAlgos ? 1 : b.microAlgos < a.microAlgos ? -1 : 0))

  // Check for undeployed tiers that would have been useful
  const allTiersSorted = [...DENOMINATION_TIERS]
    .sort((a, b) => (b.microAlgos > a.microAlgos ? 1 : b.microAlgos < a.microAlgos ? -1 : 0))

  for (const tier of allTiersSorted) {
    if (!isTierDeployed(tier.microAlgos) && tier.microAlgos <= targetMicroAlgos) {
      warnings.push(`${tier.label} ALGO pool not yet deployed — using smaller denominations instead`)
    }
  }

  for (const tier of deployedTiers) {
    if (remaining <= 0n) break
    const count = Number(remaining / tier.microAlgos)
    if (count > 0) {
      steps.push({
        type: 'deposit',
        tierMicroAlgos: tier.microAlgos,
        count,
        fee: FEES.deposit + protocolFee,
        batchWindow: false,
      })
      remaining -= tier.microAlgos * BigInt(count)
    }
  }

  if (remaining > 0n) {
    warnings.push('Amount must be in 0.1 ALGO increments')
  }

  const totalFees = steps.reduce((sum, s) => sum + s.fee * BigInt(s.count), 0n)
  const totalAmount = targetMicroAlgos - remaining

  return {
    steps,
    totalFees,
    totalAmount,
    estimatedWindows: 1, // deposits all go in the same batch window
    warnings,
  }
}

/** Plan a withdrawal/send — use existing notes, prefer using available notes */
export function planWithdrawal(
  targetMicroAlgos: bigint,
  availableNotes: DepositNote[],
  mode: 'withdraw' | 'privateSend',
): Plan {
  const steps: PlanStep[] = []
  const warnings: string[] = []

  // Sort notes descending by denomination, randomize within same denomination
  const sorted = [...availableNotes].sort((a, b) => {
    if (a.denomination !== b.denomination) {
      return a.denomination > b.denomination ? -1 : 1
    }
    // Randomize among same denomination for privacy
    return Math.random() - 0.5
  })

  let remaining = targetMicroAlgos
  const usedNotes: DepositNote[] = []

  // Greedy match: pick notes that sum to target
  for (const note of sorted) {
    if (remaining <= 0n) break
    if (note.denomination <= remaining) {
      usedNotes.push(note)
      remaining -= note.denomination
    }
  }

  // If not exact match, try to find smallest overshoot
  if (remaining > 0n) {
    // Find the smallest note that covers the remaining amount
    const smallestCovering = sorted
      .filter(n => !usedNotes.includes(n) && n.denomination >= remaining)
      .sort((a, b) => (a.denomination > b.denomination ? 1 : -1))

    if (smallestCovering.length > 0) {
      usedNotes.push(smallestCovering[0])
      remaining -= smallestCovering[0].denomination
      if (remaining < 0n) {
        warnings.push(`Closest match overshoots by ${formatAlgo(-remaining)} ALGO (change is not returned in privacy pools)`)
      }
    } else if (remaining > 0n) {
      warnings.push(`Insufficient shielded balance: need ${formatAlgo(remaining)} more ALGO`)
    }
  }

  // Group used notes by denomination into steps
  const grouped = new Map<string, number>()
  for (const note of usedNotes) {
    const key = note.denomination.toString()
    grouped.set(key, (grouped.get(key) || 0) + 1)
  }

  const feePerOp = mode === 'withdraw' ? FEES.withdraw : FEES.privateSend
  let totalWindows = 0

  for (const [denom, count] of grouped) {
    const isPrivateSend = mode === 'privateSend'
    steps.push({
      type: mode,
      tierMicroAlgos: BigInt(denom),
      count,
      fee: feePerOp + protocolFee,
      batchWindow: isPrivateSend,
    })
    totalWindows += isPrivateSend ? count : 0
  }

  // For withdraw mode, all in same window
  if (mode === 'withdraw') totalWindows = 1

  const totalFees = steps.reduce((sum, s) => sum + s.fee * BigInt(s.count), 0n)
  const totalAmount = usedNotes.reduce((sum, n) => sum + n.denomination, 0n)

  return {
    steps,
    totalFees,
    totalAmount,
    estimatedWindows: Math.max(totalWindows, 1),
    warnings,
  }
}

/** Plan a "send X ALGO" — may need deposits first if insufficient shielded balance */
export function planSend(
  targetMicroAlgos: bigint,
  availableNotes: DepositNote[],
): Plan {
  const totalShielded = availableNotes.reduce((sum, n) => sum + n.denomination, 0n)

  if (totalShielded >= targetMicroAlgos) {
    // Have enough shielded balance — plan withdrawal
    return planWithdrawal(targetMicroAlgos, availableNotes, 'privateSend')
  }

  // Need deposits first
  const deficit = targetMicroAlgos - totalShielded
  const depositPlan = planDeposit(deficit)
  const withdrawPlan = planWithdrawal(targetMicroAlgos, [
    ...availableNotes,
    // Simulate the notes that would be created by deposits
    ...depositPlan.steps.flatMap(s =>
      Array(s.count).fill(null).map(() => ({
        secret: 0n,
        nullifier: 0n,
        commitment: 0n,
        leafIndex: -1,
        denomination: s.tierMicroAlgos,
        assetId: 0,
        timestamp: Date.now(),
      }))
    ),
  ], 'privateSend')

  const warnings = [
    ...depositPlan.warnings,
    ...withdrawPlan.warnings,
    `Requires depositing ${formatAlgo(deficit)} ALGO first (insufficient shielded balance)`,
  ]

  return {
    steps: [...depositPlan.steps, ...withdrawPlan.steps],
    totalFees: depositPlan.totalFees + withdrawPlan.totalFees,
    totalAmount: targetMicroAlgos,
    estimatedWindows: depositPlan.estimatedWindows + withdrawPlan.estimatedWindows,
    warnings,
  }
}

/** Generate a human-readable fee guidance string */
export function feeGuidance(plan: Plan): string {
  const totalOps = plan.steps.reduce((sum, s) => sum + s.count, 0)
  const types = new Set(plan.steps.map(s => s.type))
  const typeLabel = types.size === 1
    ? `${totalOps} ${[...types][0]}${totalOps > 1 ? 's' : ''}`
    : `${totalOps} operation${totalOps > 1 ? 's' : ''}`

  const feeStr = formatAlgo(plan.totalFees)
  const windowStr = plan.estimatedWindows === 1
    ? '1 batch window'
    : `${plan.estimatedWindows} batch windows`

  return `${typeLabel}, ~${feeStr} ALGO fees, ~${windowStr}`
}
