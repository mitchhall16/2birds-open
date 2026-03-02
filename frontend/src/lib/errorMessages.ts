const ERROR_MAP: [RegExp, string][] = [
  [/User rejected/i, 'Transaction was cancelled in your wallet'],
  [/user.*cancel/i, 'Transaction was cancelled in your wallet'],
  [/overspend/i, 'Insufficient ALGO balance to cover this transaction and fees'],
  [/asset (\d+) missing/i, 'Receiver has not opted into this asset. They need to opt in first.'],
  [/nullifier/i, 'This deposit has already been withdrawn'],
  [/logic eval error/i, 'On-chain proof verification failed'],
  [/Failed to fetch/i, 'Could not reach the Algorand node. Check your connection.'],
  [/root not found/i, 'Merkle root mismatch — try Recover Notes'],
  [/below min/i, 'Transaction amount is below the minimum allowed'],
  [/PopEmptyStack/i, 'Smart contract execution error — the contract may need redeployment'],
]

export function humanizeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err)

  for (const [pattern, friendly] of ERROR_MAP) {
    if (pattern.test(raw)) return friendly
  }

  // Truncate raw message if no pattern matches
  return raw.length > 120 ? raw.slice(0, 117) + '...' : raw
}
