const ERROR_MAP: [RegExp, string][] = [
  [/User rejected/i, 'Transaction was cancelled in your wallet'],
  [/user.*cancel/i, 'Transaction was cancelled in your wallet'],
  [/overspend/i, 'Insufficient ALGO balance to cover this transaction and fees'],
  [/asset (\d+) missing/i, 'Receiver has not opted into this asset. They need to opt in first.'],
  [/nullifier/i, 'This deposit has already been withdrawn'],
  [/logic eval error/i, 'On-chain proof verification failed'],
  [/Failed to fetch/i, 'Request failed — the Algorand node may be briefly unavailable, try again'],
  [/NetworkError/i, 'Request failed — the Algorand node may be briefly unavailable, try again'],
  [/ECONNREFUSED/i, 'Could not reach the Algorand node — try again shortly'],
  [/timeout/i, 'Request timed out — the network may be congested, try again'],
  [/root not found/i, 'Merkle root mismatch — try Recover Notes'],
  [/concurrent deposit/i, 'Pool state changed — rebuilding tree and retrying'],
  [/below min/i, 'Transaction amount is below the minimum allowed'],
  [/PopEmptyStack/i, 'Smart contract execution error — the contract may need redeployment'],
  [/wasm/i, 'Proof generation failed — try refreshing the page'],
  [/out of memory/i, 'Proof generation ran out of memory — close other tabs and try again'],
]

export function humanizeError(err: unknown): string {
  const raw = err instanceof Error ? err.message : String(err)

  for (const [pattern, friendly] of ERROR_MAP) {
    if (pattern.test(raw)) return friendly
  }

  // Truncate raw message if no pattern matches
  return raw.length > 120 ? raw.slice(0, 117) + '...' : raw
}

/** Retry a function on network errors (timeout, connection refused). */
export async function withRetry<T>(
  fn: () => Promise<T>,
  retries: number = 3,
  delayMs: number = 1000,
): Promise<T> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn()
    } catch (err) {
      const msg = String(err)
      const isNetworkError = /Failed to fetch|NetworkError|ECONNREFUSED|timeout/i.test(msg)
      if (!isNetworkError || attempt === retries) throw err
      await new Promise(r => setTimeout(r, delayMs * attempt))
    }
  }
  throw new Error('unreachable')
}
