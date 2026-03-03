/** Batch window timing utilities for timing attack mitigation.
 *  All operations snap to fixed-schedule batch windows (e.g. :00, :15, :30, :45)
 *  so that multiple users' deposits land in the same time window. */

/** Calculate next batch window boundary (ms since epoch) */
export function nextBatchWindow(intervalMinutes: number): number {
  const now = Date.now()
  const intervalMs = intervalMinutes * 60_000
  return Math.ceil(now / intervalMs) * intervalMs
}

/** Time remaining until next batch window (ms) */
export function msUntilNextBatch(intervalMinutes: number): number {
  return Math.max(0, nextBatchWindow(intervalMinutes) - Date.now())
}

/** Wait until the next batch window. Returns a cancellable promise. */
export function waitForBatchWindow(intervalMinutes: number): {
  promise: Promise<void>
  cancel: () => void
  remainingMs: () => number
  targetTime: number
} {
  const targetTime = nextBatchWindow(intervalMinutes)
  let timerId: ReturnType<typeof setTimeout> | null = null
  let rejectFn: ((reason: Error) => void) | null = null

  const promise = new Promise<void>((resolve, reject) => {
    rejectFn = reject
    const delay = targetTime - Date.now()
    if (delay <= 0) {
      resolve()
      return
    }
    timerId = setTimeout(resolve, delay)
  })

  return {
    promise,
    cancel: () => {
      if (timerId !== null) clearTimeout(timerId)
      rejectFn?.(new Error('Batch window wait cancelled'))
    },
    remainingMs: () => Math.max(0, targetTime - Date.now()),
    targetTime,
  }
}

/** Format countdown as MM:SS */
export function formatBatchCountdown(ms: number): string {
  const totalSeconds = Math.ceil(ms / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
}
