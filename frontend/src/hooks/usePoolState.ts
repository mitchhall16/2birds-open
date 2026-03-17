import { useState, useEffect, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { ALGOD_CONFIG, INDEXER_CONFIG, POOL_CONTRACTS, getAllPools } from '../lib/config'
import { loadNotes } from '../lib/privacy'
import { cachedGetApp, cachedGetAccount } from '../lib/algodCache'
import algosdk from 'algosdk'

interface PoolState {
  totalDeposited: number // total ALGO across all pools
  userBalance: number // this user's shielded notes total
  depositCount: number
  isLoading: boolean
  error: string | null
  walletBalance: number // connected wallet's balance in ALGO
  refresh: () => void
}

// Cache indexer withdrawal totals per pool, keyed by depositCount.
// Only re-query indexer when deposit count changes (withdrawals are rare events).
const indexerCache = new Map<string, { depositCount: number; totalOut: number }>()

/**
 * Compute pool balance from on-chain state: depositCount × denomination.
 * Uses next_idx (number of deposits) and denom (denomination) from global state.
 * Then subtracts any inner-txn withdrawals to get actual shielded balance.
 */
async function fetchPoolDeposits(appId: number, poolAddr: string, client: algosdk.Algodv2): Promise<number> {
  // Read deposit count and denomination from on-chain state (via cache)
  let depositCount = 0
  let denomination = 0
  try {
    const appInfo = await cachedGetApp(client, appId)
    const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
    for (const kv of globalState as any[]) {
      const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
      if (key === 'next_idx') depositCount = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
      if (key === 'denom') denomination = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
    }
  } catch { return 0 }

  const totalIn = depositCount * denomination

  // Check if we can reuse cached indexer withdrawal total
  const cacheKey = `${appId}`
  const cached = indexerCache.get(cacheKey)
  if (cached && cached.depositCount === depositCount) {
    return Math.max(0, totalIn - cached.totalOut)
  }

  // Deposit count changed — re-query indexer for withdrawal totals
  const base = INDEXER_CONFIG.baseServer.replace(/\/$/, '')
  let totalOut = 0
  let nextToken = ''
  do {
    const url = `${base}/v2/transactions?address=${poolAddr}&tx-type=appl&limit=100${nextToken ? `&next=${nextToken}` : ''}`
    const res = await fetch(url)
    const data = await res.json()
    for (const tx of data.transactions ?? []) {
      for (const itx of tx['inner-txns'] ?? []) {
        if (itx['tx-type'] === 'pay') {
          const receiver = itx['payment-transaction']?.receiver ?? ''
          if (receiver !== poolAddr) {
            totalOut += itx['payment-transaction']?.amount ?? 0
          }
        }
      }
    }
    nextToken = data['next-token'] ?? ''
  } while (nextToken)

  indexerCache.set(cacheKey, { depositCount, totalOut })
  return Math.max(0, totalIn - totalOut)
}

export function usePoolState(): PoolState {
  const { activeAddress, algodClient } = useWallet()
  const [totalDeposited, setTotalDeposited] = useState(0)
  const [userBalance, setUserBalance] = useState(0)
  const [depositCount, setDepositCount] = useState(0)
  const [walletBalance, setWalletBalance] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchState = useCallback(async () => {
    setIsLoading(true)
    setError(null)

    try {
      const client = algodClient ?? new algosdk.Algodv2(
        ALGOD_CONFIG.token,
        ALGOD_CONFIG.baseServer,
        ALGOD_CONFIG.port,
      )

      // Pool total: sum deposits across all pools (all generations)
      try {
        const pools = getAllPools()
        const totals = await Promise.all(pools.map(p => fetchPoolDeposits(p.appId, p.appAddress, client).catch(() => 0)))
        setTotalDeposited(totals.reduce((a, b) => a + b, 0) / 1_000_000)
      } catch {
        setTotalDeposited(0)
      }

      // User's shielded balance from their local notes
      try {
        const notes = await loadNotes()
        const userTotal = notes.reduce((sum, n) => sum + Number(n.denomination), 0)
        setUserBalance(userTotal / 1_000_000)
      } catch {
        setUserBalance(0)
      }

      // Deposit count: sum next_idx across all pools (all generations)
      try {
        const pools = getAllPools()
        let total = 0
        for (const p of pools) {
          try {
            const appInfo = await cachedGetApp(client, p.appId)
            const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
            for (const kv of globalState as any[]) {
              const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
              if (key === 'next_idx') {
                total += Number(kv.value?.uint ?? kv.value?.ui ?? 0)
              }
            }
          } catch { /* skip unavailable pools */ }
        }
        setDepositCount(total)
      } catch {
        setDepositCount(0)
      }

      // Get connected wallet balance
      if (activeAddress) {
        try {
          const acctInfo = await cachedGetAccount(client, activeAddress)
          setWalletBalance(Number(acctInfo.amount ?? 0) / 1_000_000)
        } catch {
          setWalletBalance(0)
        }
      } else {
        setWalletBalance(0)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch pool state')
    } finally {
      setIsLoading(false)
    }
  }, [activeAddress, algodClient])

  useEffect(() => {
    fetchState()
    const interval = setInterval(fetchState, 60_000)
    return () => clearInterval(interval)
  }, [fetchState])

  return {
    totalDeposited,
    userBalance,
    depositCount,
    isLoading,
    error,
    walletBalance,
    refresh: fetchState,
  }
}
