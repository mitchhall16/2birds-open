import { useState, useEffect, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { CONTRACTS, ALGOD_CONFIG, INDEXER_CONFIG } from '../lib/config'
import { loadNotes } from '../lib/privacy'
import algosdk from 'algosdk'

interface PoolState {
  totalDeposited: number // total user-deposited ALGO in the pool
  userBalance: number // this user's shielded notes total
  depositCount: number
  isLoading: boolean
  error: string | null
  walletBalance: number // connected wallet's balance in ALGO
  refresh: () => void
}

/**
 * Query the indexer to compute real user deposits in the pool.
 * Only counts payments that are part of an atomic group (deposit txns),
 * and subtracts inner-transaction withdrawals from app calls.
 */
async function fetchPoolDeposits(poolAddr: string): Promise<number> {
  const base = INDEXER_CONFIG.baseServer.replace(/\/$/, '')

  // 1. Sum grouped payment txns TO the pool (real deposits)
  let totalIn = 0
  let nextToken = ''
  do {
    const url = `${base}/v2/transactions?address=${poolAddr}&address-role=receiver&tx-type=pay&limit=100${nextToken ? `&next=${nextToken}` : ''}`
    const res = await fetch(url)
    const data = await res.json()
    for (const tx of data.transactions ?? []) {
      if (tx.group) {
        totalIn += tx['payment-transaction']?.amount ?? 0
      }
    }
    nextToken = data['next-token'] ?? ''
  } while (nextToken)

  // 2. Sum inner-txn withdrawals (app calls that produce inner pay txns out)
  let totalOut = 0
  nextToken = ''
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

  return Math.max(0, totalIn - totalOut) / 1_000_000
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

      const poolAddr = CONTRACTS.PrivacyPool.appAddress
      const appId = CONTRACTS.PrivacyPool.appId

      // Pool total via indexer (grouped deposits minus withdrawals)
      try {
        const poolTotal = await fetchPoolDeposits(poolAddr)
        setTotalDeposited(poolTotal)
      } catch {
        setTotalDeposited(0)
      }

      // User's shielded balance from their local notes
      try {
        const notes = loadNotes()
        const userTotal = notes.reduce((sum, n) => sum + Number(n.denomination), 0)
        setUserBalance(userTotal / 1_000_000)
      } catch {
        setUserBalance(0)
      }

      // Deposit count from global state
      try {
        const appInfo = await client.getApplicationByID(appId).do()
        const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
        for (const kv of globalState as any[]) {
          const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
          if (key === 'next_idx') {
            setDepositCount(Number(kv.value?.uint ?? kv.value?.ui ?? 0))
          }
        }
      } catch {
        setDepositCount(0)
      }

      // Get connected wallet balance
      if (activeAddress) {
        try {
          const acctInfo = await client.accountInformation(activeAddress).do()
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
    const interval = setInterval(fetchState, 30_000)
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
