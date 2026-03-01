import { useState, useEffect, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { CONTRACTS, ALGOD_CONFIG } from '../lib/config'
import algosdk from 'algosdk'

interface PoolState {
  totalDeposited: number // in ALGO
  depositCount: number
  isLoading: boolean
  error: string | null
  walletBalance: number // connected wallet's balance in ALGO
  refresh: () => void
}

export function usePoolState(): PoolState {
  const { activeAddress, algodClient } = useWallet()
  const [totalDeposited, setTotalDeposited] = useState(0)
  const [depositCount, setDepositCount] = useState(0)
  const [walletBalance, setWalletBalance] = useState(0)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchState = useCallback(async () => {
    setIsLoading(true)
    setError(null)

    try {
      // Use the algodClient from use-wallet if available, else create one
      const client = algodClient ?? new algosdk.Algodv2(
        ALGOD_CONFIG.token,
        ALGOD_CONFIG.baseServer,
        ALGOD_CONFIG.port,
      )

      // Get pool contract account info to read balance
      const poolAddr = CONTRACTS.PrivacyPool.appAddress
      try {
        const accountInfo = await client.accountInformation(poolAddr).do()
        const balanceMicroAlgo = Number(accountInfo.amount ?? 0)
        // Subtract minimum balance (0.1 ALGO)
        const available = Math.max(0, balanceMicroAlgo - 100_000)
        setTotalDeposited(available / 1_000_000)
      } catch {
        // Pool might not be funded yet
        setTotalDeposited(0)
      }

      // Try to read app global state for deposit count
      try {
        const appInfo = await client.getApplicationByID(CONTRACTS.PrivacyPool.appId).do()
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
    // Poll every 15s
    const interval = setInterval(fetchState, 15_000)
    return () => clearInterval(interval)
  }, [fetchState])

  return {
    totalDeposited,
    depositCount,
    isLoading,
    error,
    walletBalance,
    refresh: fetchState,
  }
}
