/**
 * Falcon-1024 Post-Quantum Mode — React Context
 *
 * EXPERIMENTAL: Provides post-quantum SIGNING only. Note encryption (HPKE)
 * still uses X25519 which is NOT post-quantum secure. See hpke.ts and
 * falcon.ts for detailed security analysis. This is defense-in-depth,
 * not a complete post-quantum solution.
 *
 * Manages the opt-in Falcon mode state: toggle, keypair derivation,
 * compiled LogicSig program, Falcon address funding status, and balance.
 *
 * Toggle is persisted in localStorage. Keypair is derived deterministically
 * from the master key (same wallet + password = same Falcon address).
 */

import { createContext, useContext, useState, useCallback, useRef, type ReactNode } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import algosdk from 'algosdk'
import { ALGOD_CONFIG } from '../lib/config'
import {
  deriveFalconKeypair,
  compileFalconProgram,
  createFalconSigner,
  clearFalconCache,
  type FalconAccount,
} from '../lib/falcon'

// ── Types ──

export interface DeriveResult {
  account: FalconAccount
  funded: boolean
  balance: bigint
}

interface FalconContextValue {
  enabled: boolean
  account: FalconAccount | null
  funded: boolean
  balance: bigint
  loading: boolean
  error: string | null
  setEnabled: (v: boolean) => void
  /** Derive Falcon keypair from master key. Returns result for immediate use (React state updates async). */
  derive: (masterKey: bigint) => Promise<DeriveResult | null>
  /** Refresh balance from algod. */
  refresh: () => Promise<void>
  /** Fund the Falcon address from the connected wallet. */
  fundFalcon: (walletSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>, walletAddress: string, amount?: bigint) => Promise<string>
  /** Transaction signer using Falcon LogicSig (null if not derived yet). */
  signer: ((txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>) | null
}

const FalconContext = createContext<FalconContextValue | null>(null)

// ── Provider ──

export function FalconProvider({ children }: { children: ReactNode }) {
  const { algodClient } = useWallet()

  const [enabled, setEnabledState] = useState(
    () => localStorage.getItem('falcon_enabled') === 'true',
  )
  const [account, setAccount] = useState<FalconAccount | null>(null)
  const [funded, setFunded] = useState(false)
  const [balance, setBalance] = useState(0n)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const derivedForKey = useRef<bigint | null>(null)

  const getClient = useCallback(
    () =>
      algodClient ??
      new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port),
    [algodClient],
  )

  const setEnabled = useCallback((v: boolean) => {
    setEnabledState(v)
    localStorage.setItem('falcon_enabled', String(v))
    if (!v) {
      setAccount(null)
      setFunded(false)
      setBalance(0n)
      setError(null)
      clearFalconCache()
    }
  }, [])

  const derive = useCallback(
    async (masterKey: bigint): Promise<DeriveResult | null> => {
      // Skip if already derived for this master key
      if (account && derivedForKey.current === masterKey) {
        return { account, funded, balance }
      }

      setLoading(true)
      setError(null)

      try {
        const client = getClient()
        const keypair = await deriveFalconKeypair(masterKey)
        const { program, address } = await compileFalconProgram(client, keypair.publicKey)

        // Check funding status
        let bal = 0n
        let isFunded = false
        try {
          const info = await client.accountInformation(address).do()
          bal = BigInt(info.amount)
          isFunded = bal > 100_000n
        } catch {
          // Account may not exist yet (never funded)
        }

        const acct: FalconAccount = {
          publicKey: keypair.publicKey,
          privateKey: keypair.privateKey,
          program,
          address,
        }

        setAccount(acct)
        setFunded(isFunded)
        setBalance(bal)
        derivedForKey.current = masterKey
        setLoading(false)

        return { account: acct, funded: isFunded, balance: bal }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        console.error('[Falcon] Derivation failed:', err)
        setError(msg)
        setLoading(false)
        throw err
      }
    },
    [account, funded, balance, getClient],
  )

  const refresh = useCallback(async () => {
    if (!account) return
    try {
      const client = getClient()
      const info = await client.accountInformation(account.address).do()
      const bal = BigInt(info.amount)
      setBalance(bal)
      setFunded(bal > 100_000n)
    } catch {
      // Network error — keep existing state
    }
  }, [account, getClient])

  const fundFalcon = useCallback(
    async (
      walletSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>,
      walletAddress: string,
      amount: bigint = 500_000n, // 0.5 ALGO default
    ): Promise<string> => {
      if (!account) throw new Error('Falcon account not derived yet')
      const client = getClient()
      const params = await client.getTransactionParams().do()
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: walletAddress,
        receiver: account.address,
        amount,
        suggestedParams: params,
      })
      const signed = await walletSigner([txn], [0])
      await client.sendRawTransaction(signed[0]).do()
      await algosdk.waitForConfirmation(client, txn.txID(), 4)
      // Refresh balance after funding
      const info = await client.accountInformation(account.address).do()
      const bal = BigInt(info.amount)
      setBalance(bal)
      setFunded(bal > 100_000n)
      return txn.txID()
    },
    [account, getClient],
  )

  const signer = account
    ? createFalconSigner(account.program, account.privateKey)
    : null

  return (
    <FalconContext.Provider
      value={{
        enabled,
        account,
        funded,
        balance,
        loading,
        error,
        setEnabled,
        derive,
        refresh,
        fundFalcon,
        signer,
      }}
    >
      {children}
    </FalconContext.Provider>
  )
}

// ── Hook ──

export function useFalcon(): FalconContextValue {
  const ctx = useContext(FalconContext)
  if (!ctx) throw new Error('useFalcon must be used within a FalconProvider')
  return ctx
}
