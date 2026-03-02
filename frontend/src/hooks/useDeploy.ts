import { useState, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import algosdk from 'algosdk'
import { ALGOD_CONFIG } from '../lib/config'
import { useToast } from '../contexts/ToastContext'
import { humanizeError } from '../lib/errorMessages'

// Base64-encoded TEAL source from compiled ARC-56 artifact
import arc56 from '../../../contracts/artifacts/PrivacyPool.arc56.json'

interface DeployState {
  deploying: boolean
  appId: number | null
  appAddress: string | null
  error: string | null
}

export function useDeploy() {
  const { activeAddress, transactionSigner, algodClient } = useWallet()
  const { addToast } = useToast()
  const [state, setState] = useState<DeployState>({
    deploying: false,
    appId: null,
    appAddress: null,
    error: null,
  })

  const deploy = useCallback(async () => {
    if (!activeAddress || !transactionSigner) {
      addToast('error', 'Connect wallet first')
      setState(s => ({ ...s, error: 'Connect wallet first' }))
      return
    }

    setState({ deploying: true, appId: null, appAddress: null, error: null })

    try {
      const client = algodClient ?? new algosdk.Algodv2(
        ALGOD_CONFIG.token,
        ALGOD_CONFIG.baseServer,
        ALGOD_CONFIG.port,
      )

      // Decode TEAL source from ARC-56
      const approvalTeal = atob(arc56.source.approval)
      const clearTeal = atob(arc56.source.clear)

      // Compile TEAL to bytecode via algod
      const approvalCompiled = await client.compile(new TextEncoder().encode(approvalTeal)).do()
      const clearCompiled = await client.compile(new TextEncoder().encode(clearTeal)).do()

      const approvalBytes = new Uint8Array(
        atob(approvalCompiled.result).split('').map(c => c.charCodeAt(0))
      )
      const clearBytes = new Uint8Array(
        atob(clearCompiled.result).split('').map(c => c.charCodeAt(0))
      )

      // Method selector for createApplication(uint64,uint64)void
      const selectorHash = new Uint8Array(
        await crypto.subtle.digest(
          'SHA-512',
          new TextEncoder().encode('createApplication(uint64,uint64)void')
        )
      )
      // SHA-512/256 = first 32 bytes of SHA-512, then take first 4
      // Actually, ARC-4 uses SHA-512/256. Let's compute it properly.
      // We'll use the known selector from the TEAL: 0x917c48b6
      const methodSelector = new Uint8Array([0x91, 0x7c, 0x48, 0xb6])

      // ABI-encode uint64 args
      function abiUint64(n: number): Uint8Array {
        const buf = new Uint8Array(8)
        const view = new DataView(buf.buffer)
        view.setBigUint64(0, BigInt(n))
        return buf
      }

      const schema = arc56.state.schema
      const params = await client.getTransactionParams().do()

      const createTxn = algosdk.makeApplicationCreateTxnFromObject({
        sender: activeAddress,
        approvalProgram: approvalBytes,
        clearProgram: clearBytes,
        numGlobalInts: schema.global.ints,
        numGlobalByteSlices: schema.global.bytes,
        numLocalInts: schema.local.ints,
        numLocalByteSlices: schema.local.bytes,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          methodSelector,
          abiUint64(1_000_000), // denomination (reference)
          abiUint64(0),          // ALGO (not ASA)
        ],
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const signed = await transactionSigner([createTxn], [0])
      const resp = await client.sendRawTransaction(signed).do()
      const txId = (resp as any).txid ?? (resp as any).txId
      const confirmed = await algosdk.waitForConfirmation(client, txId, 4)
      const appId = Number((confirmed as any).applicationIndex)
      const appAddress = String(algosdk.getApplicationAddress(appId))

      // Fund the contract with 0.5 ALGO for MBR
      const fundParams = await client.getTransactionParams().do()
      const fundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: appAddress,
        amount: 500_000,
        suggestedParams: fundParams,
      })
      const signedFund = await transactionSigner([fundTxn], [0])
      const fundResp = await client.sendRawTransaction(signedFund).do()
      const fundTxId = (fundResp as any).txid ?? (fundResp as any).txId
      await algosdk.waitForConfirmation(client, fundTxId, 4)

      setState({
        deploying: false,
        appId,
        appAddress,
        error: null,
      })

      // Save to localStorage so we can use the new contract
      localStorage.setItem('privacy_pool_app_id', appId.toString())
      localStorage.setItem('privacy_pool_app_address', appAddress)

      addToast('success', `Contract deployed! App ID: ${appId}`)
      console.log(`Deployed PrivacyPool v2: appId=${appId}, appAddress=${appAddress}`)
    } catch (err) {
      const msg = humanizeError(err)
      console.error('Deploy error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, deploying: false, error: msg }))
    }
  }, [activeAddress, transactionSigner, algodClient, addToast])

  return { ...state, deploy }
}
