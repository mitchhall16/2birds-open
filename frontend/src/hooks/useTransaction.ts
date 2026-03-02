import { useState, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import algosdk from 'algosdk'
import { CONTRACTS, ALGOD_CONFIG, FEES } from '../lib/config'
import { useToast } from '../contexts/ToastContext'
import { humanizeError } from '../lib/errorMessages'
import {
  initMimc,
  deriveDeposit,
  deriveMasterKey,
  getCachedMasterKey,
  getNextDepositIndex,
  incrementDepositIndex,
  computeNullifierHash,
  scalarToBytes,
  uint64ToBytes,
  abiEncodeBytes,
  addressToScalar,
  encodeProofForVerifier,
  encodePublicSignals,
  METHOD_SELECTORS,
  depositBoxRefs,
  nullifierBox,
  saveNote,
  loadNotes,
  removeNote,
  DepositNote,
} from '../lib/privacy'
import {
  getOrCreateTree,
  insertLeaf,
  getPath,
  saveTree,
} from '../lib/tree'

export type TxStage =
  | 'idle'
  | 'depositing'
  | 'deposit_complete'
  | 'generating_proof'
  | 'withdrawing'
  | 'withdraw_complete'
  | 'splitting'
  | 'split_complete'
  | 'combining'
  | 'combine_complete'
  | 'error'

interface TxState {
  stage: TxStage
  message: string
  txId: string | null
  error: string | null
  savedNotes: DepositNote[]
}

interface UseTransactionReturn extends TxState {
  deposit: (amountAlgo: number) => Promise<void>
  withdraw: (noteIndex: number, destinationAddr: string) => Promise<void>
  privateSend: (amountAlgo: number, destinationAddr: string) => Promise<void>
  splitNote: (noteIndex: number, splitAmountAlgo: number) => Promise<void>
  combineNotes: (noteIndices: number[]) => Promise<void>
  reset: () => void
  refreshNotes: () => void
}

const APP_ID = CONTRACTS.PrivacyPool.appId
const APP_ADDR = CONTRACTS.PrivacyPool.appAddress
const VERIFIER_APP_ID = CONTRACTS.ZkVerifier.appId
const BUDGET_HELPER_APP_ID = CONTRACTS.ZkVerifier.budgetHelperAppId

export function useTransaction(): UseTransactionReturn {
  const { activeAddress, transactionSigner, algodClient, signData } = useWallet()
  const { addToast } = useToast()
  const [state, setState] = useState<TxState>({
    stage: 'idle',
    message: '',
    txId: null,
    error: null,
    savedNotes: loadNotes(),
  })

  const getClient = useCallback(() => {
    return algodClient ?? new algosdk.Algodv2(
      ALGOD_CONFIG.token,
      ALGOD_CONFIG.baseServer,
      ALGOD_CONFIG.port,
    )
  }, [algodClient])

  /** Read contract global state */
  async function readContractState(client: algosdk.Algodv2) {
    const appInfo = await client.getApplicationByID(APP_ID).do()
    const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []

    let currentRoot = new Uint8Array(32)
    let rootHistoryIndex = 0
    let nextIndex = 0

    for (const kv of globalState) {
      const key = typeof kv.key === 'string' ? atob(kv.key) : new TextDecoder().decode(kv.key)
      if (key === 'root') {
        const val = kv.value?.bytes ?? kv.value?.tb
        if (val) {
          currentRoot = typeof val === 'string' ? Uint8Array.from(atob(val), c => c.charCodeAt(0)) : val
        }
      } else if (key === 'rhi') {
        rootHistoryIndex = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
      } else if (key === 'next_idx') {
        nextIndex = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
      }
    }

    return { currentRoot, rootHistoryIndex, nextIndex }
  }

  // ── DEPOSIT ──────────────────────────────
  const deposit = useCallback(async (amountAlgo: number) => {
    if (!activeAddress || !transactionSigner) {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (amountAlgo <= 0 || amountAlgo > 1) {
      addToast('error', 'Amount must be between 0 and 1 ALGO')
      setState(s => ({ ...s, stage: 'error', error: 'Amount must be between 0 and 1 ALGO' }))
      return
    }

    const amountMicroAlgo = Math.round(amountAlgo * 1_000_000)
    const client = getClient()

    try {
      setState({ stage: 'depositing', message: 'Initializing cryptography...', txId: null, error: null, savedNotes: state.savedNotes })

      await initMimc()

      // Derive deterministic note from wallet signature (or use cached master key)
      setState(s => ({ ...s, message: 'Deriving deposit key...' }))
      const masterKey = await deriveMasterKey(signData)
      const depositIdx = getNextDepositIndex()
      const note = deriveDeposit(masterKey, depositIdx, BigInt(amountMicroAlgo), 0)
      const commitmentBytes = scalarToBytes(note.commitment)

      // Insert into local MiMC Merkle tree and get new root
      const tree = await getOrCreateTree()
      const { index: leafIndex, root: mimcRoot } = insertLeaf(tree, note.commitment)
      note.leafIndex = leafIndex

      const mimcRootBytes = scalarToBytes(mimcRoot)

      const contractState = await readContractState(client)

      setState(s => ({ ...s, message: 'Building deposit transaction...' }))
      const params = await client.getTransactionParams().do()

      // Only 3 box references needed (no on-chain tree)
      const boxes = depositBoxRefs(APP_ID, contractState.rootHistoryIndex, contractState.nextIndex)

      // Build group: [payment, app call] — just 2 transactions, no noops
      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: APP_ADDR,
        amount: amountMicroAlgo,
        suggestedParams: params,
      })

      const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(mimcRootBytes),
        ],
        boxes,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      algosdk.assignGroupID([payTxn, appCallTxn])

      setState(s => ({ ...s, message: 'Approve deposit in your wallet...' }))
      const signedTxns = await transactionSigner([payTxn, appCallTxn], [0, 1])

      setState(s => ({ ...s, message: 'Submitting deposit...' }))
      const result = await client.sendRawTransaction(signedTxns).do()
      const txId = (result as any).txid ?? (result as any).txId

      setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
      await algosdk.waitForConfirmation(client, txId, 4)

      // Persist note, tree, and increment deterministic counter
      saveNote(note)
      saveTree(tree)
      incrementDepositIndex()

      addToast('success', `Deposited ${amountAlgo} ALGO into the privacy pool`)
      setState({
        stage: 'deposit_complete',
        message: `Deposit confirmed! ${amountAlgo} ALGO is now shielded in the pool.`,
        txId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = humanizeError(err)
      console.error('Deposit error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, signData, getClient, state.savedNotes, addToast])

  // ── WITHDRAW ─────────────────────────────
  const withdraw = useCallback(async (noteIndex: number, destinationAddr: string) => {
    if (!activeAddress || !transactionSigner) {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (!algosdk.isValidAddress(destinationAddr)) {
      addToast('error', 'Invalid destination address')
      setState(s => ({ ...s, stage: 'error', error: 'Invalid destination address' }))
      return
    }

    const notes = loadNotes()
    if (noteIndex < 0 || noteIndex >= notes.length) {
      addToast('error', 'No deposit note found')
      setState(s => ({ ...s, stage: 'error', error: 'No deposit note found' }))
      return
    }

    const note = notes[noteIndex]
    const client = getClient()

    try {
      setState(s => ({ ...s, stage: 'withdrawing', message: 'Initializing cryptography...', txId: null, error: null }))

      await initMimc()

      // Load local Merkle tree and get path for this deposit
      setState(s => ({ ...s, message: 'Loading Merkle tree...' }))
      const tree = await getOrCreateTree()
      const merklePath = getPath(tree, note.leafIndex)
      const root = tree.root

      // Generate ZK proof
      setState(s => ({ ...s, stage: 'generating_proof', message: 'Computing zero-knowledge proof... (10-30 sec)' }))

      const snarkjs = await import('snarkjs')

      const nullifierHash = computeNullifierHash(note.nullifier)
      const zeroAddr = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'

      const circuitInput = {
        // Public inputs
        root: root.toString(),
        nullifierHash: nullifierHash.toString(),
        recipient: addressToScalar(destinationAddr).toString(),
        relayer: addressToScalar(zeroAddr).toString(),
        fee: '0',
        // Private inputs
        secret: note.secret.toString(),
        nullifier: note.nullifier.toString(),
        pathElements: merklePath.pathElements.map(e => e.toString()),
        pathIndices: merklePath.pathIndices,
      }

      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput,
        '/circuits/withdraw.wasm',
        '/circuits/withdraw_final.zkey',
      )

      // Convert snarkjs proof to our format
      const groth16Proof = {
        pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])] as [bigint, bigint],
        pi_b: [
          [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
          [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
        ] as [[bigint, bigint], [bigint, bigint]],
        pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])] as [bigint, bigint],
      }

      setState(s => ({ ...s, stage: 'withdrawing', message: 'Building withdrawal transaction...' }))

      // Encode proof and public signals for verifier app
      const proofBytes = encodeProofForVerifier(groth16Proof)
      const signalsBytes = encodePublicSignals(root, nullifierHash, destinationAddr, zeroAddr, 0n)

      const params = await client.getTransactionParams().do()
      const nullifierHashBytes = scalarToBytes(nullifierHash)
      const withdrawAmount = Number(note.denomination)

      // Build 2-txn atomic group:
      // [0] App call to ZK verifier (proof + signals as args, fee covers inner budget padding calls)
      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: VERIFIER_APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: [BUDGET_HELPER_APP_ID],
        suggestedParams: { ...params, fee: FEES.verifierCall, flatFee: true },
      })

      // [1] App call — withdraw(nullifierHash, recipient, relayer, fee, root, amount)
      const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
      const relayerPubKey = algosdk.decodeAddress(zeroAddr).publicKey
      const rootBytes = scalarToBytes(root)

      const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.withdraw,
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(0n),
          abiEncodeBytes(rootBytes),
          uint64ToBytes(BigInt(withdrawAmount)),
        ],
        accounts: [destinationAddr],
        boxes: [nullifierBox(APP_ID, nullifierHashBytes)],
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      algosdk.assignGroupID([verifierAppCall, withdrawAppCall])

      setState(s => ({ ...s, message: 'Approve withdrawal in your wallet...' }))

      // User signs both transactions
      const signedTxns = await transactionSigner(
        [verifierAppCall, withdrawAppCall],
        [0, 1],
      )

      const txId = withdrawAppCall.txID()

      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(signedTxns).do()

      setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
      await algosdk.waitForConfirmation(client, txId, 4)

      // Remove used note
      removeNote(noteIndex)

      const algoAmount = (Number(note.denomination) / 1_000_000).toFixed(6).replace(/\.?0+$/, '')
      addToast('success', `Withdrew ${algoAmount} ALGO to destination`)
      setState({
        stage: 'withdraw_complete',
        message: `${algoAmount} ALGO withdrawn from the pool to the destination!`,
        txId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = humanizeError(err)
      console.error('Withdraw error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, getClient, addToast])

  // ── PRIVATE SEND (deposit → immediate withdraw) ──
  const privateSend = useCallback(async (amountAlgo: number, destinationAddr: string) => {
    if (!activeAddress || !transactionSigner) {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }
    if (amountAlgo <= 0 || amountAlgo > 1) {
      addToast('error', 'Amount must be between 0 and 1 ALGO')
      setState(s => ({ ...s, stage: 'error', error: 'Amount must be between 0 and 1 ALGO' }))
      return
    }
    if (!algosdk.isValidAddress(destinationAddr)) {
      addToast('error', 'Invalid destination address')
      setState(s => ({ ...s, stage: 'error', error: 'Invalid destination address' }))
      return
    }

    const amountMicroAlgo = Math.round(amountAlgo * 1_000_000)
    const client = getClient()

    try {
      // ── Step 1: Deposit ──
      setState({ stage: 'depositing', message: 'Initializing cryptography...', txId: null, error: null, savedNotes: state.savedNotes })

      await initMimc()

      setState(s => ({ ...s, message: 'Deriving deposit key...' }))
      const masterKey = await deriveMasterKey(signData)
      const depositIdx = getNextDepositIndex()
      const note = deriveDeposit(masterKey, depositIdx, BigInt(amountMicroAlgo), 0)
      const commitmentBytes = scalarToBytes(note.commitment)

      // Insert into local MiMC Merkle tree
      const tree = await getOrCreateTree()
      const { index: leafIndex, root: mimcRoot } = insertLeaf(tree, note.commitment)
      note.leafIndex = leafIndex

      const mimcRootBytes = scalarToBytes(mimcRoot)

      let contractState = await readContractState(client)

      setState(s => ({ ...s, message: 'Building deposit transaction...' }))
      let params = await client.getTransactionParams().do()

      const boxes = depositBoxRefs(APP_ID, contractState.rootHistoryIndex, contractState.nextIndex)

      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: APP_ADDR,
        amount: amountMicroAlgo,
        suggestedParams: params,
      })

      const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(mimcRootBytes),
        ],
        boxes,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      algosdk.assignGroupID([payTxn, appCallTxn])

      setState(s => ({ ...s, message: 'Approve deposit in your wallet...' }))
      const depositSigned = await transactionSigner([payTxn, appCallTxn], [0, 1])

      setState(s => ({ ...s, message: 'Submitting deposit...' }))
      const depositResult = await client.sendRawTransaction(depositSigned).do()
      const depositTxId = (depositResult as any).txid ?? (depositResult as any).txId

      setState(s => ({ ...s, message: 'Waiting for deposit confirmation...' }))
      await algosdk.waitForConfirmation(client, depositTxId, 4)

      saveNote(note)
      saveTree(tree)
      incrementDepositIndex()

      // ── Step 2: Generate ZK proof ──
      setState(s => ({ ...s, stage: 'generating_proof', message: 'Computing zero-knowledge proof... (10-30 sec)', txId: depositTxId }))

      const snarkjs = await import('snarkjs')

      const nullifierHash = computeNullifierHash(note.nullifier)
      const root = tree.root
      const merklePath = getPath(tree, leafIndex)
      const zeroAddr = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'

      const circuitInput = {
        root: root.toString(),
        nullifierHash: nullifierHash.toString(),
        recipient: addressToScalar(destinationAddr).toString(),
        relayer: addressToScalar(zeroAddr).toString(),
        fee: '0',
        secret: note.secret.toString(),
        nullifier: note.nullifier.toString(),
        pathElements: merklePath.pathElements.map(e => e.toString()),
        pathIndices: merklePath.pathIndices,
      }

      const { proof } = await snarkjs.groth16.fullProve(
        circuitInput,
        '/circuits/withdraw.wasm',
        '/circuits/withdraw_final.zkey',
      )

      const groth16Proof = {
        pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])] as [bigint, bigint],
        pi_b: [
          [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
          [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
        ] as [[bigint, bigint], [bigint, bigint]],
        pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])] as [bigint, bigint],
      }

      // ── Step 3: Withdraw to destination ──
      setState(s => ({ ...s, stage: 'withdrawing', message: 'Building withdrawal transaction...' }))

      const proofBytes = encodeProofForVerifier(groth16Proof)
      const signalsBytes = encodePublicSignals(root, nullifierHash, destinationAddr, zeroAddr, 0n)

      params = await client.getTransactionParams().do()
      const nullifierHashBytes = scalarToBytes(nullifierHash)

      // [0] App call to ZK verifier
      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: VERIFIER_APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: [BUDGET_HELPER_APP_ID],
        suggestedParams: { ...params, fee: FEES.verifierCall, flatFee: true },
      })

      const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
      const relayerPubKey = algosdk.decodeAddress(zeroAddr).publicKey
      const rootBytes = scalarToBytes(root)

      // [1] App call — withdraw
      const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.withdraw,
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(0n),
          abiEncodeBytes(rootBytes),
          uint64ToBytes(BigInt(amountMicroAlgo)),
        ],
        accounts: [destinationAddr],
        boxes: [nullifierBox(APP_ID, nullifierHashBytes)],
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      algosdk.assignGroupID([verifierAppCall, withdrawAppCall])

      setState(s => ({ ...s, message: 'Approve withdrawal in your wallet...' }))
      const withdrawSigned = await transactionSigner(
        [verifierAppCall, withdrawAppCall],
        [0, 1],
      )

      const withdrawTxId = withdrawAppCall.txID()

      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(withdrawSigned).do()

      setState(s => ({ ...s, message: 'Waiting for withdrawal confirmation...' }))
      await algosdk.waitForConfirmation(client, withdrawTxId, 4)

      // Remove the note we just used
      const currentNotes = loadNotes()
      const usedIdx = currentNotes.findIndex(n =>
        n.nullifier === note.nullifier && n.secret === note.secret
      )
      if (usedIdx >= 0) removeNote(usedIdx)

      addToast('success', `${amountAlgo} ALGO sent privately to ${destinationAddr.slice(0, 6)}...${destinationAddr.slice(-4)}`)
      setState({
        stage: 'withdraw_complete',
        message: `${amountAlgo} ALGO sent privately to ${destinationAddr.slice(0, 6)}...${destinationAddr.slice(-4)}`,
        txId: withdrawTxId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = humanizeError(err)
      console.error('Private send error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, signData, getClient, state.savedNotes, addToast])

  // ── SPLIT NOTE ──────────────────────────
  const splitNote = useCallback(async (noteIndex: number, splitAmountAlgo: number) => {
    if (!activeAddress || !transactionSigner) {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    const notes = loadNotes()
    if (noteIndex < 0 || noteIndex >= notes.length) {
      addToast('error', 'Note not found')
      setState(s => ({ ...s, stage: 'error', error: 'Note not found' }))
      return
    }

    const note = notes[noteIndex]
    const totalAlgo = Number(note.denomination) / 1_000_000
    if (splitAmountAlgo <= 0 || splitAmountAlgo >= totalAlgo) {
      addToast('error', `Split amount must be between 0 and ${totalAlgo} ALGO`)
      setState(s => ({ ...s, stage: 'error', error: `Split amount must be between 0 and ${totalAlgo} ALGO` }))
      return
    }

    const client = getClient()

    try {
      setState({ stage: 'splitting', message: 'Withdrawing original note (step 1/3)...', txId: null, error: null, savedNotes: state.savedNotes })

      // Step 1: Withdraw the original note to self
      await initMimc()

      const tree = await getOrCreateTree()
      const merklePath = getPath(tree, note.leafIndex)
      const root = tree.root

      setState(s => ({ ...s, stage: 'generating_proof', message: 'Computing zero-knowledge proof for withdrawal... (10-30 sec)' }))

      const snarkjs = await import('snarkjs')
      const nullifierHash = computeNullifierHash(note.nullifier)
      const zeroAddr = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'

      const circuitInput = {
        root: root.toString(),
        nullifierHash: nullifierHash.toString(),
        recipient: addressToScalar(activeAddress).toString(),
        relayer: addressToScalar(zeroAddr).toString(),
        fee: '0',
        secret: note.secret.toString(),
        nullifier: note.nullifier.toString(),
        pathElements: merklePath.pathElements.map(e => e.toString()),
        pathIndices: merklePath.pathIndices,
      }

      const { proof } = await snarkjs.groth16.fullProve(
        circuitInput,
        '/circuits/withdraw.wasm',
        '/circuits/withdraw_final.zkey',
      )

      const groth16Proof = {
        pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])] as [bigint, bigint],
        pi_b: [
          [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
          [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
        ] as [[bigint, bigint], [bigint, bigint]],
        pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])] as [bigint, bigint],
      }

      setState(s => ({ ...s, stage: 'splitting', message: 'Building withdrawal transaction...' }))

      const proofBytes = encodeProofForVerifier(groth16Proof)
      const signalsBytes = encodePublicSignals(root, nullifierHash, activeAddress, zeroAddr, 0n)

      let params = await client.getTransactionParams().do()
      const nullifierHashBytes = scalarToBytes(nullifierHash)
      const withdrawAmount = Number(note.denomination)

      // [0] App call to ZK verifier
      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: VERIFIER_APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: [BUDGET_HELPER_APP_ID],
        suggestedParams: { ...params, fee: FEES.verifierCall, flatFee: true },
      })

      const recipientPubKey = algosdk.decodeAddress(activeAddress).publicKey
      const relayerPubKey = algosdk.decodeAddress(zeroAddr).publicKey
      const rootBytes = scalarToBytes(root)

      // [1] App call — withdraw
      const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.withdraw,
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(0n),
          abiEncodeBytes(rootBytes),
          uint64ToBytes(BigInt(withdrawAmount)),
        ],
        accounts: [activeAddress],
        boxes: [nullifierBox(APP_ID, nullifierHashBytes)],
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      algosdk.assignGroupID([verifierAppCall, withdrawAppCall])

      setState(s => ({ ...s, message: 'Approve withdrawal in your wallet...' }))
      const signedGroup = await transactionSigner(
        [verifierAppCall, withdrawAppCall],
        [0, 1],
      )

      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(signedGroup).do()
      const withdrawTxId = withdrawAppCall.txID()
      await algosdk.waitForConfirmation(client, withdrawTxId, 4)

      // Remove the original note
      removeNote(noteIndex)

      // Step 2: Deposit first split amount
      const splitMicro1 = Math.round(splitAmountAlgo * 1_000_000)
      const splitMicro2 = withdrawAmount - splitMicro1

      setState(s => ({ ...s, message: `Depositing ${splitAmountAlgo} ALGO (step 2/3)...` }))

      const masterKey = await deriveMasterKey(signData)

      const depositIdx1 = getNextDepositIndex()
      const note1 = deriveDeposit(masterKey, depositIdx1, BigInt(splitMicro1), 0)
      const commitment1 = scalarToBytes(note1.commitment)
      const { index: leaf1, root: root1 } = insertLeaf(tree, note1.commitment)
      note1.leafIndex = leaf1

      let contractState = await readContractState(client)
      params = await client.getTransactionParams().do()

      const boxes1 = depositBoxRefs(APP_ID, contractState.rootHistoryIndex, contractState.nextIndex)
      const payTxn1 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: APP_ADDR,
        amount: splitMicro1,
        suggestedParams: params,
      })
      const appCall1 = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitment1),
          abiEncodeBytes(scalarToBytes(root1)),
        ],
        boxes: boxes1,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })
      algosdk.assignGroupID([payTxn1, appCall1])

      setState(s => ({ ...s, message: 'Approve first deposit in your wallet...' }))
      const signed1 = await transactionSigner([payTxn1, appCall1], [0, 1])
      const res1 = await client.sendRawTransaction(signed1).do()
      const txId1 = (res1 as any).txid ?? (res1 as any).txId ?? appCall1.txID()
      await algosdk.waitForConfirmation(client, txId1, 4)

      saveNote(note1)
      saveTree(tree)
      incrementDepositIndex()

      // Step 3: Deposit second split amount
      const splitAlgo2 = splitMicro2 / 1_000_000
      setState(s => ({ ...s, message: `Depositing ${splitAlgo2} ALGO (step 3/3)...` }))

      const depositIdx2 = getNextDepositIndex()
      const note2 = deriveDeposit(masterKey, depositIdx2, BigInt(splitMicro2), 0)
      const commitment2 = scalarToBytes(note2.commitment)
      const { index: leaf2, root: root2 } = insertLeaf(tree, note2.commitment)
      note2.leafIndex = leaf2

      contractState = await readContractState(client)
      params = await client.getTransactionParams().do()

      const boxes2 = depositBoxRefs(APP_ID, contractState.rootHistoryIndex, contractState.nextIndex)
      const payTxn2 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: APP_ADDR,
        amount: splitMicro2,
        suggestedParams: params,
      })
      const appCall2 = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitment2),
          abiEncodeBytes(scalarToBytes(root2)),
        ],
        boxes: boxes2,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })
      algosdk.assignGroupID([payTxn2, appCall2])

      setState(s => ({ ...s, message: 'Approve second deposit in your wallet...' }))
      const signed2 = await transactionSigner([payTxn2, appCall2], [0, 1])
      const res2 = await client.sendRawTransaction(signed2).do()
      const txId2 = (res2 as any).txid ?? (res2 as any).txId ?? appCall2.txID()
      await algosdk.waitForConfirmation(client, txId2, 4)

      saveNote(note2)
      saveTree(tree)
      incrementDepositIndex()

      addToast('success', `Split ${totalAlgo} ALGO into ${splitAmountAlgo} + ${splitAlgo2} ALGO`)
      setState({
        stage: 'split_complete',
        message: `Split complete! ${totalAlgo} ALGO → ${splitAmountAlgo} + ${splitAlgo2} ALGO`,
        txId: withdrawTxId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = humanizeError(err)
      console.error('Split error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg, savedNotes: loadNotes() }))
    }
  }, [activeAddress, transactionSigner, signData, getClient, state.savedNotes, addToast])

  // ── COMBINE NOTES ──────────────────────────
  const combineNotes = useCallback(async (noteIndices: number[]) => {
    if (!activeAddress || !transactionSigner) {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (noteIndices.length < 2) {
      addToast('error', 'Select at least 2 notes to combine')
      setState(s => ({ ...s, stage: 'error', error: 'Select at least 2 notes to combine' }))
      return
    }

    const allNotes = loadNotes()
    const selectedNotes = noteIndices.map(i => allNotes[i])
    if (selectedNotes.some(n => !n)) {
      addToast('error', 'One or more notes not found')
      setState(s => ({ ...s, stage: 'error', error: 'One or more notes not found' }))
      return
    }

    const totalMicro = selectedNotes.reduce((sum, n) => sum + Number(n.denomination), 0)
    const totalAlgo = totalMicro / 1_000_000
    const client = getClient()

    try {
      setState({ stage: 'combining', message: 'Initializing cryptography...', txId: null, error: null, savedNotes: state.savedNotes })

      await initMimc()
      const tree = await getOrCreateTree()
      const snarkjs = await import('snarkjs')
      const zeroAddr = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'

      // Step 1: Withdraw each note to self
      // Process in reverse index order so removal doesn't shift indices
      const sortedIndices = [...noteIndices].sort((a, b) => b - a)

      for (let wi = 0; wi < selectedNotes.length; wi++) {
        const origIdx = noteIndices[wi]
        const note = selectedNotes[wi]

        setState(s => ({ ...s, stage: 'generating_proof', message: `Computing proof ${wi + 1}/${selectedNotes.length}... (10-30 sec)` }))

        const merklePath = getPath(tree, note.leafIndex)
        const root = tree.root

        const nullifierHash = computeNullifierHash(note.nullifier)
        const circuitInput = {
          root: root.toString(),
          nullifierHash: nullifierHash.toString(),
          recipient: addressToScalar(activeAddress).toString(),
          relayer: addressToScalar(zeroAddr).toString(),
          fee: '0',
          secret: note.secret.toString(),
          nullifier: note.nullifier.toString(),
          pathElements: merklePath.pathElements.map(e => e.toString()),
          pathIndices: merklePath.pathIndices,
        }

        const { proof } = await snarkjs.groth16.fullProve(
          circuitInput,
          '/circuits/withdraw.wasm',
          '/circuits/withdraw_final.zkey',
        )

        const groth16Proof = {
          pi_a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])] as [bigint, bigint],
          pi_b: [
            [BigInt(proof.pi_b[0][0]), BigInt(proof.pi_b[0][1])],
            [BigInt(proof.pi_b[1][0]), BigInt(proof.pi_b[1][1])],
          ] as [[bigint, bigint], [bigint, bigint]],
          pi_c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])] as [bigint, bigint],
        }

        setState(s => ({ ...s, stage: 'combining', message: `Withdrawing note ${wi + 1}/${selectedNotes.length}...` }))

        const proofBytes = encodeProofForVerifier(groth16Proof)
        const signalsBytes = encodePublicSignals(root, nullifierHash, activeAddress, zeroAddr, 0n)

        const params = await client.getTransactionParams().do()
        const nullifierHashBytes = scalarToBytes(nullifierHash)

        // [0] App call to ZK verifier
        const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
          sender: activeAddress,
          appIndex: VERIFIER_APP_ID,
          onComplete: algosdk.OnApplicationComplete.NoOpOC,
          appArgs: [proofBytes, signalsBytes],
          foreignApps: [BUDGET_HELPER_APP_ID],
          suggestedParams: { ...params, fee: FEES.verifierCall, flatFee: true },
        })

        const recipientPubKey = algosdk.decodeAddress(activeAddress).publicKey
        const relayerPubKey = algosdk.decodeAddress(zeroAddr).publicKey
        const rootBytes = scalarToBytes(root)

        // [1] App call — withdraw
        const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
          sender: activeAddress,
          appIndex: APP_ID,
          onComplete: algosdk.OnApplicationComplete.NoOpOC,
          appArgs: [
            METHOD_SELECTORS.withdraw,
            abiEncodeBytes(nullifierHashBytes),
            recipientPubKey,
            relayerPubKey,
            uint64ToBytes(0n),
            abiEncodeBytes(rootBytes),
            uint64ToBytes(BigInt(Number(note.denomination))),
          ],
          accounts: [activeAddress],
          boxes: [nullifierBox(APP_ID, nullifierHashBytes)],
          suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
        })

        algosdk.assignGroupID([verifierAppCall, withdrawAppCall])

        setState(s => ({ ...s, message: `Approve withdrawal ${wi + 1}/${selectedNotes.length} in your wallet...` }))
        const signedGroup = await transactionSigner(
          [verifierAppCall, withdrawAppCall],
          [0, 1],
        )

        await client.sendRawTransaction(signedGroup).do()
        await algosdk.waitForConfirmation(client, withdrawAppCall.txID(), 4)
      }

      // Remove all used notes (reverse order so indices stay valid)
      for (const idx of sortedIndices) {
        removeNote(idx)
      }

      // Step 2: Deposit combined amount as one new note
      setState(s => ({ ...s, stage: 'combining', message: `Depositing combined ${totalAlgo} ALGO...` }))

      const masterKey = await deriveMasterKey(signData)
      const depositIdx = getNextDepositIndex()
      const newNote = deriveDeposit(masterKey, depositIdx, BigInt(totalMicro), 0)
      const commitmentBytes = scalarToBytes(newNote.commitment)
      const { index: leafIndex, root: newRoot } = insertLeaf(tree, newNote.commitment)
      newNote.leafIndex = leafIndex

      const contractState = await readContractState(client)
      const depParams = await client.getTransactionParams().do()

      const boxes = depositBoxRefs(APP_ID, contractState.rootHistoryIndex, contractState.nextIndex)
      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: APP_ADDR,
        amount: totalMicro,
        suggestedParams: depParams,
      })
      const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
        sender: activeAddress,
        appIndex: APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(scalarToBytes(newRoot)),
        ],
        boxes,
        suggestedParams: { ...depParams, fee: BigInt(2000), flatFee: true },
      })
      algosdk.assignGroupID([payTxn, appCallTxn])

      setState(s => ({ ...s, message: 'Approve combined deposit in your wallet...' }))
      const signed = await transactionSigner([payTxn, appCallTxn], [0, 1])
      const depRes = await client.sendRawTransaction(signed).do()
      const depTxId = (depRes as any).txid ?? (depRes as any).txId ?? appCallTxn.txID()
      await algosdk.waitForConfirmation(client, depTxId, 4)

      saveNote(newNote)
      saveTree(tree)
      incrementDepositIndex()

      addToast('success', `Combined ${selectedNotes.length} notes into ${totalAlgo} ALGO`)
      setState({
        stage: 'combine_complete',
        message: `Combined ${selectedNotes.length} notes into a single ${totalAlgo} ALGO note.`,
        txId: appCallTxn.txID(),
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = humanizeError(err)
      console.error('Combine error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg, savedNotes: loadNotes() }))
    }
  }, [activeAddress, transactionSigner, signData, getClient, state.savedNotes, addToast])

  const reset = useCallback(() => {
    setState({
      stage: 'idle',
      message: '',
      txId: null,
      error: null,
      savedNotes: loadNotes(),
    })
  }, [])

  const refreshNotes = useCallback(() => {
    setState(s => ({ ...s, savedNotes: loadNotes() }))
  }, [])

  return {
    ...state,
    deposit,
    withdraw,
    privateSend,
    splitNote,
    combineNotes,
    reset,
    refreshNotes,
  }
}
