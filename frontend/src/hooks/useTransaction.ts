import { useState, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import algosdk from 'algosdk'
import { CONTRACTS, ALGOD_CONFIG } from '../lib/config'
import {
  initMimc,
  createDeposit,
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
  reset: () => void
  refreshNotes: () => void
}

const APP_ID = CONTRACTS.PrivacyPool.appId
const APP_ADDR = CONTRACTS.PrivacyPool.appAddress

// Verifier TEAL — compiled once and cached
let verifierProgram: Uint8Array | null = null

/** Compile the withdraw verifier TEAL (fetched from /contracts/withdraw_verifier.teal) */
async function getVerifierProgram(client: algosdk.Algodv2): Promise<Uint8Array> {
  if (verifierProgram) return verifierProgram

  const resp = await fetch('/contracts/withdraw_verifier.teal')
  const tealSource = await resp.text()
  const compiled = await client.compile(new TextEncoder().encode(tealSource)).do()
  verifierProgram = new Uint8Array(Buffer.from(compiled.result, 'base64'))
  return verifierProgram
}

export function useTransaction(): UseTransactionReturn {
  const { activeAddress, transactionSigner, algodClient } = useWallet()
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
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (amountAlgo <= 0 || amountAlgo > 1) {
      setState(s => ({ ...s, stage: 'error', error: 'Amount must be between 0 and 1 ALGO' }))
      return
    }

    const amountMicroAlgo = Math.round(amountAlgo * 1_000_000)
    const client = getClient()

    try {
      setState({ stage: 'depositing', message: 'Initializing cryptography...', txId: null, error: null, savedNotes: state.savedNotes })

      await initMimc()

      setState(s => ({ ...s, message: 'Generating deposit commitment...' }))
      const note = await createDeposit(BigInt(amountMicroAlgo), 0)
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

      // Persist note and tree
      saveNote(note)
      saveTree(tree)

      setState({
        stage: 'deposit_complete',
        message: `Deposit confirmed! ${amountAlgo} ALGO is now shielded in the pool.`,
        txId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Deposit failed'
      console.error('Deposit error:', err)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, getClient, state.savedNotes])

  // ── WITHDRAW ─────────────────────────────
  const withdraw = useCallback(async (noteIndex: number, destinationAddr: string) => {
    if (!activeAddress || !transactionSigner) {
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (!algosdk.isValidAddress(destinationAddr)) {
      setState(s => ({ ...s, stage: 'error', error: 'Invalid destination address' }))
      return
    }

    const notes = loadNotes()
    if (noteIndex < 0 || noteIndex >= notes.length) {
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

      // Encode proof and public signals for LogicSig verifier
      const proofBytes = encodeProofForVerifier(groth16Proof)
      const signalsBytes = encodePublicSignals(root, nullifierHash, destinationAddr, zeroAddr, 0n)

      // Compile verifier TEAL and create LogicSig
      const program = await getVerifierProgram(client)
      const lsig = new algosdk.LogicSigAccount(program, [proofBytes, signalsBytes])

      const params = await client.getTransactionParams().do()
      const nullifierHashBytes = scalarToBytes(nullifierHash)
      const withdrawAmount = Number(note.denomination)

      // Build 3-txn atomic group:
      // [0] Fund the LogicSig account (so it can pay its own fee)
      const fundLsigTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: lsig.address(),
        amount: 6_000, // Enough for LogicSig fee (ec_pairing_check is expensive)
        suggestedParams: params,
      })

      // [1] LogicSig verifier transaction — proves ZK proof is valid
      const verifierTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: lsig.address(),
        receiver: lsig.address(),
        amount: 0,
        suggestedParams: { ...params, fee: BigInt(6000), flatFee: true },
      })

      // [2] App call — withdraw(nullifierHash, recipient, relayer, fee, root, amount)
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

      algosdk.assignGroupID([fundLsigTxn, verifierTxn, withdrawAppCall])

      setState(s => ({ ...s, message: 'Approve withdrawal in your wallet...' }))

      // Sign: user signs txns 0 and 2, LogicSig signs txn 1
      const userSigned = await transactionSigner(
        [fundLsigTxn, verifierTxn, withdrawAppCall],
        [0, 2],
      )
      const lsigSigned = algosdk.signLogicSigTransactionObject(verifierTxn, lsig)

      // Assemble: [userSigned[0], lsigSigned, userSigned[1]]
      const signedGroup = [userSigned[0], lsigSigned.blob, userSigned[1]]

      const txId = withdrawAppCall.txID()

      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(signedGroup).do()

      setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
      await algosdk.waitForConfirmation(client, txId, 4)

      // Remove used note
      removeNote(noteIndex)

      const algoAmount = (Number(note.denomination) / 1_000_000).toFixed(6).replace(/\.?0+$/, '')
      setState({
        stage: 'withdraw_complete',
        message: `${algoAmount} ALGO withdrawn from the pool to the destination!`,
        txId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Withdrawal failed'
      console.error('Withdraw error:', err)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, getClient])

  // ── PRIVATE SEND (deposit → immediate withdraw) ──
  const privateSend = useCallback(async (amountAlgo: number, destinationAddr: string) => {
    if (!activeAddress || !transactionSigner) {
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }
    if (amountAlgo <= 0 || amountAlgo > 1) {
      setState(s => ({ ...s, stage: 'error', error: 'Amount must be between 0 and 1 ALGO' }))
      return
    }
    if (!algosdk.isValidAddress(destinationAddr)) {
      setState(s => ({ ...s, stage: 'error', error: 'Invalid destination address' }))
      return
    }

    const amountMicroAlgo = Math.round(amountAlgo * 1_000_000)
    const client = getClient()

    try {
      // ── Step 1: Deposit ──
      setState({ stage: 'depositing', message: 'Initializing cryptography...', txId: null, error: null, savedNotes: state.savedNotes })

      await initMimc()

      setState(s => ({ ...s, message: 'Generating deposit commitment...' }))
      const note = await createDeposit(BigInt(amountMicroAlgo), 0)
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

      const program = await getVerifierProgram(client)
      const lsig = new algosdk.LogicSigAccount(program, [proofBytes, signalsBytes])

      params = await client.getTransactionParams().do()
      const nullifierHashBytes = scalarToBytes(nullifierHash)

      const fundLsigTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: activeAddress,
        receiver: lsig.address(),
        amount: 6_000,
        suggestedParams: params,
      })

      const verifierTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: lsig.address(),
        receiver: lsig.address(),
        amount: 0,
        suggestedParams: { ...params, fee: BigInt(6000), flatFee: true },
      })

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
          uint64ToBytes(BigInt(amountMicroAlgo)),
        ],
        accounts: [destinationAddr],
        boxes: [nullifierBox(APP_ID, nullifierHashBytes)],
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      algosdk.assignGroupID([fundLsigTxn, verifierTxn, withdrawAppCall])

      setState(s => ({ ...s, message: 'Approve withdrawal in your wallet...' }))
      const userSigned = await transactionSigner(
        [fundLsigTxn, verifierTxn, withdrawAppCall],
        [0, 2],
      )
      const lsigSigned = algosdk.signLogicSigTransactionObject(verifierTxn, lsig)
      const signedGroup = [userSigned[0], lsigSigned.blob, userSigned[1]]

      const withdrawTxId = withdrawAppCall.txID()

      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(signedGroup).do()

      setState(s => ({ ...s, message: 'Waiting for withdrawal confirmation...' }))
      await algosdk.waitForConfirmation(client, withdrawTxId, 4)

      // Remove the note we just used
      const currentNotes = loadNotes()
      const usedIdx = currentNotes.findIndex(n =>
        n.nullifier === note.nullifier && n.secret === note.secret
      )
      if (usedIdx >= 0) removeNote(usedIdx)

      setState({
        stage: 'withdraw_complete',
        message: `${amountAlgo} ALGO sent privately to ${destinationAddr.slice(0, 6)}...${destinationAddr.slice(-4)}`,
        txId: withdrawTxId,
        error: null,
        savedNotes: loadNotes(),
      })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Private send failed'
      console.error('Private send error:', err)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, getClient, state.savedNotes])

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
    reset,
    refreshNotes,
  }
}
