import { useState, useCallback, useEffect, useRef } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import algosdk from 'algosdk'
import { CONTRACTS, ALGOD_CONFIG, FEES, isValidTier, DENOMINATION_TIERS, getPoolForTier, POOL_CONTRACTS, RELAYERS, pickRelayer, BATCH_WINDOW_MINUTES, TREASURY_ADDRESS, PROTOCOL_FEE, STALE_NOTE_THRESHOLD, SUBSIDY_TIERS, USE_PLONK_LSIG, MIN_SOAK_DEPOSITS, OPERATION_COOLDOWN_MS, CLUSTER_WARNING_THRESHOLD, WITHDRAW_JITTER_MS, FALCON_EXTRA_FEE } from '../lib/config'
import { useFalcon, type DeriveResult } from '../contexts/FalconContext'
import { createFalconSigner } from '../lib/falcon'
import { useToast } from '../contexts/ToastContext'
import { humanizeError, withRetry } from '../lib/errorMessages'
import { cachedGetApp, cachedGetAccount, invalidateCache } from '../lib/algodCache'
import {
  initMimc,
  deriveDeposit,
  deriveMasterKey,
  getCachedMasterKey,
  getViewKeypair,
  claimNextDepositIndex,
  computeNullifierHash,
  scalarToBytes,
  bytesToScalar,
  uint64ToBytes,
  abiEncodeBytes,
  addressToScalar,
  encodeProofForVerifier,
  encodePublicSignals,
  encodeDepositSignals,
  encodePrivateSendSignals,
  METHOD_SELECTORS,
  depositBoxRefs,
  privateSendBoxRefs,
  nullifierBox,
  withdrawBoxRefs,
  readEvictedRoot,
  saveNote,
  loadNotes,
  removeNote,
  removeNoteByCommitment,
  isNullifierSpent,
  recoverNotesFromChain,
  findStaleNotes,
  PasswordRequiredError,
  DepositNote,
  setActiveWallet,
  generateProof,
  parseGroth16Proof,
  clearMasterKey,
} from '../lib/privacy'
import {
  getOrCreateTree,
  insertLeaf,
  getPath,
  saveTree,
  clearTreeCache,
  incrementalSyncTree,
  syncAllTreesFromChain,
} from '../lib/tree'
import { encryptNote, HPKE_ENVELOPE_LEN } from '../lib/hpke'
import { isPrivacyAddress, decodePrivacyAddress, algoAddressFromPrivacyAddress } from '../lib/address'
import { waitForBatchWindow, formatBatchCountdown, msUntilNextBatch } from '../lib/batchQueue'

export type TxStage =
  | 'idle'
  | 'waiting_batch'
  | 'depositing'
  | 'deposit_complete'
  | 'generating_proof'
  | 'withdrawing'
  | 'withdraw_complete'
  | 'error'

export interface SoakWarning {
  depositsSince: number
  needed: number
  resolve: (proceed: boolean) => void
}

interface TxState {
  stage: TxStage
  message: string
  txId: string | null
  error: string | null
  savedNotes: DepositNote[]
  batchCountdown: string | null
  staleNotes: DepositNote[]
  poolNextIndices: Map<number, number>
  treasuryBalance: bigint | null
  subsidyActive: boolean
  soakWarning: SoakWarning | null
}

interface UseTransactionReturn extends TxState {
  deposit: (microAlgos: bigint, skipBatchWait?: boolean, subsidyMicroAlgos?: bigint, scheduledTime?: number) => Promise<void>
  withdraw: (noteCommitment: bigint, destinationAddr: string) => Promise<void>
  privateSend: (microAlgos: bigint, destinationAddr: string, skipBatchWait?: boolean, subsidyMicroAlgos?: bigint) => Promise<void>
  churnNote: (note: DepositNote) => Promise<void>
  split: (noteCommitment: bigint) => Promise<void>
  combine: (noteCommitment1: bigint, noteCommitment2: bigint) => Promise<void>
  skipBatchWait: () => void
  reset: () => Promise<void>
  refreshNotes: () => Promise<void>
  refreshStaleNotes: () => Promise<void>
  refreshTreasuryBalance: () => Promise<void>
  rebuildAllTrees: (onProgress?: (pool: string, done: boolean) => void) => Promise<void>
  scanForNotes: (onProgress?: (round: number, found: number) => void) => Promise<{ recovered: number; newNotes: number }>
  useRelayer: boolean
  setUseRelayer: (v: boolean) => void
  relayerAvailable: boolean
}

import type { PlonkVerifierProgram } from '../lib/plonkVerifierLsig'

// ── PLONK LogicSig helpers (module-level, lazy-cached) ──

const _plonkCache = new Map<string, PlonkVerifierProgram | null>()

/** Load and compile a PLONK verifier LogicSig for a circuit. Cached per circuit name. */
async function loadPlonkVerifier(
  client: algosdk.Algodv2,
  circuit: string,
): Promise<PlonkVerifierProgram | null> {
  if (_plonkCache.has(circuit)) return _plonkCache.get(circuit)!
  try {
    const { compilePlonkVerifier } = await import('../lib/plonkVerifierLsig')
    const [tealResp, vkResp] = await Promise.all([
      fetch(`/circuits/${circuit}_plonk_verifier.teal`),
      fetch(`/circuits/${circuit}_plonk_vk_chunks.json`),
    ])
    if (!tealResp.ok || !vkResp.ok) {
      _plonkCache.set(circuit, null)
      return null
    }
    const [tealSource, vkChunks] = await Promise.all([tealResp.text(), vkResp.json()])
    const verifier = await compilePlonkVerifier(client, tealSource, vkChunks)
    _plonkCache.set(circuit, verifier)
    return verifier
  } catch (err) {
    console.error(`[PLONK] Failed to load ${circuit} verifier:`, err)
    _plonkCache.set(circuit, null)
    return null
  }
}

/**
 * Compute precomputed modular inverses for the PLONK LogicSig verifier.
 * These are passed as arg[1] so the TEAL program can evaluate Lagrange basis
 * polynomials without expensive in-TEAL field inversions.
 */
async function computePlonkInverses(
  circuit: string,
  proof: any,
  publicSignals: string[],
): Promise<Uint8Array> {
  const plonk = await import('../lib/plonkVerifierLsig')
  const [vkResp, chunksResp] = await Promise.all([
    fetch(`/circuits/${circuit}_plonk_vkey.json`),
    fetch(`/circuits/${circuit}_plonk_verifier_vk_chunks.json`),
  ])
  const [vkey, vkChunks] = await Promise.all([vkResp.json(), chunksResp.json()])

  const { xi } = await plonk.deriveFiatShamirXi(vkChunks, proof, publicSignals, vkey)
  const omega = BigInt(vkey.w)
  const n = 1 << vkChunks.power
  return plonk.computePrecomputedInverses(xi, omega, n, vkChunks.nPublic)
}

/** Sign a mixed group: LogicSig for first 4 txns, wallet signer for the rest. */
async function signPlonkMixedGroup(
  verifier: PlonkVerifierProgram,
  group: algosdk.Transaction[],
  proofBytes: Uint8Array,
  inversesBytes: Uint8Array,
  walletSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>,
): Promise<Uint8Array[]> {
  const { signPlonkVerifierTxns, PLONK_LSIG_GROUP_SIZE } = await import('../lib/plonkVerifierLsig')
  const lsigSigned = signPlonkVerifierTxns(verifier, group, proofBytes, inversesBytes)
  const walletIndices = Array.from(
    { length: group.length - PLONK_LSIG_GROUP_SIZE },
    (_, i) => i + PLONK_LSIG_GROUP_SIZE,
  )
  // Timeout: if wallet doesn't respond in 90s, throw instead of hanging forever
  const walletResult = await Promise.race([
    walletSigner(group, walletIndices),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('Wallet did not respond — try reconnecting Pera and retry')), 90_000)
    ),
  ])
  return group.map((_, i) =>
    i < PLONK_LSIG_GROUP_SIZE ? lsigSigned[i] : walletResult[i]
  )
}

const VERIFIER_APP_ID = CONTRACTS.ZkVerifier.appId
const BUDGET_HELPER_APP_ID = CONTRACTS.ZkVerifier.budgetHelperAppId
const DEPOSIT_VERIFIER_APP_ID = CONTRACTS.DepositVerifier.appId
const DEPOSIT_BUDGET_HELPER_APP_ID = CONTRACTS.DepositVerifier.budgetHelperAppId
const PRIVATESEND_VERIFIER_APP_ID = CONTRACTS.PrivateSendVerifier.appId
const PRIVATESEND_BUDGET_HELPER_APP_ID = CONTRACTS.PrivateSendVerifier.budgetHelperAppId

// Guard: refuse to operate if verifier apps are not deployed
if (!VERIFIER_APP_ID) console.error('ZkVerifier appId is 0 — withdrawals will fail. Run the deploy script.')
if (!DEPOSIT_VERIFIER_APP_ID) console.error('DepositVerifier appId is 0 — deposits will fail. Run the deploy script.')
if (!PRIVATESEND_VERIFIER_APP_ID) console.error('PrivateSendVerifier appId is 0 — privateSend will fail. Run the deploy script.')

// ── Anti-correlation session tracking (localStorage-backed, survives re-renders AND cross-tab) ──
let sessionOperationCount = 0
let sessionDepositCount = 0
let sessionWithdrawCount = 0

function getLastOperationTime(): number {
  try { return Number(localStorage.getItem('privacy_pool_last_op_time') ?? '0') } catch { return 0 }
}

/** Enforce cooldown between operations to prevent clustering (cross-tab via localStorage) */
function checkCooldown(): { ok: boolean; remainingSec: number } {
  const lastOp = getLastOperationTime()
  const elapsed = Date.now() - lastOp
  if (lastOp === 0 || elapsed >= OPERATION_COOLDOWN_MS) return { ok: true, remainingSec: 0 }
  return { ok: false, remainingSec: Math.ceil((OPERATION_COOLDOWN_MS - elapsed) / 1000) }
}

/** Record that an operation was performed */
function recordOperation(type: 'deposit' | 'withdraw') {
  try { localStorage.setItem('privacy_pool_last_op_time', Date.now().toString()) } catch {}
  sessionOperationCount++
  if (type === 'deposit') sessionDepositCount++
  else sessionWithdrawCount++
}

/** Check if user is creating a suspicious cluster pattern */
function checkClusterRisk(): string | null {
  if (sessionDepositCount >= CLUSTER_WARNING_THRESHOLD) {
    return `You've made ${sessionDepositCount} deposits this session. Depositing many times in a row creates a linkable cluster — an observer can correlate them even without knowing your address. Consider waiting and spreading deposits across sessions.`
  }
  if (sessionWithdrawCount >= CLUSTER_WARNING_THRESHOLD) {
    return `You've made ${sessionWithdrawCount} withdrawals this session. Withdrawing many times in a row creates a linkable cluster. Consider waiting and spreading withdrawals across sessions.`
  }
  return null
}

/** Add random jitter delay before withdrawal to prevent timing correlation */
function withdrawJitter(): Promise<void> {
  const jitter = WITHDRAW_JITTER_MS.min + Math.random() * (WITHDRAW_JITTER_MS.max - WITHDRAW_JITTER_MS.min)
  return new Promise(resolve => setTimeout(resolve, jitter))
}

export function useTransaction(): UseTransactionReturn {
  const { activeAddress, transactionSigner, algodClient, signData } = useWallet()
  const { addToast } = useToast()
  const relayerAvailable = RELAYERS.length > 0
  const [useRelayerState, setUseRelayer] = useState(relayerAvailable)
  const batchCancelRef = useRef<(() => void) | null>(null)
  const batchTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const [state, setState] = useState<TxState>({
    stage: 'idle',
    message: '',
    txId: null,
    error: null,
    savedNotes: [],
    batchCountdown: null,
    staleNotes: [],
    poolNextIndices: new Map(),
    treasuryBalance: null,
    subsidyActive: false,
    soakWarning: null,
  })

  // Track active wallet for per-wallet deposit counter; clear keys on disconnect
  useEffect(() => {
    if (activeAddress) {
      setActiveWallet(activeAddress)
    } else {
      clearMasterKey()
    }
  }, [activeAddress])

  // Load notes async on mount
  useEffect(() => {
    loadNotes().then(notes => setState(s => ({ ...s, savedNotes: notes })))
  }, [])

  const getClient = useCallback(() => {
    return algodClient ?? new algosdk.Algodv2(
      ALGOD_CONFIG.token,
      ALGOD_CONFIG.baseServer,
      ALGOD_CONFIG.port,
    )
  }, [algodClient])

  // ── Falcon post-quantum mode ──
  const falcon = useFalcon()

  /**
   * Resolve effective sender and signer.
   * When Falcon mode is enabled + funded, uses Falcon LogicSig.
   * Otherwise, falls back to wallet sender/signer.
   * If Falcon is enabled but not yet derived, derives from master key.
   */
  async function ensureSigner(): Promise<{
    sender: string
    signer: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>
    isFalcon: boolean
  }> {
    if (falcon.enabled) {
      // Already derived and funded
      if (falcon.account && falcon.funded && falcon.signer) {
        return { sender: falcon.account.address, signer: falcon.signer, isFalcon: true }
      }
      // Need to derive
      if (!falcon.account) {
        try {
          const mk = await deriveMasterKey(signData)
          const result = await falcon.derive(mk)
          if (result && result.funded) {
            const signer = createFalconSigner(result.account.program, result.account.privateKey)
            return { sender: result.account.address, signer, isFalcon: true }
          }
        } catch (err) {
          // Falcon derivation failed (e.g., AVM v12 not available) — fall through to wallet
          console.warn('[Falcon] Derivation failed, using wallet:', err)
        }
      }
      // Falcon enabled but not usable (not funded, or derivation failed) — use wallet
    }
    if (!activeAddress || !transactionSigner) {
      throw new Error('Wallet not connected')
    }
    return { sender: activeAddress, signer: transactionSigner, isFalcon: false }
  }

  /** Read contract global state (with network retry) */
  async function readContractState(client: algosdk.Algodv2, appId: number) {
    const appInfo = await withRetry(() => cachedGetApp(client, appId))
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

  /** Wait for the next batch window with countdown UI updates. Resolves when the window arrives.
   *  If skipBatchWait is true, resolves immediately (for testing / reduced privacy).
   *  If the user clicks "skip", resolves immediately (cancellation = proceed with reduced privacy). */
  async function awaitBatchWindow(skip?: boolean): Promise<void> {
    if (skip) return

    const remaining = msUntilNextBatch(BATCH_WINDOW_MINUTES)
    if (remaining <= 1000) return // Already within 1s of a window

    const batch = waitForBatchWindow(BATCH_WINDOW_MINUTES)
    batchCancelRef.current = batch.cancel

    setState(s => ({
      ...s,
      stage: 'waiting_batch',
      message: 'Waiting for batch window...',
      batchCountdown: formatBatchCountdown(batch.remainingMs()),
    }))

    // Update countdown every second
    batchTimerRef.current = setInterval(() => {
      const ms = batch.remainingMs()
      setState(s => ({ ...s, batchCountdown: formatBatchCountdown(ms) }))
      if (ms <= 0 && batchTimerRef.current) {
        clearInterval(batchTimerRef.current)
        batchTimerRef.current = null
      }
    }, 1000)

    try {
      await batch.promise
    } catch {
      // Cancelled = user chose to skip, proceed immediately
    } finally {
      if (batchTimerRef.current) {
        clearInterval(batchTimerRef.current)
        batchTimerRef.current = null
      }
      batchCancelRef.current = null
      setState(s => ({ ...s, batchCountdown: null }))
    }
  }

  /** Build a protocol fee + optional subsidy payment transaction (appended to transaction groups) */
  function buildProtocolFeeTxn(sender: string, params: algosdk.SuggestedParams, subsidyMicroAlgos: bigint = 0n): algosdk.Transaction | null {
    if (!TREASURY_ADDRESS) return null
    const total = PROTOCOL_FEE + subsidyMicroAlgos
    if (total <= 0n) return null
    return algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender,
      receiver: TREASURY_ADDRESS,
      amount: Number(total),
      suggestedParams: params,
    })
  }

  /** Read treasury account balance to determine if protocol fees are subsidized */
  async function readTreasuryBalance(client: algosdk.Algodv2): Promise<bigint> {
    if (!TREASURY_ADDRESS) return 0n
    try {
      const info = await cachedGetAccount(client, TREASURY_ADDRESS)
      const balance = BigInt(info.amount)
      const minBalance = BigInt(info.minBalance ?? 100_000)
      return balance > minBalance ? balance - minBalance : 0n
    } catch {
      return 0n
    }
  }

  /** Fetch pool nextIndex values for all active pools (parallel, with network retry) */
  async function fetchPoolNextIndices(client: algosdk.Algodv2): Promise<Map<number, number>> {
    const indices = new Map<number, number>()
    const pools = Object.values(POOL_CONTRACTS)
    const results = await Promise.allSettled(
      pools.map(async pool => {
        const state = await withRetry(() => readContractState(client, pool.appId))
        return { appId: pool.appId, nextIndex: state.nextIndex }
      })
    )
    for (const result of results) {
      if (result.status === 'fulfilled') {
        indices.set(result.value.appId, result.value.nextIndex)
      } else {
        console.warn('[poolNextIndices] Failed to read pool:', result.reason)
      }
    }
    return indices
  }

  /** Minimum pool deposits before allowing withdrawals/sends — prevents trivial deanonymization */
  const MIN_POOL_DEPOSITS = 5

  /** Check if a pool has enough deposits for meaningful privacy */
  async function checkPoolSize(client: algosdk.Algodv2, poolAppId: number, operation: string): Promise<void> {
    try {
      const state = await readContractState(client, poolAppId)
      if (state.nextIndex < MIN_POOL_DEPOSITS) {
        throw new Error(
          `Pool only has ${state.nextIndex} deposit${state.nextIndex === 1 ? '' : 's'} — need at least ${MIN_POOL_DEPOSITS} for privacy. ` +
          `${operation} blocked to prevent deanonymization.`
        )
      }
    } catch (err) {
      if ((err as Error).message.includes('blocked to prevent')) throw err
      // If we can't read state, allow the operation (don't block on network errors)
    }
  }

  function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
  }

  /** Submit a withdrawal via a randomly-picked relayer service */
  async function submitViaRelayer(
    proofBytes: Uint8Array,
    signalsBytes: Uint8Array,
    poolAppId: number,
    nullifierHashBytes: Uint8Array,
    rootBytes: Uint8Array,
    recipient: string,
    fee: number,
    relayerUrl: string,
    relayerAddress: string,
    inversesBytes?: Uint8Array,
  ): Promise<string> {
    const resp = await fetch(`${relayerUrl}/api/withdraw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: USE_PLONK_LSIG ? 'plonk' : 'groth16',
        proof: bytesToHex(proofBytes),
        signals: bytesToHex(signalsBytes),
        inverses: inversesBytes ? bytesToHex(inversesBytes) : undefined,
        poolAppId,
        nullifierHash: bytesToHex(nullifierHashBytes),
        root: bytesToHex(rootBytes),
        recipient,
        relayerAddress,
        fee,
      }),
    })
    const data = await resp.json()
    if (!resp.ok) throw new Error(data.error || 'Relayer request failed')
    return data.txId
  }

  /** Submit a deposit via the relayer — hides the depositor's address on-chain */
  async function submitDepositViaRelayer(
    proofBytes: Uint8Array,
    signalsBytes: Uint8Array,
    pool: { appId: number; appAddress: string },
    commitmentBytes: Uint8Array,
    newRootBytes: Uint8Array,
    amount: bigint,
    boxState: { rootHistoryIndex: number; nextIndex: number; evictedRoot?: Uint8Array },
    relayerUrl: string,
    relayerAddress: string,
    relayerFee: bigint,
    signer: typeof transactionSigner,
    sender: string,
    client: algosdk.Algodv2,
    hpkeNote?: Uint8Array,
    inversesBytes?: Uint8Array,
  ): Promise<string> {
    // Step 1: Build and sign a payment from user → relayer (amount + fee)
    const params = await client.getTransactionParams().do()
    const paymentTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender,
      receiver: relayerAddress,
      amount: Number(amount + relayerFee),
      suggestedParams: params,
      note: commitmentBytes, // Binds payment to this specific deposit
    })
    const signedPaymentGroup = await signer([paymentTxn], [0])
    const signedPaymentB64 = btoa(String.fromCharCode(...signedPaymentGroup[0]))

    // Step 2: Send to relayer
    const resp = await fetch(`${relayerUrl}/api/deposit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: USE_PLONK_LSIG ? 'plonk' : 'groth16',
        proof: bytesToHex(proofBytes),
        signals: bytesToHex(signalsBytes),
        inverses: inversesBytes ? bytesToHex(inversesBytes) : undefined,
        poolAppId: pool.appId,
        commitment: bytesToHex(commitmentBytes),
        newRoot: bytesToHex(newRootBytes),
        amount: Number(amount),
        fee: Number(relayerFee),
        signedPayment: signedPaymentB64,
        hpkeNote: hpkeNote ? bytesToHex(hpkeNote) : undefined,
        boxState: {
          rootHistoryIndex: boxState.rootHistoryIndex,
          nextIndex: boxState.nextIndex,
          evictedRoot: boxState.evictedRoot ? bytesToHex(boxState.evictedRoot) : undefined,
        },
      }),
    })
    const data = await resp.json()
    if (!resp.ok) throw new Error(data.error || 'Deposit relayer request failed')
    return data.txId
  }

  /** Check wallet balance is sufficient before starting expensive proof generation */
  async function checkBalance(client: algosdk.Algodv2, sender: string, requiredMicroAlgos: bigint): Promise<void> {
    const accountInfo = await client.accountInformation(sender).do()
    const balance = BigInt(accountInfo.amount)
    const minBalance = BigInt(accountInfo.minBalance ?? 100_000)
    const available = balance - minBalance
    if (available < requiredMicroAlgos) {
      const needed = (Number(requiredMicroAlgos) / 1_000_000).toFixed(3)
      const have = (Number(available) / 1_000_000).toFixed(3)
      throw new Error(`Insufficient balance: need ${needed} ALGO but only ${have} ALGO available (after min balance)`)
    }
  }

  /** Build and submit a deposit with ZK insertion proof. Returns txId. */
  async function executeDeposit(
    client: algosdk.Algodv2,
    sender: string,
    signer: typeof transactionSigner,
    pool: { appId: number; appAddress: string },
    note: DepositNote,
    microAlgos: bigint,
    subsidyMicroAlgos: bigint = 0n,
    falconMode: boolean = false,
  ): Promise<string> {
    const commitmentBytes = scalarToBytes(note.commitment)

    // Incremental sync: only fetch new leaves since last sync (O(delta) not O(N))
    setState(s => ({ ...s, message: 'Syncing Merkle tree...' }))
    const tree = await incrementalSyncTree(pool.appId)

    // Use the synced tree's root directly as oldRoot (avoids race with separate RPC read)
    const oldRoot = tree.root

    // Read contract state only for box reference indices
    const contractState = await readContractState(client, pool.appId)

    // Insert into synced local tree
    const { index: leafIndex, root: mimcRoot } = insertLeaf(tree, note.commitment)
    note.leafIndex = leafIndex

    const mimcRootBytes = scalarToBytes(mimcRoot)

    // Get Merkle path for the insertion proof
    const merklePath = getPath(tree, leafIndex)

    // Generate deposit insertion ZK proof
    setState(s => ({ ...s, stage: 'generating_proof', message: 'Preparing proof generation...' }))

    const proofSystem = USE_PLONK_LSIG ? 'plonk' as const : 'groth16' as const
    const zkeyFile = USE_PLONK_LSIG ? '/circuits/deposit_plonk.zkey' : '/circuits/deposit_final.zkey'

    const circuitInput = {
      oldRoot: oldRoot.toString(),
      newRoot: mimcRoot.toString(),
      commitment: note.commitment.toString(),
      leafIndex: leafIndex.toString(),
      pathElements: merklePath.pathElements.map(e => e.toString()),
    }

    const { proof, publicSignals } = await generateProof(
      proofSystem,
      circuitInput,
      '/circuits/deposit.wasm',
      zkeyFile,
      (msg) => setState(s => ({ ...s, message: msg })),
    )

    const proofBytes = USE_PLONK_LSIG
      ? (await import('../lib/plonkVerifierLsig')).encodePlonkProof(proof)
      : encodeProofForVerifier(parseGroth16Proof(proof))
    const signalsBytes = encodeDepositSignals(oldRoot, mimcRoot, note.commitment, BigInt(leafIndex))

    // Pre-check: re-read on-chain root after proof gen — if it changed, skip submission
    setState(s => ({ ...s, stage: 'depositing', message: 'Verifying tree state...' }))
    const freshState = await readContractState(client, pool.appId)
    if (bytesToScalar(freshState.currentRoot) !== oldRoot) {
      throw new Error('Tree root changed during proof generation (concurrent deposit)')
    }

    setState(s => ({ ...s, message: 'Building deposit transaction...' }))
    const params = await client.getTransactionParams().do()

    // Read evicted root for knownRoots pruning (only when ring buffer wraps at >=1000 deposits)
    const evictedRoot = await readEvictedRoot(client, pool.appId, freshState.rootHistoryIndex)
    const boxes = depositBoxRefs(pool.appId, freshState.rootHistoryIndex, freshState.nextIndex, mimcRootBytes, evictedRoot)

    // Compute HPKE envelope for the note field (self-deposit)
    // Always include a note of HPKE_ENVELOPE_LEN bytes to prevent correlation —
    // deposits with vs without notes are distinguishable on-chain, shrinking anonymity set.
    let hpkeNote: Uint8Array
    const viewKeypair = await getViewKeypair()
    if (viewKeypair) {
      hpkeNote = await encryptNote(note, viewKeypair.publicKey)
    } else {
      // Dummy note with correct HPKE header bytes to be indistinguishable from real envelopes
      hpkeNote = crypto.getRandomValues(new Uint8Array(HPKE_ENVELOPE_LEN))
      hpkeNote[0] = 0x01 // ENVELOPE_VERSION
      hpkeNote[1] = 0x01 // ENVELOPE_SUITE
    }

    let txId: string

    // Skip relayer when Falcon is active — Falcon address is already pseudonymous
    const viaRelayer = useRelayerState && relayerAvailable && !(falcon.enabled && falcon.funded)
    if (viaRelayer) {
      // Deposit via relayer — hides depositor's address on-chain
      const chosenRelayer = pickRelayer()
      setState(s => ({ ...s, message: 'Approve payment to relayer...' }))
      const inversesBytes = USE_PLONK_LSIG
        ? await computePlonkInverses('deposit', proof, publicSignals)
        : undefined
      txId = await submitDepositViaRelayer(
        proofBytes, signalsBytes, pool, commitmentBytes, mimcRootBytes,
        microAlgos,
        { rootHistoryIndex: freshState.rootHistoryIndex, nextIndex: freshState.nextIndex, evictedRoot },
        chosenRelayer.url, chosenRelayer.address, chosenRelayer.fee,
        signer, sender, client, hpkeNote, inversesBytes,
      )
    } else if (USE_PLONK_LSIG) {
      // PLONK LogicSig group: [lsig×4, payTxn, poolAppCall, ?feeTxn]
      setState(s => ({ ...s, message: 'Compiling PLONK verifier...' }))
      const plonk = await import('../lib/plonkVerifierLsig')
      const verifier = await loadPlonkVerifier(client, 'deposit')
      if (!verifier) throw new Error('PLONK deposit verifier not available — deploy PLONK verifiers or set VITE_USE_PLONK_LSIG=false')

      setState(s => ({ ...s, message: 'Building transaction group...' }))
      const lsigTxns = plonk.buildPlonkVerifierGroup(verifier, proofBytes, signalsBytes, sender, params)

      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender,
        receiver: pool.appAddress,
        amount: Number(microAlgos),
        suggestedParams: params,
      })

      const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: pool.appId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(mimcRootBytes),
        ],
        boxes,
        note: hpkeNote,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const depositGroup = [...lsigTxns, payTxn, appCallTxn]
      const feeTxn = buildProtocolFeeTxn(sender, params, subsidyMicroAlgos)
      if (feeTxn) depositGroup.push(feeTxn)

      algosdk.assignGroupID(depositGroup)

      setState(s => ({ ...s, message: 'Computing PLONK inverses...' }))
      const inversesBytes = await computePlonkInverses('deposit', proof, publicSignals)

      setState(s => ({ ...s, message: falconMode ? 'Signing deposit with Falcon...' : 'Approve deposit in your wallet...' }))
      const signedTxns = await signPlonkMixedGroup(verifier, depositGroup, proofBytes, inversesBytes, signer)

      setState(s => ({ ...s, message: 'Submitting deposit...' }))
      const result = await client.sendRawTransaction(signedTxns).do()
      txId = (result as any).txid ?? (result as any).txId
    } else {
      // Groth16 app-based group: [verifierAppCall, payTxn, poolAppCall, ?feeTxn]
      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: DEPOSIT_VERIFIER_APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: [DEPOSIT_BUDGET_HELPER_APP_ID],
        suggestedParams: { ...params, fee: FEES.verifierCall, flatFee: true },
      })

      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender,
        receiver: pool.appAddress,
        amount: Number(microAlgos),
        suggestedParams: params,
      })

      const appCallTxn = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: pool.appId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.deposit,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(mimcRootBytes),
        ],
        foreignApps: [DEPOSIT_VERIFIER_APP_ID],
        boxes,
        note: hpkeNote,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const depositGroup: algosdk.Transaction[] = [verifierAppCall, payTxn, appCallTxn]
      const feeTxn = buildProtocolFeeTxn(sender, params, subsidyMicroAlgos)
      if (feeTxn) depositGroup.push(feeTxn)

      // Groth16 + Falcon: add padding txns for byte budget (~3KB LogicSig)
      if (falconMode) {
        while (depositGroup.length < 4) {
          depositGroup.push(algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender, receiver: sender, amount: 0, suggestedParams: params,
          }))
        }
      }

      algosdk.assignGroupID(depositGroup)

      setState(s => ({ ...s, message: falconMode ? 'Signing deposit with Falcon...' : 'Approve deposit in your wallet...' }))
      const signedTxns = await signer(depositGroup, depositGroup.map((_, i) => i))

      setState(s => ({ ...s, message: 'Submitting deposit...' }))
      const result = await client.sendRawTransaction(signedTxns).do()
      txId = (result as any).txid ?? (result as any).txId
    }

    setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
    await algosdk.waitForConfirmation(client, txId, 4)

    // Persist tree after successful confirmation
    saveTree(tree, pool.appId)
    return txId
  }

  /** Detect if an error is a stale root mismatch (concurrent deposit) */
  function isStaleRootError(err: unknown): boolean {
    const msg = String(err)
    // Only retry on our explicit pre-check failure (detected before submission, no wasted fee)
    return msg.includes('concurrent deposit')
  }

  const MAX_DEPOSIT_RETRIES = 3

  // ── DEPOSIT ──────────────────────────────
  const deposit = useCallback(async (microAlgos: bigint, skipBatchWait?: boolean, subsidyMicroAlgos?: bigint, scheduledTime?: number) => {
    let effectiveSender: string
    let effectiveSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>
    let isFalcon: boolean
    try {
      ({ sender: effectiveSender, signer: effectiveSigner, isFalcon } = await ensureSigner())
    } catch {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (!isValidTier(microAlgos)) {
      addToast('error', `Invalid denomination. Use ${DENOMINATION_TIERS.map(t => t.label).join(', ')} ALGO`)
      setState(s => ({ ...s, stage: 'error', error: 'Invalid denomination tier' }))
      return
    }

    if (!DEPOSIT_VERIFIER_APP_ID) {
      addToast('error', 'Deposit verifier not deployed. Run the deploy script first.')
      setState(s => ({ ...s, stage: 'error', error: 'Deposit verifier not deployed (appId = 0)' }))
      return
    }

    const amountMicroAlgo = Number(microAlgos)
    const amountAlgo = amountMicroAlgo / 1_000_000
    const client = getClient()
    const pool = getPoolForTier(microAlgos)

    try {
      // Anti-correlation: enforce cooldown between operations
      const cooldown = checkCooldown()
      if (!cooldown.ok) {
        addToast('error', `Please wait ${cooldown.remainingSec}s between operations to avoid creating linkable patterns`)
        setState(s => ({ ...s, stage: 'error', error: `Cooldown: wait ${cooldown.remainingSec}s between operations` }))
        return
      }

      // Anti-correlation: warn about cluster patterns
      const clusterWarning = checkClusterRisk()
      if (clusterWarning) {
        addToast('error', clusterWarning)
      }

      setState(s => ({ ...s, stage: 'depositing', message: 'Initializing cryptography...', txId: null, error: null }))

      await initMimc()

      // Pre-check balance before expensive proof generation
      const subsidy = subsidyMicroAlgos ?? 0n
      const falconFee = isFalcon && !USE_PLONK_LSIG ? FALCON_EXTRA_FEE.groth16Padding : 0n
      setState(s => ({ ...s, message: 'Checking balance...' }))
      await checkBalance(client, effectiveSender, microAlgos + FEES.deposit + PROTOCOL_FEE + subsidy + falconFee)

      // Derive deterministic note from wallet signature (or use cached master key)
      setState(s => ({ ...s, message: 'Deriving deposit key...' }))
      const masterKey = await deriveMasterKey(signData)
      const depositIdx = await claimNextDepositIndex() // atomic: claims index + increments counter
      const note = deriveDeposit(masterKey, depositIdx, microAlgos, 0)

      // If a specific time was scheduled, wait until then (proof+signing already done above)
      if (scheduledTime) {
        const now = Date.now()
        const waitMs = scheduledTime - now
        if (waitMs > 1000) {
          setState(s => ({ ...s, stage: 'waiting_batch', message: `Signed. Submitting at scheduled time...` }))
          // Update countdown every second
          const countdownId = setInterval(() => {
            const remaining = Math.max(0, scheduledTime - Date.now())
            const m = Math.floor(remaining / 60000)
            const sec = Math.floor((remaining % 60000) / 1000)
            setState(s => ({ ...s, batchCountdown: `${m}:${String(sec).padStart(2, '0')}` }))
          }, 1000)
          await new Promise<void>(resolve => setTimeout(resolve, waitMs))
          clearInterval(countdownId)
        }
      } else if (!skipBatchWait) {
        await awaitBatchWindow(true) // instant mode — skip batch wait
      }
      setState(s => ({ ...s, stage: 'depositing', message: 'Starting deposit...', txId: null, error: null }))

      // Attempt deposit with retry on stale root (concurrent deposit by another user)
      let txId: string | undefined
      for (let attempt = 1; attempt <= MAX_DEPOSIT_RETRIES; attempt++) {
        try {
          txId = await executeDeposit(client, effectiveSender, effectiveSigner, pool, note, microAlgos, subsidy, isFalcon)
          break // success
        } catch (err) {
          // Always clear tree cache on failure — the in-memory tree has a phantom leaf
          clearTreeCache(pool.appId)
          if (attempt < MAX_DEPOSIT_RETRIES && isStaleRootError(err)) {
            console.warn(`Deposit attempt ${attempt} failed (stale root), retrying...`)
            setState(s => ({
              ...s,
              stage: 'depositing',
              message: `Another deposit was processed. Retrying... (${attempt}/${MAX_DEPOSIT_RETRIES})`,
            }))
            continue
          }
          throw err // non-retryable or out of retries
        }
      }

      await saveNote(note)
      recordOperation('deposit')
      invalidateCache()

      addToast('success', `Deposited ${amountAlgo} ALGO into the privacy pool`)
      const updatedNotes = await loadNotes()
      setState(s => ({
        ...s,
        stage: 'deposit_complete',
        message: `Deposit confirmed! ${amountAlgo} ALGO is now shielded in the pool.`,
        txId: txId!,
        error: null,
        savedNotes: updatedNotes,
      }))
    } catch (err) {
      if (err instanceof PasswordRequiredError || (err as any)?.name === 'PasswordRequiredError') throw err
      const msg = humanizeError(err)
      console.error('Deposit error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, signData, getClient, addToast, falcon])

  /** Build and submit a withdrawal with ZK proof. Returns txId. */
  async function executeWithdraw(
    client: algosdk.Algodv2,
    sender: string,
    signer: typeof transactionSigner,
    pool: { appId: number; appAddress: string },
    note: DepositNote,
    destinationAddr: string,
    falconMode: boolean = false,
  ): Promise<string> {
    await initMimc()

    // Check if nullifier is already spent
    const alreadySpent = await isNullifierSpent(client, pool.appId, note.nullifier)
    if (alreadySpent) {
      await removeNoteByCommitment(note.commitment)
      throw new Error('Note already spent on-chain')
    }

    // Sync local Merkle tree
    setState(s => ({ ...s, message: 'Syncing Merkle tree...' }))
    const tree = await incrementalSyncTree(pool.appId)
    const merklePath = getPath(tree, note.leafIndex)
    const root = tree.root

    // Generate ZK proof
    setState(s => ({ ...s, stage: 'generating_proof', message: 'Preparing withdrawal proof...' }))

    const proofSystem = USE_PLONK_LSIG ? 'plonk' as const : 'groth16' as const
    const zkeyFile = USE_PLONK_LSIG ? '/circuits/withdraw_plonk.zkey' : '/circuits/withdraw_final.zkey'

    const nullifierHash = computeNullifierHash(note.nullifier)
    const relayerAddr = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'
    const relayerFee = 0n

    const circuitInput = {
      root: root.toString(),
      nullifierHash: nullifierHash.toString(),
      recipient: addressToScalar(destinationAddr).toString(),
      relayer: addressToScalar(relayerAddr).toString(),
      fee: relayerFee.toString(),
      amount: note.denomination.toString(),
      secret: note.secret.toString(),
      nullifier: note.nullifier.toString(),
      pathElements: merklePath.pathElements.map(e => e.toString()),
      pathIndices: merklePath.pathIndices,
    }

    const { proof, publicSignals } = await generateProof(
      proofSystem,
      circuitInput,
      '/circuits/withdraw.wasm',
      zkeyFile,
      (msg) => setState(s => ({ ...s, message: msg })),
    )

    setState(s => ({ ...s, stage: 'withdrawing', message: 'Building withdrawal transaction...' }))

    const proofBytes = USE_PLONK_LSIG
      ? (await import('../lib/plonkVerifierLsig')).encodePlonkProof(proof)
      : encodeProofForVerifier(parseGroth16Proof(proof))
    const signalsBytes = encodePublicSignals(root, nullifierHash, destinationAddr, relayerAddr, relayerFee, note.denomination)
    const nullifierHashBytes = scalarToBytes(nullifierHash)
    const rootBytes = scalarToBytes(root)
    const recipientSignalBytes = scalarToBytes(addressToScalar(destinationAddr))
    const relayerSignalBytes = scalarToBytes(addressToScalar(relayerAddr))

    const params = await client.getTransactionParams().do()
    let txId: string

    if (USE_PLONK_LSIG) {
      const plonk = await import('../lib/plonkVerifierLsig')
      const verifier = await loadPlonkVerifier(client, 'withdraw')
      if (!verifier) throw new Error('PLONK withdraw verifier not available')

      const lsigTxns = plonk.buildPlonkVerifierGroup(verifier, proofBytes, signalsBytes, sender, params)

      const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
      const relayerPubKey = algosdk.decodeAddress(relayerAddr).publicKey

      const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: pool.appId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.withdraw,
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(0n),
          abiEncodeBytes(rootBytes),
          abiEncodeBytes(recipientSignalBytes),
          abiEncodeBytes(relayerSignalBytes),
        ],
        accounts: [destinationAddr],
        boxes: withdrawBoxRefs(pool.appId, nullifierHashBytes, rootBytes),
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const withdrawGroup = [...lsigTxns, withdrawAppCall]
      const wFeeTxn = buildProtocolFeeTxn(sender, params)
      if (wFeeTxn) withdrawGroup.push(wFeeTxn)

      algosdk.assignGroupID(withdrawGroup)

      setState(s => ({ ...s, message: falconMode ? 'Signing withdrawal with Falcon...' : 'Approve withdrawal in your wallet...' }))
      const inversesBytes = await computePlonkInverses('withdraw', proof, publicSignals)
      const signedTxns = await signPlonkMixedGroup(verifier, withdrawGroup, proofBytes, inversesBytes, signer)

      txId = withdrawAppCall.txID()
      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(signedTxns).do()
    } else {
      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: VERIFIER_APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: [BUDGET_HELPER_APP_ID],
        suggestedParams: { ...params, fee: FEES.withdrawVerifierCall, flatFee: true },
      })

      const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
      const relayerPubKey = algosdk.decodeAddress(relayerAddr).publicKey

      const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: pool.appId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.withdraw,
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(0n),
          abiEncodeBytes(rootBytes),
          abiEncodeBytes(recipientSignalBytes),
          abiEncodeBytes(relayerSignalBytes),
        ],
        accounts: [destinationAddr],
        boxes: withdrawBoxRefs(pool.appId, nullifierHashBytes, rootBytes),
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const withdrawGroup: algosdk.Transaction[] = [verifierAppCall, withdrawAppCall]
      const wFeeTxn = buildProtocolFeeTxn(sender, params)
      if (wFeeTxn) withdrawGroup.push(wFeeTxn)

      // Groth16 + Falcon: add padding txns for byte budget
      if (falconMode) {
        while (withdrawGroup.length < 4) {
          withdrawGroup.push(algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender, receiver: sender, amount: 0, suggestedParams: params,
          }))
        }
      }

      algosdk.assignGroupID(withdrawGroup)

      setState(s => ({ ...s, message: falconMode ? 'Signing withdrawal with Falcon...' : 'Approve withdrawal in your wallet...' }))
      const signedTxns = await signer(withdrawGroup, withdrawGroup.map((_, i) => i))

      txId = withdrawAppCall.txID()
      setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
      await client.sendRawTransaction(signedTxns).do()
    }

    setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
    await algosdk.waitForConfirmation(client, txId, 4)

    return txId
  }

  // ── WITHDRAW ─────────────────────────────
  const withdraw = useCallback(async (noteCommitment: bigint, destinationAddr: string) => {
    let effectiveSender: string
    let effectiveSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>
    let isFalcon: boolean
    try {
      ({ sender: effectiveSender, signer: effectiveSigner, isFalcon } = await ensureSigner())
    } catch {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    if (!algosdk.isValidAddress(destinationAddr)) {
      addToast('error', 'Invalid destination address')
      setState(s => ({ ...s, stage: 'error', error: 'Invalid destination address' }))
      return
    }

    if (!VERIFIER_APP_ID) {
      addToast('error', 'Withdraw verifier not deployed. Run the deploy script first.')
      setState(s => ({ ...s, stage: 'error', error: 'Withdraw verifier not deployed (appId = 0)' }))
      return
    }

    const notes = await loadNotes()
    const note = notes.find(n => n.commitment === noteCommitment)
    if (!note) {
      addToast('error', 'No deposit note found')
      setState(s => ({ ...s, stage: 'error', error: 'No deposit note found' }))
      return
    }
    const client = getClient()
    const pool = getPoolForTier(note.denomination)

    try {
      // Anti-correlation: enforce cooldown between operations
      const cooldown = checkCooldown()
      if (!cooldown.ok) {
        addToast('error', `Please wait ${cooldown.remainingSec}s between operations to avoid creating linkable patterns`)
        setState(s => ({ ...s, stage: 'error', error: `Cooldown: wait ${cooldown.remainingSec}s between operations` }))
        return
      }

      // Anti-correlation: warn about cluster patterns
      const clusterWarning = checkClusterRisk()
      if (clusterWarning) {
        addToast('error', clusterWarning)
      }

      // Privacy check: block if pool has too few deposits
      await checkPoolSize(client, pool.appId, 'Withdrawal')

      // Anti-correlation: soak time — warn if too few deposits since this note
      const contractState = await readContractState(client, pool.appId)
      const depositsSinceNote = contractState.nextIndex - note.leafIndex
      if (depositsSinceNote < MIN_SOAK_DEPOSITS) {
        const needed = MIN_SOAK_DEPOSITS - depositsSinceNote
        const proceed = await new Promise<boolean>(resolve => {
          setState(s => ({ ...s, soakWarning: { depositsSince: depositsSinceNote, needed, resolve } }))
        })
        setState(s => ({ ...s, soakWarning: null }))
        if (!proceed) {
          setState(s => ({ ...s, stage: 'idle' }))
          return
        }
      }

      // Privacy warning: direct withdrawal links sender wallet to withdrawal destination
      // (Falcon mode is already pseudonymous — no warning needed)
      if ((!useRelayerState || !relayerAvailable) && !isFalcon) {
        addToast('error', 'Direct withdrawal: your wallet address will be visible on-chain, linking you to this withdrawal. Enable relayer mode for full privacy.')
      }

      // Optional batch delay — multiple withdrawals in the same window are harder to correlate
      if (useRelayerState && relayerAvailable && !isFalcon) {
        await awaitBatchWindow()
      }

      // Anti-correlation: random jitter before submission
      setState(s => ({ ...s, stage: 'withdrawing', message: 'Adding timing jitter for privacy...', txId: null, error: null }))
      await withdrawJitter()

      setState(s => ({ ...s, stage: 'withdrawing', message: 'Checking note status...', txId: null, error: null }))

      await initMimc()

      // Check if nullifier is already spent before generating expensive proof
      const alreadySpent = await isNullifierSpent(client, pool.appId, note.nullifier)
      if (alreadySpent) {
        await removeNoteByCommitment(note.commitment)
        const updated = await loadNotes()
        addToast('error', 'This note has already been withdrawn')
        setState(s => ({ ...s, stage: 'error', message: '', error: 'Note already spent on-chain', txId: null, savedNotes: updated }))
        return
      }

      // Sync local Merkle tree from chain before proof generation
      setState(s => ({ ...s, message: 'Syncing Merkle tree...' }))
      const tree = await incrementalSyncTree(pool.appId)
      const merklePath = getPath(tree, note.leafIndex)
      const root = tree.root

      // Generate ZK proof
      setState(s => ({ ...s, stage: 'generating_proof', message: 'Computing zero-knowledge proof... (10-30 sec)' }))

      const proofSystem = USE_PLONK_LSIG ? 'plonk' as const : 'groth16' as const
      const zkeyFile = USE_PLONK_LSIG ? '/circuits/withdraw_plonk.zkey' : '/circuits/withdraw_final.zkey'

      const nullifierHash = computeNullifierHash(note.nullifier)
      // Skip relayer when Falcon is active — Falcon address is already pseudonymous
      const viaRelayer = useRelayerState && relayerAvailable && !isFalcon
      const chosenRelayer = viaRelayer ? pickRelayer() : null
      const relayerAddr = chosenRelayer ? chosenRelayer.address : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'
      const relayerFee = chosenRelayer ? chosenRelayer.fee : 0n

      const circuitInput = {
        // Public inputs
        root: root.toString(),
        nullifierHash: nullifierHash.toString(),
        recipient: addressToScalar(destinationAddr).toString(),
        relayer: addressToScalar(relayerAddr).toString(),
        fee: relayerFee.toString(),
        amount: note.denomination.toString(),
        // Private inputs
        secret: note.secret.toString(),
        nullifier: note.nullifier.toString(),
        pathElements: merklePath.pathElements.map(e => e.toString()),
        pathIndices: merklePath.pathIndices,
      }

      const { proof, publicSignals } = await generateProof(
        proofSystem,
        circuitInput,
        '/circuits/withdraw.wasm',
        zkeyFile,
        (msg) => setState(s => ({ ...s, message: msg })),
      )

      setState(s => ({ ...s, stage: 'withdrawing', message: 'Building withdrawal transaction...' }))

      // Encode proof and public signals for verifier
      const proofBytes = USE_PLONK_LSIG
        ? (await import('../lib/plonkVerifierLsig')).encodePlonkProof(proof)
        : encodeProofForVerifier(parseGroth16Proof(proof))
      const signalsBytes = encodePublicSignals(root, nullifierHash, destinationAddr, relayerAddr, relayerFee, note.denomination)
      const nullifierHashBytes = scalarToBytes(nullifierHash)
      const rootBytes = scalarToBytes(root)
      const recipientSignalBytes = scalarToBytes(addressToScalar(destinationAddr))
      const relayerSignalBytes = scalarToBytes(addressToScalar(relayerAddr))

      let txId: string

      if (viaRelayer) {
        // Submit via relayer — user doesn't sign, preserving privacy
        setState(s => ({ ...s, message: 'Submitting via relayer...' }))
        const relayerInverses = USE_PLONK_LSIG
          ? await computePlonkInverses('withdraw', proof, publicSignals)
          : undefined
        txId = await submitViaRelayer(
          proofBytes, signalsBytes, pool.appId,
          nullifierHashBytes, rootBytes, destinationAddr,
          Number(relayerFee), chosenRelayer!.url, chosenRelayer!.address,
          relayerInverses,
        )
      } else if (USE_PLONK_LSIG) {
        // PLONK LogicSig group: [lsig×4, withdrawAppCall, ?feeTxn]
        const plonk = await import('../lib/plonkVerifierLsig')
        const verifier = await loadPlonkVerifier(client, 'withdraw')
        if (!verifier) throw new Error('PLONK withdraw verifier not available — deploy PLONK verifiers or set VITE_USE_PLONK_LSIG=false')

        const params = await client.getTransactionParams().do()
        const lsigTxns = plonk.buildPlonkVerifierGroup(verifier, proofBytes, signalsBytes, effectiveSender, params)

        const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
        const relayerPubKey = algosdk.decodeAddress(relayerAddr).publicKey

        const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
          sender: effectiveSender,
          appIndex: pool.appId,
          onComplete: algosdk.OnApplicationComplete.NoOpOC,
          appArgs: [
            METHOD_SELECTORS.withdraw,
            abiEncodeBytes(nullifierHashBytes),
            recipientPubKey,
            relayerPubKey,
            uint64ToBytes(0n),
            abiEncodeBytes(rootBytes),
            abiEncodeBytes(recipientSignalBytes),
            abiEncodeBytes(relayerSignalBytes),
          ],
          accounts: [destinationAddr],
          boxes: withdrawBoxRefs(pool.appId, nullifierHashBytes, rootBytes),
          suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
        })

        const withdrawGroup = [...lsigTxns, withdrawAppCall]
        const wFeeTxn = buildProtocolFeeTxn(effectiveSender, params)
        if (wFeeTxn) withdrawGroup.push(wFeeTxn)

        algosdk.assignGroupID(withdrawGroup)

        setState(s => ({ ...s, message: isFalcon ? 'Signing withdrawal with Falcon...' : 'Approve withdrawal in your wallet...' }))
        const inversesBytes = await computePlonkInverses('withdraw', proof, publicSignals)
        const signedTxns = await signPlonkMixedGroup(verifier, withdrawGroup, proofBytes, inversesBytes, effectiveSigner)

        txId = withdrawAppCall.txID()
        setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
        await client.sendRawTransaction(signedTxns).do()

        setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
        await algosdk.waitForConfirmation(client, txId, 4)
      } else {
        // Groth16 app-based group: [verifierAppCall, withdrawAppCall, ?feeTxn]
        const params = await client.getTransactionParams().do()

        const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
          sender: effectiveSender,
          appIndex: VERIFIER_APP_ID,
          onComplete: algosdk.OnApplicationComplete.NoOpOC,
          appArgs: [proofBytes, signalsBytes],
          foreignApps: [BUDGET_HELPER_APP_ID],
          suggestedParams: { ...params, fee: FEES.withdrawVerifierCall, flatFee: true },
        })

        const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
        const relayerPubKey = algosdk.decodeAddress(relayerAddr).publicKey

        const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
          sender: effectiveSender,
          appIndex: pool.appId,
          onComplete: algosdk.OnApplicationComplete.NoOpOC,
          appArgs: [
            METHOD_SELECTORS.withdraw,
            abiEncodeBytes(nullifierHashBytes),
            recipientPubKey,
            relayerPubKey,
            uint64ToBytes(0n),
            abiEncodeBytes(rootBytes),
            abiEncodeBytes(recipientSignalBytes),
            abiEncodeBytes(relayerSignalBytes),
          ],
          accounts: [destinationAddr],
          boxes: withdrawBoxRefs(pool.appId, nullifierHashBytes, rootBytes),
          suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
        })

        const withdrawGroup: algosdk.Transaction[] = [verifierAppCall, withdrawAppCall]
        const wFeeTxn = buildProtocolFeeTxn(effectiveSender, params)
        if (wFeeTxn) withdrawGroup.push(wFeeTxn)

        // Groth16 + Falcon: add padding txns for byte budget
        if (isFalcon) {
          while (withdrawGroup.length < 4) {
            withdrawGroup.push(algosdk.makePaymentTxnWithSuggestedParamsFromObject({
              sender: effectiveSender, receiver: effectiveSender, amount: 0, suggestedParams: params,
            }))
          }
        }

        algosdk.assignGroupID(withdrawGroup)

        setState(s => ({ ...s, message: isFalcon ? 'Signing withdrawal with Falcon...' : 'Approve withdrawal in your wallet...' }))
        const signedTxns = await effectiveSigner(
          withdrawGroup,
          withdrawGroup.map((_, i) => i),
        )

        txId = withdrawAppCall.txID()
        setState(s => ({ ...s, message: 'Submitting withdrawal...' }))
        await client.sendRawTransaction(signedTxns).do()

        setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
        await algosdk.waitForConfirmation(client, txId, 4)
      }

      // Remove used note by commitment (safe regardless of index shifts)
      await removeNoteByCommitment(note.commitment)

      const algoAmount = (Number(note.denomination) / 1_000_000).toFixed(6).replace(/\.?0+$/, '')
      recordOperation('withdraw')
      invalidateCache()
      addToast('success', `Withdrew ${algoAmount} ALGO to destination`)
      const wNotes = await loadNotes()
      setState(s => ({
        ...s,
        stage: 'withdraw_complete',
        message: `${algoAmount} ALGO withdrawn from the pool to the destination!`,
        txId,
        error: null,
        savedNotes: wNotes,
      }))
    } catch (err) {
      if (err instanceof PasswordRequiredError || (err as any)?.name === 'PasswordRequiredError') throw err
      const msg = humanizeError(err)
      console.error('Withdraw error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, getClient, addToast, useRelayerState, relayerAvailable, signData, falcon])

  /** Build and submit a privateSend with ZK combined proof. Returns txId. */
  async function executePrivateSend(
    client: algosdk.Algodv2,
    sender: string,
    signer: typeof transactionSigner,
    pool: { appId: number; appAddress: string },
    note: DepositNote,
    microAlgos: bigint,
    destinationAddr: string,
    recipientViewPubkey?: Uint8Array | null,
    subsidyMicroAlgos: bigint = 0n,
    falconMode: boolean = false,
  ): Promise<string> {
    // Sync tree and prepare insertion
    setState(s => ({ ...s, message: 'Syncing Merkle tree...' }))
    const tree = await incrementalSyncTree(pool.appId)
    const oldRoot = tree.root
    const contractState = await readContractState(client, pool.appId)

    const { index: leafIndex, root: newRoot } = insertLeaf(tree, note.commitment)
    note.leafIndex = leafIndex

    const merklePath = getPath(tree, leafIndex)
    const nullifierHash = computeNullifierHash(note.nullifier)
    // Skip relayer when Falcon is active — Falcon address is already pseudonymous
    const viaRelayer = useRelayerState && relayerAvailable && !falconMode
    const chosenRelayer = viaRelayer ? pickRelayer() : null
    const relayerAddr = chosenRelayer ? chosenRelayer.address : 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'
    const relayerFee = chosenRelayer ? chosenRelayer.fee : 0n

    // Generate ONE combined ZK proof (privateSend circuit)
    setState(s => ({ ...s, stage: 'generating_proof', message: 'Computing zero-knowledge proof... (10-30 sec)' }))

    const proofSystem = USE_PLONK_LSIG ? 'plonk' as const : 'groth16' as const
    const zkeyFile = USE_PLONK_LSIG ? '/circuits/privateSend_plonk.zkey' : '/circuits/privateSend_final.zkey'

    const circuitInput = {
      oldRoot: oldRoot.toString(),
      newRoot: newRoot.toString(),
      commitment: note.commitment.toString(),
      leafIndex: leafIndex.toString(),
      nullifierHash: nullifierHash.toString(),
      recipient: addressToScalar(destinationAddr).toString(),
      relayer: addressToScalar(relayerAddr).toString(),
      fee: relayerFee.toString(),
      amount: microAlgos.toString(),
      secret: note.secret.toString(),
      nullifier: note.nullifier.toString(),
      pathElements: merklePath.pathElements.map(e => e.toString()),
    }

    const { proof, publicSignals } = await generateProof(
      proofSystem,
      circuitInput,
      '/circuits/privateSend.wasm',
      zkeyFile,
      (msg) => setState(s => ({ ...s, message: msg })),
    )

    // Pre-check: re-read on-chain root after proof gen — if it changed, abort
    setState(s => ({ ...s, stage: 'depositing', message: 'Verifying tree state...' }))
    const freshState = await readContractState(client, pool.appId)
    if (bytesToScalar(freshState.currentRoot) !== oldRoot) {
      throw new Error('Tree root changed during proof generation (concurrent deposit)')
    }

    // Build 3-txn group: [privateSend verifier call, payment, pool privateSend call]
    setState(s => ({ ...s, stage: 'withdrawing', message: 'Building transaction...' }))

    const proofBytes = USE_PLONK_LSIG
      ? (await import('../lib/plonkVerifierLsig')).encodePlonkProof(proof)
      : encodeProofForVerifier(parseGroth16Proof(proof))
    const signalsBytes = encodePrivateSendSignals(
      oldRoot, newRoot, note.commitment, BigInt(leafIndex),
      nullifierHash, destinationAddr, relayerAddr, relayerFee, microAlgos,
    )

    const commitmentBytes = scalarToBytes(note.commitment)
    const mimcRootBytes = scalarToBytes(newRoot)
    const nullifierHashBytes = scalarToBytes(nullifierHash)
    const recipientSignalBytes = scalarToBytes(addressToScalar(destinationAddr))
    const relayerSignalBytes = scalarToBytes(addressToScalar(relayerAddr))
    const recipientPubKey = algosdk.decodeAddress(destinationAddr).publicKey
    const relayerPubKey = algosdk.decodeAddress(relayerAddr).publicKey

    const params = await client.getTransactionParams().do()

    // Read evicted root for knownRoots pruning (only when ring buffer wraps at >=1000 deposits)
    const evictedRoot = await readEvictedRoot(client, pool.appId, freshState.rootHistoryIndex)
    const boxes = privateSendBoxRefs(pool.appId, freshState.rootHistoryIndex, freshState.nextIndex, nullifierHashBytes, mimcRootBytes, evictedRoot)

    // Do NOT emit HPKE envelope for privateSend — the contract burns the note's
    // nullifier during execution, so the recipient would import an unspendable note.
    // The recipient receives ALGO via the inner payment, not via the note.
    const hpkeNote: Uint8Array | undefined = undefined

    let txId: string

    if (USE_PLONK_LSIG) {
      // PLONK LogicSig group: [lsig×4, payTxn, poolAppCall, ?feeTxn]
      const plonk = await import('../lib/plonkVerifierLsig')
      const verifier = await loadPlonkVerifier(client, 'privateSend')
      if (!verifier) throw new Error('PLONK privateSend verifier not available — deploy PLONK verifiers or set VITE_USE_PLONK_LSIG=false')

      const lsigTxns = plonk.buildPlonkVerifierGroup(verifier, proofBytes, signalsBytes, sender, params)

      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender,
        receiver: pool.appAddress,
        amount: Number(microAlgos),
        suggestedParams: params,
      })

      const poolAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: pool.appId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.privateSend,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(mimcRootBytes),
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(relayerFee),
          abiEncodeBytes(recipientSignalBytes),
          abiEncodeBytes(relayerSignalBytes),
        ],
        accounts: [destinationAddr],
        boxes,
        note: hpkeNote,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const psGroup = [...lsigTxns, payTxn, poolAppCall]
      const psFeeTxn = buildProtocolFeeTxn(sender, params, subsidyMicroAlgos)
      if (psFeeTxn) psGroup.push(psFeeTxn)

      algosdk.assignGroupID(psGroup)

      setState(s => ({ ...s, message: falconMode ? 'Signing transaction with Falcon...' : 'Approve transaction in your wallet...' }))
      const inversesBytes = await computePlonkInverses('privateSend', proof, publicSignals)
      const signedTxns = await signPlonkMixedGroup(verifier, psGroup, proofBytes, inversesBytes, signer)

      setState(s => ({ ...s, message: 'Submitting transaction...' }))
      const result = await client.sendRawTransaction(signedTxns).do()
      txId = (result as any).txid ?? (result as any).txId
    } else {
      // Groth16 app-based group: [verifierAppCall, payTxn, poolAppCall, ?feeTxn]
      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: PRIVATESEND_VERIFIER_APP_ID,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: [PRIVATESEND_BUDGET_HELPER_APP_ID],
        suggestedParams: { ...params, fee: FEES.privateSendVerifierCall, flatFee: true },
      })

      const payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender,
        receiver: pool.appAddress,
        amount: Number(microAlgos),
        suggestedParams: params,
      })

      const poolAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender,
        appIndex: pool.appId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [
          METHOD_SELECTORS.privateSend,
          abiEncodeBytes(commitmentBytes),
          abiEncodeBytes(mimcRootBytes),
          abiEncodeBytes(nullifierHashBytes),
          recipientPubKey,
          relayerPubKey,
          uint64ToBytes(relayerFee),
          abiEncodeBytes(recipientSignalBytes),
          abiEncodeBytes(relayerSignalBytes),
        ],
        foreignApps: [PRIVATESEND_VERIFIER_APP_ID],
        accounts: [destinationAddr],
        boxes,
        note: hpkeNote,
        suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
      })

      const psGroup: algosdk.Transaction[] = [verifierAppCall, payTxn, poolAppCall]
      const psFeeTxn = buildProtocolFeeTxn(sender, params, subsidyMicroAlgos)
      if (psFeeTxn) psGroup.push(psFeeTxn)

      // Groth16 + Falcon: add padding txns for byte budget
      if (falconMode) {
        while (psGroup.length < 4) {
          psGroup.push(algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            sender, receiver: sender, amount: 0, suggestedParams: params,
          }))
        }
      }

      algosdk.assignGroupID(psGroup)

      setState(s => ({ ...s, message: falconMode ? 'Signing transaction with Falcon...' : 'Approve transaction in your wallet...' }))
      const signedTxns = await signer(
        psGroup,
        psGroup.map((_, i) => i),
      )

      setState(s => ({ ...s, message: 'Submitting transaction...' }))
      const result = await client.sendRawTransaction(signedTxns).do()
      txId = (result as any).txid ?? (result as any).txId
    }

    setState(s => ({ ...s, message: 'Waiting for confirmation...' }))
    await algosdk.waitForConfirmation(client, txId, 4)

    // Persist tree after successful confirmation
    saveTree(tree, pool.appId)
    return txId
  }

  // ── PRIVATE SEND (combined single-proof deposit+withdraw) ──
  const privateSend = useCallback(async (microAlgos: bigint, destinationAddr: string, skipBatchWait?: boolean, subsidyMicroAlgos?: bigint) => {
    let effectiveSender: string
    let effectiveSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>
    let isFalcon: boolean
    try {
      ({ sender: effectiveSender, signer: effectiveSigner, isFalcon } = await ensureSigner())
    } catch {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }
    if (!isValidTier(microAlgos)) {
      addToast('error', `Invalid denomination. Use ${DENOMINATION_TIERS.map(t => t.label).join(', ')} ALGO`)
      setState(s => ({ ...s, stage: 'error', error: 'Invalid denomination tier' }))
      return
    }

    // Accept both priv1... privacy addresses and raw Algorand addresses
    let recipientAlgoAddr: string
    let recipientViewPubkey: Uint8Array | null = null
    if (isPrivacyAddress(destinationAddr)) {
      const decoded = decodePrivacyAddress(destinationAddr)
      recipientAlgoAddr = algosdk.encodeAddress(decoded.algoPubkey)
      recipientViewPubkey = decoded.viewPubkey
    } else if (algosdk.isValidAddress(destinationAddr)) {
      recipientAlgoAddr = destinationAddr
    } else {
      addToast('error', 'Invalid destination address')
      setState(s => ({ ...s, stage: 'error', error: 'Invalid destination address' }))
      return
    }

    if (!PRIVATESEND_VERIFIER_APP_ID) {
      addToast('error', 'PrivateSend verifier not deployed. Run the deploy script first.')
      setState(s => ({ ...s, stage: 'error', error: 'PrivateSend verifier not deployed (appId = 0)' }))
      return
    }

    const amountMicroAlgo = Number(microAlgos)
    const amountAlgo = amountMicroAlgo / 1_000_000
    const client = getClient()
    const pool = getPoolForTier(microAlgos)

    try {
      // Anti-correlation: enforce cooldown between operations
      const cooldown = checkCooldown()
      if (!cooldown.ok) {
        addToast('error', `Please wait ${cooldown.remainingSec}s between operations to avoid creating linkable patterns`)
        setState(s => ({ ...s, stage: 'error', error: `Cooldown: wait ${cooldown.remainingSec}s between operations` }))
        return
      }

      // Anti-correlation: warn about cluster patterns
      const clusterWarning = checkClusterRisk()
      if (clusterWarning) {
        addToast('error', clusterWarning)
      }

      // Privacy check: block if pool has too few deposits
      await checkPoolSize(client, pool.appId, 'Private send')

      setState(s => ({ ...s, stage: 'depositing', message: 'Initializing cryptography...', txId: null, error: null }))

      await initMimc()

      // Pre-check balance for combined privateSend fee
      const subsidy = subsidyMicroAlgos ?? 0n
      const falconFee = isFalcon && !USE_PLONK_LSIG ? FALCON_EXTRA_FEE.groth16Padding : 0n
      setState(s => ({ ...s, message: 'Checking balance...' }))
      await checkBalance(client, effectiveSender, microAlgos + FEES.privateSend + PROTOCOL_FEE + subsidy + falconFee)

      setState(s => ({ ...s, message: 'Deriving deposit key...' }))
      const masterKey = await deriveMasterKey(signData)
      const depositIdx = await claimNextDepositIndex() // atomic claim
      const note = deriveDeposit(masterKey, depositIdx, microAlgos, 0)

      // Wait for batch window (timing attack mitigation)
      await awaitBatchWindow(skipBatchWait)
      setState(s => ({ ...s, stage: 'depositing', message: 'Starting private send...', txId: null, error: null }))

      // Attempt privateSend with retry on stale root (concurrent deposit by another user)
      let txId: string | undefined
      for (let attempt = 1; attempt <= MAX_DEPOSIT_RETRIES; attempt++) {
        try {
          txId = await executePrivateSend(client, effectiveSender, effectiveSigner, pool, note, microAlgos, recipientAlgoAddr, recipientViewPubkey, subsidy, isFalcon)
          break // success
        } catch (err) {
          clearTreeCache(pool.appId) // Always clear — in-memory tree has phantom leaf
          if (attempt < MAX_DEPOSIT_RETRIES && isStaleRootError(err)) {
            console.warn(`PrivateSend attempt ${attempt} failed (stale root), retrying...`)
            setState(s => ({
              ...s,
              stage: 'depositing',
              message: `Another deposit was processed. Retrying... (${attempt}/${MAX_DEPOSIT_RETRIES})`,
            }))
            continue
          }
          throw err // non-retryable or out of retries
        }
      }

      const displayAddr = recipientAlgoAddr.slice(0, 6) + '...' + recipientAlgoAddr.slice(-4)
      recordOperation('deposit') // privateSend is deposit+withdraw combined
      invalidateCache()
      addToast('success', `${amountAlgo} ALGO sent privately to ${displayAddr}`)
      const psNotes = await loadNotes()
      setState(s => ({
        ...s,
        stage: 'withdraw_complete',
        message: `${amountAlgo} ALGO sent privately to ${displayAddr}`,
        txId: txId!,
        error: null,
        savedNotes: psNotes,
      }))
    } catch (err) {
      if (err instanceof PasswordRequiredError || (err as any)?.name === 'PasswordRequiredError') throw err
      const msg = humanizeError(err)
      console.error('Private send error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg }))
    }
  }, [activeAddress, transactionSigner, signData, getClient, addToast, falcon])

  // ── CHURN (withdraw old note + deposit new one) ──
  const churnNote = useCallback(async (note: DepositNote) => {
    if (!activeAddress) {
      addToast('error', 'Wallet not connected')
      return
    }
    // Must use withdraw+deposit to actually consume the old note's nullifier.
    // privateSend derives a fresh note and doesn't spend the specified one.
    // Self-churn is inherently linkable (same address), but the old note IS consumed.
    // Withdraw to the effective sender (Falcon address if active, wallet address otherwise)
    const churnDest = (falcon.enabled && falcon.funded && falcon.account)
      ? falcon.account.address
      : activeAddress
    await withdraw(note.commitment, churnDest)
    await deposit(note.denomination)
    addToast('success', 'Note churned — old nullifier spent, new note created')
  }, [activeAddress, withdraw, deposit, addToast, falcon])

  // ── SPLIT (1.0 ALGO → 2×0.5 ALGO) ──
  const split = useCallback(async (noteCommitment: bigint) => {
    let effectiveSender: string
    let effectiveSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>
    let isFalcon: boolean
    try {
      ({ sender: effectiveSender, signer: effectiveSigner, isFalcon } = await ensureSigner())
    } catch {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    const notes = await loadNotes()
    const note = notes.find(n => n.commitment === noteCommitment)
    if (!note) {
      addToast('error', 'Note not found')
      setState(s => ({ ...s, stage: 'error', error: 'Note not found' }))
      return
    }

    // Only 1.0 → 2×0.5 is supported (0.5/2 = 0.25 is not a valid tier)
    const destDenom = note.denomination / 2n
    if (!isValidTier(destDenom)) {
      addToast('error', `Cannot split ${Number(note.denomination) / 1_000_000} ALGO notes`)
      setState(s => ({ ...s, stage: 'error', error: 'No valid destination denomination for this split' }))
      return
    }

    const client = getClient()
    const sourcePool = getPoolForTier(note.denomination)
    const destPool = getPoolForTier(destDenom)

    try {
      const cooldown = checkCooldown()
      if (!cooldown.ok) {
        addToast('error', `Please wait ${cooldown.remainingSec}s between operations`)
        setState(s => ({ ...s, stage: 'error', error: `Cooldown: wait ${cooldown.remainingSec}s` }))
        return
      }

      // Privacy check: block if source pool has too few deposits
      await checkPoolSize(client, sourcePool.appId, 'Split')

      setState(s => ({ ...s, stage: 'withdrawing', message: 'Split step 1/3: Withdrawing from source pool...', txId: null, error: null }))
      await initMimc()

      // Checkpoint: track multi-step progress so we can recover from partial failure
      const checkpoint = {
        op: 'split' as const,
        sourceCommitment: note.commitment.toString(),
        sourceDenom: note.denomination.toString(),
        destDenom: destDenom.toString(),
        step: 0,
      }
      localStorage.setItem('privacy_pool_pending_op', JSON.stringify(checkpoint))

      // Step 1: Withdraw from source pool to self
      await executeWithdraw(client, effectiveSender, effectiveSigner, sourcePool, note, effectiveSender, isFalcon)
      await removeNoteByCommitment(note.commitment)
      checkpoint.step = 1
      localStorage.setItem('privacy_pool_pending_op', JSON.stringify(checkpoint))

      // Step 2: First deposit into destination pool (with retry on concurrent deposit)
      setState(s => ({ ...s, stage: 'depositing', message: 'Split step 2/3: First deposit...' }))
      const masterKey = await deriveMasterKey(signData)
      const depositIdx1 = await claimNextDepositIndex() // atomic claim
      const note1 = deriveDeposit(masterKey, depositIdx1, destDenom, 0)

      for (let attempt = 1; attempt <= MAX_DEPOSIT_RETRIES; attempt++) {
        try {
          await executeDeposit(client, effectiveSender, effectiveSigner, destPool, note1, destDenom, 0n, isFalcon)
          break
        } catch (err) {
          clearTreeCache(destPool.appId)
          if (attempt < MAX_DEPOSIT_RETRIES && isStaleRootError(err)) {
            setState(s => ({ ...s, message: `Split step 2/3: Retrying deposit... (${attempt}/${MAX_DEPOSIT_RETRIES})` }))
            continue
          }
          throw err
        }
      }
      await saveNote(note1)
      checkpoint.step = 2
      localStorage.setItem('privacy_pool_pending_op', JSON.stringify(checkpoint))

      // Step 3: Second deposit into destination pool (with retry)
      setState(s => ({ ...s, stage: 'depositing', message: 'Split step 3/3: Second deposit...' }))
      const depositIdx2 = await claimNextDepositIndex() // atomic claim
      const note2 = deriveDeposit(masterKey, depositIdx2, destDenom, 0)

      let lastTxId: string | undefined
      clearTreeCache(destPool.appId)
      for (let attempt = 1; attempt <= MAX_DEPOSIT_RETRIES; attempt++) {
        try {
          lastTxId = await executeDeposit(client, effectiveSender, effectiveSigner, destPool, note2, destDenom, 0n, isFalcon)
          break
        } catch (err) {
          clearTreeCache(destPool.appId)
          if (attempt < MAX_DEPOSIT_RETRIES && isStaleRootError(err)) {
            setState(s => ({ ...s, message: `Split step 3/3: Retrying deposit... (${attempt}/${MAX_DEPOSIT_RETRIES})` }))
            continue
          }
          throw err
        }
      }
      await saveNote(note2)

      // All steps complete — clear checkpoint
      localStorage.removeItem('privacy_pool_pending_op')

      recordOperation('withdraw')
      invalidateCache()
      const srcAlgo = (Number(note.denomination) / 1_000_000).toFixed(1)
      const dstAlgo = (Number(destDenom) / 1_000_000).toFixed(1)
      addToast('success', `Split complete: ${srcAlgo} ALGO → 2×${dstAlgo} ALGO`)
      const updatedNotes = await loadNotes()
      setState(s => ({
        ...s,
        stage: 'withdraw_complete',
        message: `Split complete! ${srcAlgo} ALGO → 2×${dstAlgo} ALGO`,
        txId: lastTxId!,
        error: null,
        savedNotes: updatedNotes,
      }))
    } catch (err) {
      if (err instanceof PasswordRequiredError || (err as any)?.name === 'PasswordRequiredError') throw err
      // Clear tree caches on failure — but keep checkpoint so user can see what happened
      clearTreeCache(sourcePool.appId)
      clearTreeCache(destPool.appId)
      const pending = localStorage.getItem('privacy_pool_pending_op')
      const step = pending ? JSON.parse(pending).step : 0
      const msg = humanizeError(err)
      const recovery = step > 0
        ? `\n\nSplit failed at step ${step + 1}/3. Your ${(Number(note.denomination) / 1_000_000).toFixed(1)} ALGO was withdrawn to your wallet. Re-deposit manually or retry.`
        : ''
      console.error('Split error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg + recovery }))
      if (step >= 3) localStorage.removeItem('privacy_pool_pending_op')
    }
  }, [activeAddress, transactionSigner, signData, getClient, addToast, falcon])

  // ── COMBINE (2×0.5 ALGO → 1.0 ALGO) ──
  const combine = useCallback(async (noteCommitment1: bigint, noteCommitment2: bigint) => {
    let effectiveSender: string
    let effectiveSigner: (txns: algosdk.Transaction[], indices: number[]) => Promise<Uint8Array[]>
    let isFalcon: boolean
    try {
      ({ sender: effectiveSender, signer: effectiveSigner, isFalcon } = await ensureSigner())
    } catch {
      addToast('error', 'Wallet not connected')
      setState(s => ({ ...s, stage: 'error', error: 'Wallet not connected' }))
      return
    }

    const notes = await loadNotes()
    const note1 = notes.find(n => n.commitment === noteCommitment1)
    const note2 = notes.find(n => n.commitment === noteCommitment2)
    if (!note1 || !note2) {
      addToast('error', 'One or both notes not found')
      setState(s => ({ ...s, stage: 'error', error: 'Notes not found' }))
      return
    }

    if (note1.denomination !== note2.denomination) {
      addToast('error', 'Both notes must be the same denomination')
      setState(s => ({ ...s, stage: 'error', error: 'Denomination mismatch' }))
      return
    }

    // Only 2×0.5 → 1.0 is supported (2×0.1 = 0.2 is not a valid tier)
    const destDenom = note1.denomination * 2n
    if (!isValidTier(destDenom)) {
      addToast('error', `Cannot combine ${Number(note1.denomination) / 1_000_000} ALGO notes`)
      setState(s => ({ ...s, stage: 'error', error: 'No valid destination denomination for this combine' }))
      return
    }

    const client = getClient()
    const sourcePool = getPoolForTier(note1.denomination)
    const destPool = getPoolForTier(destDenom)

    // Checkpoint for recovery if combine fails mid-way
    const checkpoint = { op: 'combine', step: 0, srcDenom: note1.denomination.toString(), destDenom: destDenom.toString() }

    try {
      const cooldown = checkCooldown()
      if (!cooldown.ok) {
        addToast('error', `Please wait ${cooldown.remainingSec}s between operations`)
        setState(s => ({ ...s, stage: 'error', error: `Cooldown: wait ${cooldown.remainingSec}s` }))
        return
      }

      // Privacy check: block if source pool has too few deposits
      await checkPoolSize(client, sourcePool.appId, 'Combine')

      setState(s => ({ ...s, stage: 'withdrawing', message: 'Combine step 1/3: Withdrawing note 1...', txId: null, error: null }))
      await initMimc()
      localStorage.setItem('privacy_pool_pending_op', JSON.stringify(checkpoint))

      // Step 1: Withdraw first note from source pool to self
      await executeWithdraw(client, effectiveSender, effectiveSigner, sourcePool, note1, effectiveSender, isFalcon)
      await removeNoteByCommitment(note1.commitment)
      checkpoint.step = 1
      localStorage.setItem('privacy_pool_pending_op', JSON.stringify(checkpoint))

      // Step 2: Withdraw second note from source pool to self
      setState(s => ({ ...s, stage: 'withdrawing', message: 'Combine step 2/3: Withdrawing note 2...' }))
      await executeWithdraw(client, effectiveSender, effectiveSigner, sourcePool, note2, effectiveSender, isFalcon)
      await removeNoteByCommitment(note2.commitment)
      checkpoint.step = 2
      localStorage.setItem('privacy_pool_pending_op', JSON.stringify(checkpoint))

      // Step 3: Deposit combined amount into destination pool (with retry)
      setState(s => ({ ...s, stage: 'depositing', message: 'Combine step 3/3: Depositing combined amount...' }))
      const masterKey = await deriveMasterKey(signData)
      const depositIdx = await claimNextDepositIndex() // atomic claim
      const newNote = deriveDeposit(masterKey, depositIdx, destDenom, 0)

      let txId: string | undefined
      for (let attempt = 1; attempt <= MAX_DEPOSIT_RETRIES; attempt++) {
        try {
          txId = await executeDeposit(client, effectiveSender, effectiveSigner, destPool, newNote, destDenom, 0n, isFalcon)
          break
        } catch (err) {
          clearTreeCache(destPool.appId)
          if (attempt < MAX_DEPOSIT_RETRIES && isStaleRootError(err)) {
            setState(s => ({ ...s, message: `Combine step 3/3: Retrying deposit... (${attempt}/${MAX_DEPOSIT_RETRIES})` }))
            continue
          }
          throw err
        }
      }
      await saveNote(newNote)

      // All steps complete — clear checkpoint
      localStorage.removeItem('privacy_pool_pending_op')

      recordOperation('deposit')
      invalidateCache()
      const srcAlgo = (Number(note1.denomination) / 1_000_000).toFixed(1)
      const dstAlgo = (Number(destDenom) / 1_000_000).toFixed(1)
      addToast('success', `Combine complete: 2×${srcAlgo} ALGO → ${dstAlgo} ALGO`)
      const updatedNotes = await loadNotes()
      setState(s => ({
        ...s,
        stage: 'withdraw_complete',
        message: `Combine complete! 2×${srcAlgo} ALGO → ${dstAlgo} ALGO`,
        txId: txId!,
        error: null,
        savedNotes: updatedNotes,
      }))
    } catch (err) {
      if (err instanceof PasswordRequiredError || (err as any)?.name === 'PasswordRequiredError') throw err
      clearTreeCache(sourcePool.appId)
      clearTreeCache(destPool.appId)
      const pending = localStorage.getItem('privacy_pool_pending_op')
      const step = pending ? JSON.parse(pending).step : 0
      const msg = humanizeError(err)
      const srcAlgoErr = (Number(note1.denomination) / 1_000_000).toFixed(1)
      const recovery = step > 0
        ? `\n\nCombine failed at step ${step + 1}/3. ${step === 1 ? `1×${srcAlgoErr}` : `2×${srcAlgoErr}`} ALGO was withdrawn to your wallet. Re-deposit manually or retry.`
        : ''
      console.error('Combine error:', err)
      addToast('error', msg)
      setState(s => ({ ...s, stage: 'error', error: msg + recovery }))
      if (step >= 3) localStorage.removeItem('privacy_pool_pending_op')
    }
  }, [activeAddress, transactionSigner, signData, getClient, addToast, falcon])

  /** Cancel the current batch window wait */
  const skipBatchWaitFn = useCallback(() => {
    if (batchCancelRef.current) {
      batchCancelRef.current()
      batchCancelRef.current = null
    }
  }, [])

  const reset = useCallback(async () => {
    const notes = await loadNotes()
    setState(s => ({
      stage: 'idle',
      message: '',
      txId: null,
      error: null,
      savedNotes: notes,
      batchCountdown: null,
      staleNotes: s.staleNotes,
      poolNextIndices: s.poolNextIndices,
      treasuryBalance: s.treasuryBalance,
      subsidyActive: s.subsidyActive,
      soakWarning: null,
    }))
  }, [])

  const refreshNotes = useCallback(async () => {
    const notes = await loadNotes()
    setState(s => ({ ...s, savedNotes: notes }))
  }, [])

  const refreshStaleNotes = useCallback(async () => {
    const client = getClient()
    const indices = await fetchPoolNextIndices(client)
    const notes = await loadNotes()
    const stale = findStaleNotes(notes, indices, STALE_NOTE_THRESHOLD)
    setState(s => ({ ...s, staleNotes: stale, poolNextIndices: indices }))
  }, [getClient])

  const refreshTreasuryBalance = useCallback(async () => {
    const client = getClient()
    const balance = await readTreasuryBalance(client)
    // Protocol fee is subsidized when treasury has enough to cover it
    const subsidized = balance >= PROTOCOL_FEE
    setState(s => ({ ...s, treasuryBalance: balance, subsidyActive: subsidized }))
  }, [getClient])

  const rebuildAllTrees = useCallback(async (
    onProgress?: (pool: string, done: boolean) => void,
  ) => {
    await syncAllTreesFromChain(onProgress)
  }, [])

  const scanForNotes = useCallback(async (
    onProgress?: (round: number, found: number) => void,
  ): Promise<{ recovered: number; newNotes: number }> => {
    const viewKeypair = await getViewKeypair()
    if (!viewKeypair) throw new Error('View keypair not available — derive master key first')
    const poolAppIds = Object.values(POOL_CONTRACTS).map(p => p.appId)
    const result = await recoverNotesFromChain(viewKeypair, poolAppIds, undefined, onProgress)
    const notes = await loadNotes()
    setState(s => ({ ...s, savedNotes: notes }))
    return { recovered: result.recovered.length, newNotes: result.newNotes }
  }, [])

  return {
    ...state,
    deposit,
    withdraw,
    privateSend,
    churnNote,
    split,
    combine,
    skipBatchWait: skipBatchWaitFn,
    reset,
    refreshNotes,
    refreshStaleNotes,
    refreshTreasuryBalance,
    rebuildAllTrees,
    scanForNotes,
    useRelayer: useRelayerState,
    setUseRelayer,
    relayerAvailable,
  }
}
