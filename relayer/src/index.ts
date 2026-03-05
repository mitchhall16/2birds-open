/**
 * Privacy Pool Relayer — Cloudflare Worker
 *
 * Submits withdrawal and deposit transactions on behalf of users so the on-chain
 * sender is the relayer address, not the user's wallet (preserving privacy).
 *
 * Supports two verification modes:
 *   - PLONK LogicSig (default): 4-txn LogicSig group + pool app call
 *   - Groth16 app call (legacy): verifier app call + pool app call
 *
 * POST /api/withdraw
 * Body: { mode, proof, signals, poolAppId, nullifierHash, root, recipient, fee, inverses? }
 *
 * POST /api/deposit
 * Body: { mode, proof, signals, poolAppId, poolAppAddress, commitment, newRoot,
 *         amount, fee, signedPayment, inverses?, hpkeNote?, boxState }
 */

import algosdk from 'algosdk'

interface Env {
  RELAYER_MNEMONIC: string
  ALGOD_URL: string
  RELAY_KV: KVNamespace               // Persistent KV for replay protection + refund queue
  OPERATOR_API_KEY?: string           // Required for /api/process-refund (set via wrangler secret)
  VERIFIER_APP_ID?: string
  BUDGET_HELPER_APP_ID?: string
  DEPOSIT_VERIFIER_APP_ID?: string
  PLONK_VERIFIER_TEAL?: string        // base64-encoded compiled PLONK withdraw verifier
  PLONK_VERIFIER_ADDR?: string        // PLONK withdraw verifier LogicSig address
  PLONK_DEPOSIT_VERIFIER_TEAL?: string // base64-encoded compiled PLONK deposit verifier
  PLONK_DEPOSIT_VERIFIER_ADDR?: string // PLONK deposit verifier LogicSig address
  PLONK_VK_HEX?: string               // hex-encoded VK bytes for Note field
  PLONK_DEPOSIT_VK_HEX?: string       // hex-encoded deposit VK bytes
  ALLOWED_POOL_IDS?: string
  ALLOWED_ORIGINS?: string
}

const PLONK_MIN_RELAY_FEE = 10_000  // 0.01 ALGO (PLONK is cheap)
const GROTH16_MIN_RELAY_FEE = 220_000 // 0.22 ALGO (covers 213K verifier + 2K app + 1K pay + margin)
const MAX_RELAY_FEE = 1_000_000 // 1 ALGO — reject unreasonably high fees (prevents griefing)

// Anti-correlation: minimum deposits in a pool before the relayer will process withdrawals.
// Prevents "deposit 1, withdraw 1" deanonymization with trivial anonymity sets.
const MIN_POOL_DEPOSITS_FOR_RELAY = 3

interface WithdrawRequest {
  mode?: 'plonk' | 'groth16'
  proof: string        // hex-encoded proof bytes
  signals: string      // hex-encoded packed signal bytes (6×32 = 192 bytes)
  inverses?: string    // hex-encoded precomputed inverses (PLONK only)
  poolAppId: number
  nullifierHash: string
  root: string
  recipient: string
  relayerAddress: string
  fee: number
}

// ARC-4 method selectors
const WITHDRAW_SELECTOR = new Uint8Array([0x1b, 0xd9, 0xeb, 0x9c])  // withdraw(...)void
const DEPOSIT_SELECTOR = new Uint8Array([0xfc, 0x1b, 0xba, 0xae])   // deposit(byte[],byte[])void

interface DepositRequest {
  mode?: 'plonk' | 'groth16'
  proof: string          // hex-encoded proof bytes
  signals: string        // hex-encoded packed signal bytes (4×32 = 128 bytes)
  inverses?: string      // hex-encoded precomputed inverses (PLONK only)
  poolAppId: number
  // poolAppAddress computed server-side from poolAppId — never trust client
  commitment: string     // hex-encoded 32-byte commitment
  newRoot: string        // hex-encoded 32-byte new Merkle root
  amount: number         // deposit amount in microAlgos
  fee: number            // relayer fee in microAlgos
  signedPayment: string  // base64-encoded signed payment txn (user → relayer)
  hpkeNote?: string      // hex-encoded HPKE encrypted note
  boxState: {            // tree state for building box references
    rootHistoryIndex: number
    nextIndex: number
    evictedRoot?: string // hex-encoded 32-byte evicted root
  }
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) throw new Error('Hex string has odd length')
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error('Invalid hex characters')
  if (clean.length > 4096) throw new Error('Hex input too large')
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16)
  }
  return bytes
}

const VALID_DENOMINATION_TIERS = new Set([100_000, 500_000, 1_000_000])
const MAX_REQUEST_BYTES = 16_384 // 16KB — generous for any valid request

function uint64ToBytes(n: bigint | number): Uint8Array {
  const buf = new Uint8Array(8)
  let val = typeof n === 'number' ? BigInt(n) : n
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return buf
}

function abiEncodeBytes(data: Uint8Array): Uint8Array {
  if (data.length > 65535) throw new Error('Data too large for ABI encoding')
  const result = new Uint8Array(2 + data.length)
  result[0] = (data.length >> 8) & 0xff
  result[1] = data.length & 0xff
  result.set(data, 2)
  return result
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function buildDepositBoxRefs(
  appId: number, rootHistoryIndex: number, leafIndex: number,
  mimcRoot: Uint8Array, evictedRoot?: Uint8Array,
) {
  const TEXT_ENCODER = new TextEncoder()
  const rootSlot = rootHistoryIndex % 10000
  const rootBoxName = new Uint8Array(12)
  rootBoxName.set(TEXT_ENCODER.encode('root'), 0)
  rootBoxName.set(uint64ToBytes(BigInt(rootSlot)), 4)

  const commitBoxName = new Uint8Array(11)
  commitBoxName.set(TEXT_ENCODER.encode('cmt'), 0)
  commitBoxName.set(uint64ToBytes(BigInt(leafIndex)), 3)

  const krBoxName = new Uint8Array(2 + mimcRoot.length)
  krBoxName.set(TEXT_ENCODER.encode('kr'), 0)
  krBoxName.set(mimcRoot, 2)

  const refs = [
    { appIndex: appId, name: rootBoxName },
    { appIndex: appId, name: commitBoxName },
    { appIndex: appId, name: krBoxName },
  ]

  if (evictedRoot) {
    const evictKrName = new Uint8Array(2 + evictedRoot.length)
    evictKrName.set(TEXT_ENCODER.encode('kr'), 0)
    evictKrName.set(evictedRoot, 2)
    refs.push({ appIndex: appId, name: evictKrName })
  }

  return refs
}

/** Fetch pool global state (currentRoot, nextIndex, rootHistoryIndex, denomination) */
async function fetchPoolState(algod: algosdk.Algodv2, appId: number) {
  const appInfo = await algod.getApplicationByID(appId).do() as any
  const gs = appInfo.params?.['global-state'] || appInfo['global-state'] || []
  let currentRoot: Uint8Array | undefined
  let nextIndex: number | undefined
  let rootHistoryIndex: number | undefined
  let denomination: number | undefined
  for (const kv of gs) {
    const key = typeof kv.key === 'string' ? atob(kv.key) : ''
    if (key === 'root') currentRoot = base64ToBytes(kv.value.bytes)
    else if (key === 'next_idx') nextIndex = Number(kv.value.uint)
    else if (key === 'rhi') rootHistoryIndex = Number(kv.value.uint)
    else if (key === 'denom') denomination = Number(kv.value.uint)
  }
  return { currentRoot, nextIndex, rootHistoryIndex, denomination }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

function addressToSignalBytes(addr: string): Uint8Array {
  const pubKey = algosdk.decodeAddress(addr).publicKey
  let n = 0n
  for (let i = 0; i < pubKey.length; i++) {
    n = (n << 8n) | BigInt(pubKey[i])
  }
  n = n % BN254_R
  const buf = new Uint8Array(32)
  let val = n
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(val & 0xffn)
    val >>= 8n
  }
  return buf
}

function corsHeaders(env: Env, request?: Request): HeadersInit {
  let origin = '*'
  if (env.ALLOWED_ORIGINS) {
    const allowed = env.ALLOWED_ORIGINS.split(',').map(s => s.trim())
    const reqOrigin = request?.headers.get('Origin') ?? ''
    origin = allowed.includes(reqOrigin) ? reqOrigin : allowed[0]
  }
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }
}

function jsonResponse(data: object, status: number, env: Env, request?: Request): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) },
  })
}

// Per-isolate rate limiting (best-effort — resets on isolate recycle)
// IMPORTANT: Also configure Cloudflare WAF Rate Limiting rules via dashboard:
//   Security → WAF → Rate limiting rules
//   Path: /api/*, Method: POST, Rate: 5 requests/minute per IP
const rateLimitMap = new Map<string, { count: number; resetAt: number }>()
const RATE_LIMIT_WINDOW_MS = 60_000 // 1 minute
const RATE_LIMIT_MAX = 5 // 5 requests per window per IP

// Payment replay protection uses KV (persistent across isolate recycles)
// KV key: "pay:<txnId>" → "1", TTL 24 hours (txns expire after ~1000 rounds anyway)
const KV_PAY_PREFIX = 'pay:'
const KV_PAY_TTL_SECONDS = 86_400 // 24 hours

// Refund queue uses KV: "refund:<senderAddr>:<payTxId>" → JSON { amount, commitment, timestamp }
const KV_REFUND_PREFIX = 'refund:'

/** Hash IP so raw addresses are never stored in memory */
async function hashIp(ip: string): Promise<string> {
  const buf = new TextEncoder().encode(ip)
  const hash = await crypto.subtle.digest('SHA-256', buf)
  return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('')
}

function checkRateLimit(ipHash: string): boolean {
  const now = Date.now()
  const entry = rateLimitMap.get(ipHash)
  if (!entry || now > entry.resetAt) {
    rateLimitMap.set(ipHash, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS })
    return true
  }
  entry.count++
  return entry.count <= RATE_LIMIT_MAX
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) })
    }

    const url = new URL(request.url)

    if (url.pathname === '/api/withdraw' && request.method === 'POST') {
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown')
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded. Max 5 requests per minute.' }, 429, env, request)
      }
      return handleWithdraw(request, env)
    }

    if (url.pathname === '/api/deposit' && request.method === 'POST') {
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown')
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded. Max 5 requests per minute.' }, 429, env, request)
      }
      return handleDeposit(request, env)
    }

    if (url.pathname === '/api/health') {
      return jsonResponse({ status: 'ok', mode: env.PLONK_VERIFIER_TEAL ? 'plonk' : 'groth16' }, 200, env, request)
    }

    // Refund check: GET /api/refunds?address=ALGO_ADDRESS (rate-limited)
    if (url.pathname === '/api/refunds' && request.method === 'GET') {
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown')
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded.' }, 429, env, request)
      }
      return handleRefundCheck(url, env, request)
    }

    // Process refund: POST /api/process-refund (operator only — requires OPERATOR_API_KEY)
    if (url.pathname === '/api/process-refund' && request.method === 'POST') {
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown')
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded.' }, 429, env, request)
      }
      return handleProcessRefund(request, env)
    }

    return jsonResponse({ error: 'Not found' }, 404, env, request)
  },
}

async function handleWithdraw(request: Request, env: Env): Promise<Response> {
  const json = (data: object, status = 200) => jsonResponse(data, status, env, request)

  if (!env.RELAYER_MNEMONIC) {
    return json({ error: 'Relayer not configured' }, 500)
  }

  const contentLength = parseInt(request.headers.get('Content-Length') ?? '0', 10)
  if (contentLength > MAX_REQUEST_BYTES) {
    return json({ error: 'Request too large' }, 413)
  }

  let bodyText: string
  try {
    bodyText = await request.text()
  } catch {
    return json({ error: 'Failed to read request body' }, 400)
  }
  if (bodyText.length > MAX_REQUEST_BYTES) {
    return json({ error: 'Request too large' }, 413)
  }

  let body: WithdrawRequest
  try {
    body = JSON.parse(bodyText) as WithdrawRequest
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  // Default to PLONK if verifier TEAL is configured, otherwise Groth16
  const mode = body.mode ?? (env.PLONK_VERIFIER_TEAL ? 'plonk' : 'groth16')
  if (mode !== 'plonk' && mode !== 'groth16') {
    return json({ error: 'Invalid mode — must be "plonk" or "groth16"' }, 400)
  }

  // Validate required fields
  if (!body.proof || !body.signals || !body.poolAppId || !body.nullifierHash || !body.root || !body.recipient) {
    return json({ error: 'Missing required fields: proof, signals, poolAppId, nullifierHash, root, recipient' }, 400)
  }

  if (mode === 'plonk' && !body.inverses) {
    return json({ error: 'Missing required field: inverses (required for PLONK mode)' }, 400)
  }

  // Runtime type validation
  if (typeof body.poolAppId !== 'number' || !Number.isInteger(body.poolAppId) || body.poolAppId <= 0) {
    return json({ error: 'poolAppId must be a positive integer' }, 400)
  }
  if (body.fee !== undefined && (!Number.isInteger(body.fee) || body.fee < 0)) {
    return json({ error: 'fee must be a non-negative integer' }, 400)
  }

  // Validate pool allowlist
  if (env.ALLOWED_POOL_IDS) {
    const allowed = new Set(env.ALLOWED_POOL_IDS.split(',').map(s => parseInt(s.trim(), 10)))
    if (!allowed.has(body.poolAppId)) {
      return json({ error: 'Pool app ID not in allowlist' }, 403)
    }
  }

  const relayFee = body.fee ?? 0
  const minFee = mode === 'plonk' ? PLONK_MIN_RELAY_FEE : GROTH16_MIN_RELAY_FEE
  if (relayFee < minFee) {
    return json({ error: `Relay fee must be at least ${minFee} microAlgos (${minFee / 1_000_000} ALGO)` }, 400)
  }
  if (relayFee > MAX_RELAY_FEE) {
    return json({ error: `Relay fee exceeds maximum of ${MAX_RELAY_FEE} microAlgos` }, 400)
  }

  // Parse and validate hex inputs
  const proofBytes = hexToBytes(body.proof)
  const signalsBytes = hexToBytes(body.signals)
  const nullifierHashBytes = hexToBytes(body.nullifierHash)
  const rootBytes = hexToBytes(body.root)

  if (mode === 'groth16') {
    if (proofBytes.length !== 256) return json({ error: 'proof must be 256 bytes (Groth16)' }, 400)
  } else {
    if (proofBytes.length !== 768) return json({ error: 'proof must be 768 bytes (PLONK)' }, 400)
  }
  if (signalsBytes.length !== 192) return json({ error: 'signals must be 192 bytes' }, 400)
  if (nullifierHashBytes.length !== 32) return json({ error: 'nullifierHash must be 32 bytes' }, 400)
  if (rootBytes.length !== 32) return json({ error: 'root must be 32 bytes' }, 400)

  if (!algosdk.isValidAddress(body.recipient)) {
    return json({ error: 'Invalid recipient address' }, 400)
  }

  // Verify signals encode the claimed parameters
  const recipientSignal = addressToSignalBytes(body.recipient)
  if (!bytesEqual(signalsBytes.slice(64, 96), recipientSignal)) {
    return json({ error: 'Signals recipient does not match request recipient' }, 400)
  }
  if (!bytesEqual(signalsBytes.slice(0, 32), rootBytes)) {
    return json({ error: 'Signals root does not match request root' }, 400)
  }
  if (!bytesEqual(signalsBytes.slice(32, 64), nullifierHashBytes)) {
    return json({ error: 'Signals nullifierHash does not match request nullifierHash' }, 400)
  }
  const signalFeeBytes = signalsBytes.slice(128, 160)
  const expectedFeeBytes = new Uint8Array(32)
  expectedFeeBytes.set(uint64ToBytes(BigInt(relayFee)), 24)
  if (!bytesEqual(signalFeeBytes, expectedFeeBytes)) {
    return json({ error: 'Signals fee does not match request fee' }, 400)
  }

  // M-1: Validate denomination signal (bytes 160-192) against valid tiers
  const signalAmountBytes = signalsBytes.slice(160, 192)
  let signalAmountValid = false
  for (const tier of VALID_DENOMINATION_TIERS) {
    const tierBytes = new Uint8Array(32)
    tierBytes.set(uint64ToBytes(BigInt(tier)), 24)
    if (bytesEqual(signalAmountBytes, tierBytes)) { signalAmountValid = true; break }
  }
  if (!signalAmountValid) {
    return json({ error: 'Signals denomination does not match any valid tier' }, 400)
  }

  try {
    const algod = new algosdk.Algodv2('', env.ALGOD_URL)
    const relayer = algosdk.mnemonicToSecretKey(env.RELAYER_MNEMONIC)

    // Verify relayer signal
    const relayerAddrStr = relayer.addr.toString()
    const relayerSignal = addressToSignalBytes(relayerAddrStr)
    if (!bytesEqual(signalsBytes.slice(96, 128), relayerSignal)) {
      return json({ error: 'Signals relayer does not match this relayer address' }, 400)
    }

    // Pre-check: verify the claimed root exists on-chain (kr box check)
    // Prevents wasting txn fees on proofs with invalid/expired roots
    const krBoxName = new Uint8Array(2 + 32)
    krBoxName.set(new TextEncoder().encode('kr'), 0)
    krBoxName.set(rootBytes, 2)
    try {
      await algod.getApplicationBoxByName(body.poolAppId, krBoxName).do()
    } catch {
      return json({ error: 'Root is not a known root on-chain' }, 400)
    }

    // Anti-correlation: check pool has enough deposits for meaningful anonymity
    try {
      const appInfo = await algod.getApplicationByID(body.poolAppId).do()
      const globalState = (appInfo as any).params?.globalState || (appInfo as any).params?.['global-state'] || []
      for (const kv of globalState) {
        const key = typeof kv.key === 'string' ? atob(kv.key) : ''
        if (key === 'next_idx') {
          const nextIdx = Number(kv.value?.uint ?? kv.value?.ui ?? 0)
          if (nextIdx < MIN_POOL_DEPOSITS_FOR_RELAY) {
            return json({ error: `Pool has only ${nextIdx} deposit(s). Need at least ${MIN_POOL_DEPOSITS_FOR_RELAY} for meaningful anonymity.` }, 400)
          }
          break
        }
      }
    } catch (acErr) {
      console.warn('Anti-correlation check failed (proceeding anyway):', (acErr as Error)?.message)
    }

    // Nullifier spend check removed — let on-chain validation reject spent nullifiers.
    // A pre-check here would leak which notes have been withdrawn (409 vs other errors).
    const nullBoxName = new Uint8Array(4 + 32)
    nullBoxName.set(new TextEncoder().encode('null'), 0)
    nullBoxName.set(nullifierHashBytes, 4)

    const params = await algod.getTransactionParams().do()
    const recipientPubKey = algosdk.decodeAddress(body.recipient).publicKey
    const relayerPubKey = algosdk.decodeAddress(relayerAddrStr).publicKey
    const recipientSignalBytes = addressToSignalBytes(body.recipient)
    const relayerSignalBytes = addressToSignalBytes(relayerAddrStr)

    const rootBoxName = new Uint8Array(2 + 32)
    rootBoxName.set(new TextEncoder().encode('kr'), 0)
    rootBoxName.set(rootBytes, 2)

    const withdrawBoxes = [
      { appIndex: body.poolAppId, name: nullBoxName },
      { appIndex: body.poolAppId, name: rootBoxName },
    ]

    const withdrawAppCall = algosdk.makeApplicationCallTxnFromObject({
      sender: relayerAddrStr,
      appIndex: body.poolAppId,
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        WITHDRAW_SELECTOR,
        abiEncodeBytes(nullifierHashBytes),
        recipientPubKey,
        relayerPubKey,
        uint64ToBytes(BigInt(relayFee)),
        abiEncodeBytes(rootBytes),
        abiEncodeBytes(recipientSignalBytes),
        abiEncodeBytes(relayerSignalBytes),
      ],
      accounts: [body.recipient],
      boxes: withdrawBoxes,
      suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
    })

    let signedTxns: Uint8Array[]
    let txId: string

    if (mode === 'plonk') {
      // ── PLONK LogicSig mode ──
      if (!env.PLONK_VERIFIER_TEAL || !env.PLONK_VERIFIER_ADDR) {
        return json({ error: 'PLONK verifier not configured on relayer' }, 500)
      }

      const inversesBytes = hexToBytes(body.inverses!)
      const programBytes = new Uint8Array(
        atob(env.PLONK_VERIFIER_TEAL).split('').map(c => c.charCodeAt(0))
      )
      const verifierAddr = env.PLONK_VERIFIER_ADDR

      // Decode VK bytes for Note field
      const vkBytes = env.PLONK_VK_HEX ? hexToBytes(env.PLONK_VK_HEX) : new Uint8Array(0)

      // Build 4 LogicSig payment txns
      const makeLsigPay = (note?: Uint8Array) =>
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: verifierAddr,
          receiver: verifierAddr,
          amount: 0,
          suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
          note,
        })

      const lsigTxns = [
        makeLsigPay(),              // [0] verifier
        makeLsigPay(vkBytes),       // [1] VK in Note
        makeLsigPay(),              // [2] budget padding
        makeLsigPay(signalsBytes),  // [3] signals in Note
      ]

      const group = [...lsigTxns, withdrawAppCall]
      algosdk.assignGroupID(group)

      // Sign LogicSig txns with proof + inverses as args
      const lsig = new algosdk.LogicSigAccount(programBytes, [proofBytes, inversesBytes])
      const signedLsig = lsigTxns.map(txn => algosdk.signLogicSigTransaction(txn, lsig).blob)

      // Sign withdraw app call with relayer key
      const signedWithdraw = withdrawAppCall.signTxn(relayer.sk)

      signedTxns = [...signedLsig, signedWithdraw]
      txId = withdrawAppCall.txID()
    } else {
      // ── Groth16 app-based mode ──
      const verifierAppId = env.VERIFIER_APP_ID ? parseInt(env.VERIFIER_APP_ID) : 0
      const budgetHelperAppId = env.BUDGET_HELPER_APP_ID ? parseInt(env.BUDGET_HELPER_APP_ID) : 0

      if (!verifierAppId) {
        return json({ error: 'Groth16 verifier app not configured' }, 500)
      }

      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: relayerAddrStr,
        appIndex: verifierAppId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: budgetHelperAppId ? [budgetHelperAppId] : [],
        suggestedParams: { ...params, fee: BigInt(213_000), flatFee: true },
      })

      const group = [verifierAppCall, withdrawAppCall]
      algosdk.assignGroupID(group)

      signedTxns = [
        verifierAppCall.signTxn(relayer.sk),
        withdrawAppCall.signTxn(relayer.sk),
      ]
      txId = withdrawAppCall.txID()
    }

    const resp = await algod.sendRawTransaction(signedTxns).do()
    const confirmedTxId = (resp as any).txid ?? (resp as any).txId ?? txId

    await algosdk.waitForConfirmation(algod, confirmedTxId, 4)

    return json({ txId: confirmedTxId, status: 'confirmed', mode })
  } catch (err: any) {
    console.error('Relayer withdraw error:', (err?.message || 'unknown').slice(0, 80))
    // Return a generic error — do not leak on-chain error details (e.g. nullifier state)
    return json({ error: 'Transaction failed' }, 500)
  }
}

async function handleDeposit(request: Request, env: Env): Promise<Response> {
  const json = (data: object, status = 200) => jsonResponse(data, status, env, request)

  if (!env.RELAYER_MNEMONIC) {
    return json({ error: 'Relayer not configured' }, 500)
  }

  if (!env.RELAY_KV) {
    return json({ error: 'KV not configured — replay protection unavailable' }, 500)
  }

  const contentLength = parseInt(request.headers.get('Content-Length') ?? '0', 10)
  if (contentLength > MAX_REQUEST_BYTES) {
    return json({ error: 'Request too large' }, 413)
  }

  let bodyText: string
  try {
    bodyText = await request.text()
  } catch {
    return json({ error: 'Failed to read request body' }, 400)
  }
  if (bodyText.length > MAX_REQUEST_BYTES) {
    return json({ error: 'Request too large' }, 413)
  }

  let body: DepositRequest
  try {
    body = JSON.parse(bodyText) as DepositRequest
  } catch {
    return json({ error: 'Invalid JSON body' }, 400)
  }

  const mode = body.mode ?? (env.PLONK_DEPOSIT_VERIFIER_TEAL ? 'plonk' : 'groth16')
  if (mode !== 'plonk' && mode !== 'groth16') {
    return json({ error: 'Invalid mode — must be "plonk" or "groth16"' }, 400)
  }

  if (!body.proof || !body.signals || !body.poolAppId ||
      !body.commitment || !body.newRoot || !body.amount || !body.signedPayment || !body.boxState) {
    return json({ error: 'Missing required fields' }, 400)
  }

  if (mode === 'plonk' && !body.inverses) {
    return json({ error: 'Missing required field: inverses (required for PLONK mode)' }, 400)
  }

  // Runtime type validation — JSON.parse provides no type safety
  if (typeof body.poolAppId !== 'number' || !Number.isInteger(body.poolAppId) || body.poolAppId <= 0) {
    return json({ error: 'poolAppId must be a positive integer' }, 400)
  }
  if (typeof body.amount !== 'number' || !Number.isInteger(body.amount) || body.amount <= 0) {
    return json({ error: 'amount must be a positive integer' }, 400)
  }
  if (body.fee !== undefined && (!Number.isInteger(body.fee) || body.fee < 0)) {
    return json({ error: 'fee must be a non-negative integer' }, 400)
  }
  if (typeof body.boxState.rootHistoryIndex !== 'number' || !Number.isInteger(body.boxState.rootHistoryIndex) || body.boxState.rootHistoryIndex < 0) {
    return json({ error: 'boxState.rootHistoryIndex must be a non-negative integer' }, 400)
  }
  if (typeof body.boxState.nextIndex !== 'number' || !Number.isInteger(body.boxState.nextIndex) || body.boxState.nextIndex < 0) {
    return json({ error: 'boxState.nextIndex must be a non-negative integer' }, 400)
  }

  // Validate denomination tier
  if (!VALID_DENOMINATION_TIERS.has(body.amount)) {
    return json({ error: 'Invalid deposit denomination tier' }, 400)
  }

  // Validate pool allowlist
  if (env.ALLOWED_POOL_IDS) {
    const allowed = new Set(env.ALLOWED_POOL_IDS.split(',').map(s => parseInt(s.trim(), 10)))
    if (!allowed.has(body.poolAppId)) {
      return json({ error: 'Pool app ID not in allowlist' }, 403)
    }
  }

  const relayFee = body.fee ?? 0
  const minFee = mode === 'plonk' ? PLONK_MIN_RELAY_FEE : GROTH16_MIN_RELAY_FEE
  if (relayFee < minFee) {
    return json({ error: `Relay fee must be at least ${minFee} microAlgos` }, 400)
  }
  if (relayFee > MAX_RELAY_FEE) {
    return json({ error: `Relay fee exceeds maximum of ${MAX_RELAY_FEE} microAlgos` }, 400)
  }

  const proofBytes = hexToBytes(body.proof)
  const signalsBytes = hexToBytes(body.signals)
  const commitmentBytes = hexToBytes(body.commitment)
  const newRootBytes = hexToBytes(body.newRoot)

  if (commitmentBytes.length !== 32) return json({ error: 'commitment must be 32 bytes' }, 400)
  if (newRootBytes.length !== 32) return json({ error: 'newRoot must be 32 bytes' }, 400)
  if (signalsBytes.length !== 128) return json({ error: 'signals must be 128 bytes (4×32)' }, 400)

  // Validate proof size
  if (mode === 'groth16') {
    if (proofBytes.length !== 256) return json({ error: 'proof must be 256 bytes (Groth16)' }, 400)
  } else {
    if (proofBytes.length !== 768) return json({ error: 'proof must be 768 bytes (PLONK)' }, 400)
  }

  // Validate signals match claimed parameters
  if (!bytesEqual(signalsBytes.slice(64, 96), commitmentBytes)) {
    return json({ error: 'Signals commitment does not match request commitment' }, 400)
  }
  if (!bytesEqual(signalsBytes.slice(32, 64), newRootBytes)) {
    return json({ error: 'Signals newRoot does not match request newRoot' }, 400)
  }
  // Validate leafIndex signal matches boxState.nextIndex
  const expectedLeafBytes = new Uint8Array(32)
  expectedLeafBytes.set(uint64ToBytes(BigInt(body.boxState.nextIndex)), 24)
  if (!bytesEqual(signalsBytes.slice(96, 128), expectedLeafBytes)) {
    return json({ error: 'Signals leafIndex does not match boxState.nextIndex' }, 400)
  }

  // Compute pool app address server-side — never trust client-supplied address
  const poolAppAddress = algosdk.getApplicationAddress(body.poolAppId).toString()

  let payTxId: string | undefined
  try {
    const algod = new algosdk.Algodv2('', env.ALGOD_URL)
    const relayer = algosdk.mnemonicToSecretKey(env.RELAYER_MNEMONIC)
    const relayerAddrStr = relayer.addr.toString()

    // Verify user's pre-signed payment
    const signedPaymentBytes = base64ToBytes(body.signedPayment)
    const decodedPayment = algosdk.decodeSignedTransaction(signedPaymentBytes)
    const paymentTxn = decodedPayment.txn

    // Verify it's a payment transaction
    if (!paymentTxn.payment) {
      return json({ error: 'signedPayment must be a payment transaction' }, 400)
    }

    // Verify payment goes to the relayer
    if (paymentTxn.payment.receiver.toString() !== relayerAddrStr) {
      return json({ error: 'Payment must be sent to relayer address' }, 400)
    }

    // Verify payment covers deposit amount + relayer fee (use BigInt to avoid Number precision loss)
    const expectedAmount = BigInt(body.amount) + BigInt(relayFee)
    if (BigInt(paymentTxn.payment.amount) < expectedAmount) {
      return json({ error: `Payment must be at least ${expectedAmount} microAlgos (deposit + fee)` }, 400)
    }

    // Reject payments with dangerous fields
    if (paymentTxn.payment.closeRemainderTo) {
      return json({ error: 'Payment must not include closeRemainderTo' }, 400)
    }
    if (paymentTxn.rekeyTo) {
      return json({ error: 'Payment must not include rekeyTo' }, 400)
    }

    // C-2: Payment note must contain the commitment hash — binds payment to this specific deposit
    const paymentNote = paymentTxn.note ? new Uint8Array(paymentTxn.note) : undefined
    if (!paymentNote || paymentNote.length < 32 || !bytesEqual(paymentNote.slice(0, 32), commitmentBytes)) {
      return json({ error: 'Payment note must start with the 32-byte commitment hash' }, 400)
    }

    // C-2: Reject replayed payment txn IDs (KV-persistent across isolate recycles)
    const payTxnId = paymentTxn.txID()
    const kvPayKey = KV_PAY_PREFIX + payTxnId
    const existing = await env.RELAY_KV.get(kvPayKey)
    if (existing) {
      return json({ error: 'This payment transaction has already been used' }, 400)
    }
    // Claim immediately to close TOCTOU window (before submitting payment)
    await env.RELAY_KV.put(kvPayKey, 'pending', { expirationTtl: KV_PAY_TTL_SECONDS })

    const params = await algod.getTransactionParams().do()

    // Helper to release KV claim on validation failure (so user can retry)
    const rejectAndRelease = async (msg: string, status = 400) => {
      await env.RELAY_KV.delete(kvPayKey)
      return json({ error: msg }, status)
    }

    // Verify payment has a reasonable validity window (at least 20 rounds ahead)
    if (paymentTxn.lastValid < params.firstValid + 20n) {
      return rejectAndRelease('Payment validity window too short — must be valid for at least 20 rounds')
    }

    // H-2: Verify client-supplied boxState against on-chain state
    const onChainState = await fetchPoolState(algod, body.poolAppId)
    if (onChainState.nextIndex !== undefined && onChainState.nextIndex !== body.boxState.nextIndex) {
      return rejectAndRelease('boxState.nextIndex does not match on-chain state')
    }
    if (onChainState.currentRoot && !bytesEqual(signalsBytes.slice(0, 32), onChainState.currentRoot)) {
      return rejectAndRelease('Signals currentRoot does not match on-chain state')
    }
    if (onChainState.denomination !== undefined && onChainState.denomination !== body.amount) {
      return rejectAndRelease('Deposit amount does not match pool denomination')
    }
    if (onChainState.rootHistoryIndex !== undefined && onChainState.rootHistoryIndex !== body.boxState.rootHistoryIndex) {
      return rejectAndRelease('boxState.rootHistoryIndex does not match on-chain state')
    }

    // Validate evictedRoot and hpkeNote BEFORE payment submission (avoid unnecessary refund queue)
    const evictedRoot = body.boxState.evictedRoot ? hexToBytes(body.boxState.evictedRoot) : undefined
    if (evictedRoot && evictedRoot.length !== 32) {
      return rejectAndRelease('boxState.evictedRoot must be 32 bytes')
    }
    const hpkeNote = body.hpkeNote ? hexToBytes(body.hpkeNote) : undefined
    if (hpkeNote && hpkeNote.length > 1024) {
      return rejectAndRelease('hpkeNote must be at most 1024 bytes')
    }

    // Batch window pre-check — reject deposits outside the ~240s window
    // Contract enforces: windowOffset <= 120 || windowOffset >= 780 (per 900s period)
    // Use 30s buffer for clock skew between relayer and on-chain timestamp
    const approxTimestamp = Math.floor(Date.now() / 1000)
    const windowOffset = approxTimestamp % 900
    if (windowOffset > 150 && windowOffset < 750) {
      const secsUntilNext = 900 - windowOffset
      return rejectAndRelease(`Outside batch window — next window opens in ~${Math.ceil(secsUntilNext / 60)} minutes`)
    }

    // Submit user's payment FIRST — if it fails, don't front the deposit
    // This prevents the race where user drains their account after we front funds.
    const payResp = await algod.sendRawTransaction(signedPaymentBytes).do()
    payTxId = (payResp as any).txid ?? (payResp as any).txId ?? ''
    await algosdk.waitForConfirmation(algod, payTxId!, 4)

    // Update claim to confirmed — DO NOT use rejectAndRelease after this point
    // (it deletes kvPayKey, which would break replay protection for confirmed payments)
    await env.RELAY_KV.put(kvPayKey, 'confirmed', { expirationTtl: KV_PAY_TTL_SECONDS })

    const boxes = buildDepositBoxRefs(
      body.poolAppId, body.boxState.rootHistoryIndex,
      body.boxState.nextIndex, newRootBytes, evictedRoot,
    )

    // Payment from relayer → pool (deposit amount, relayer fronts this)
    const poolPayTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: relayerAddrStr,
      receiver: poolAppAddress,
      amount: body.amount,
      suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
    })

    // Deposit app call
    const depositAppCall = algosdk.makeApplicationCallTxnFromObject({
      sender: relayerAddrStr,
      appIndex: body.poolAppId,
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        DEPOSIT_SELECTOR,
        abiEncodeBytes(commitmentBytes),
        abiEncodeBytes(newRootBytes),
      ],
      boxes,
      note: hpkeNote,
      suggestedParams: { ...params, fee: BigInt(2000), flatFee: true },
    })

    let signedTxns: Uint8Array[]
    let txId: string

    if (mode === 'plonk') {
      const tealB64 = env.PLONK_DEPOSIT_VERIFIER_TEAL
      const verifierAddr = env.PLONK_DEPOSIT_VERIFIER_ADDR
      if (!tealB64 || !verifierAddr) {
        return json({ error: 'PLONK deposit verifier not configured on relayer' }, 500)
      }

      const inversesBytes = hexToBytes(body.inverses!)
      const programBytes = new Uint8Array(
        atob(tealB64).split('').map(c => c.charCodeAt(0))
      )

      const vkBytes = env.PLONK_DEPOSIT_VK_HEX ? hexToBytes(env.PLONK_DEPOSIT_VK_HEX) : new Uint8Array(0)

      const makeLsigPay = (note?: Uint8Array) =>
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: verifierAddr,
          receiver: verifierAddr,
          amount: 0,
          suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
          note,
        })

      const lsigTxns = [
        makeLsigPay(),
        makeLsigPay(vkBytes),
        makeLsigPay(),
        makeLsigPay(signalsBytes),
      ]

      const group = [...lsigTxns, poolPayTxn, depositAppCall]
      algosdk.assignGroupID(group)

      const lsig = new algosdk.LogicSigAccount(programBytes, [proofBytes, inversesBytes])
      const signedLsig = lsigTxns.map(txn => algosdk.signLogicSigTransaction(txn, lsig).blob)

      signedTxns = [
        ...signedLsig,
        poolPayTxn.signTxn(relayer.sk),
        depositAppCall.signTxn(relayer.sk),
      ]
      txId = depositAppCall.txID()
    } else {
      // Groth16 app-based
      const verifierAppId = env.DEPOSIT_VERIFIER_APP_ID ? parseInt(env.DEPOSIT_VERIFIER_APP_ID) : 0
      const budgetHelperAppId = env.BUDGET_HELPER_APP_ID ? parseInt(env.BUDGET_HELPER_APP_ID) : 0

      if (!verifierAppId) {
        return json({ error: 'Groth16 deposit verifier app not configured' }, 500)
      }

      const verifierAppCall = algosdk.makeApplicationCallTxnFromObject({
        sender: relayerAddrStr,
        appIndex: verifierAppId,
        onComplete: algosdk.OnApplicationComplete.NoOpOC,
        appArgs: [proofBytes, signalsBytes],
        foreignApps: budgetHelperAppId ? [budgetHelperAppId] : [],
        suggestedParams: { ...params, fee: BigInt(213_000), flatFee: true },
      })

      const group = [verifierAppCall, poolPayTxn, depositAppCall]
      algosdk.assignGroupID(group)

      signedTxns = [
        verifierAppCall.signTxn(relayer.sk),
        poolPayTxn.signTxn(relayer.sk),
        depositAppCall.signTxn(relayer.sk),
      ]
      txId = depositAppCall.txID()
    }

    const resp = await algod.sendRawTransaction(signedTxns).do()
    const confirmedTxId = (resp as any).txid ?? (resp as any).txId ?? txId

    await algosdk.waitForConfirmation(algod, confirmedTxId, 4)

    return json({ txId: confirmedTxId, paymentTxId: payTxId, status: 'confirmed', mode })
  } catch (err: any) {
    // User's payment was already confirmed (payment-first flow).
    // Write a refund record to KV so the operator can process refunds.
    let senderAddr = 'unknown'
    try {
      senderAddr = algosdk.decodeSignedTransaction(base64ToBytes(body.signedPayment)).txn.sender.toString()
    } catch { /* best effort */ }

    // Log only non-identifying data — don't log commitment+sender together (deanonymization risk)
    console.error('Relayer deposit FAILED after payment confirmed:', {
      payTxId, error: err?.message || 'unknown',
    })

    // Queue refund in KV (persistent — survives isolate recycle)
    if (env.RELAY_KV && payTxId) {
      const refundKey = `${KV_REFUND_PREFIX}${senderAddr}:${payTxId}`
      await env.RELAY_KV.put(refundKey, JSON.stringify({
        senderAddr,
        amount: body.amount,
        fee: relayFee,
        payTxId,
        status: 'pending',
        timestamp: Date.now(),
      }), { expirationTtl: 30 * 86_400 }) // Keep for 30 days
    }

    return json({
      error: 'Deposit failed after payment confirmed — refund queued',
      paymentTxId: payTxId,
      refundStatus: 'queued',
    }, 500)
  }
}

/** Check pending refunds for an address */
async function handleRefundCheck(url: URL, env: Env, request: Request): Promise<Response> {
  const json = (data: object, status = 200) => jsonResponse(data, status, env, request)

  const address = url.searchParams.get('address')
  if (!address || !algosdk.isValidAddress(address)) {
    return json({ error: 'Valid Algorand address required' }, 400)
  }

  if (!env.RELAY_KV) {
    return json({ error: 'KV not configured' }, 500)
  }

  // List refund keys for this address
  const prefix = `${KV_REFUND_PREFIX}${address}:`
  const list = await env.RELAY_KV.list({ prefix, limit: 50 })

  const refunds: object[] = []
  for (const key of list.keys) {
    const val = await env.RELAY_KV.get(key.name)
    if (val) {
      try {
        const record = JSON.parse(val)
        // Only expose non-identifying fields (don't leak commitment)
        refunds.push({
          amount: record.amount,
          fee: record.fee,
          payTxId: record.payTxId,
          timestamp: record.timestamp,
        })
      } catch { /* skip malformed */ }
    }
  }

  return json({ address, refunds })
}

/** Process a refund — sends funds back to the original depositor.
 *  Requires operator authorization (same mnemonic as relayer). */
async function handleProcessRefund(request: Request, env: Env): Promise<Response> {
  const json = (data: object, status = 200) => jsonResponse(data, status, env, request)

  // Authenticate operator (constant-time comparison to prevent timing attacks)
  if (!env.OPERATOR_API_KEY) {
    return json({ error: 'Operator API key not configured' }, 500)
  }
  const authHeader = request.headers.get('Authorization') ?? ''
  const expected = new TextEncoder().encode(`Bearer ${env.OPERATOR_API_KEY}`)
  const actual = new TextEncoder().encode(authHeader)
  if (expected.byteLength !== actual.byteLength) {
    return json({ error: 'Unauthorized' }, 401)
  }
  const match = await crypto.subtle.timingSafeEqual(expected, actual)
  if (!match) {
    return json({ error: 'Unauthorized' }, 401)
  }

  if (!env.RELAYER_MNEMONIC || !env.RELAY_KV) {
    return json({ error: 'Relayer or KV not configured' }, 500)
  }

  const contentLength = parseInt(request.headers.get('Content-Length') ?? '0', 10)
  if (contentLength > MAX_REQUEST_BYTES) {
    return json({ error: 'Request too large' }, 413)
  }

  let body: { senderAddr: string; payTxId: string }
  try {
    body = await request.json() as typeof body
  } catch {
    return json({ error: 'Invalid JSON' }, 400)
  }

  if (!body.senderAddr || !body.payTxId) {
    return json({ error: 'senderAddr and payTxId required' }, 400)
  }

  // Validate payTxId format (Algorand txids are 52-char base32)
  if (typeof body.payTxId !== 'string' || !/^[A-Z2-7]{52}$/.test(body.payTxId)) {
    return json({ error: 'Invalid payTxId format' }, 400)
  }

  // Validate address before using it in KV key
  if (!algosdk.isValidAddress(body.senderAddr)) {
    return json({ error: 'Invalid senderAddr' }, 400)
  }

  const refundKey = `${KV_REFUND_PREFIX}${body.senderAddr}:${body.payTxId}`
  const refundVal = await env.RELAY_KV.get(refundKey)
  if (!refundVal) {
    return json({ error: 'No pending refund found for this address/payTxId' }, 404)
  }

  const refundData = JSON.parse(refundVal) as { senderAddr: string; amount: number; fee: number; payTxId: string; status?: string }

  if (refundData.status === 'processing') {
    return json({ error: 'Refund already being processed' }, 409)
  }

  if (!algosdk.isValidAddress(refundData.senderAddr)) {
    return json({ error: 'Invalid sender address in refund record' }, 400)
  }

  // Validate numeric fields from KV (could be corrupted/tampered)
  if (typeof refundData.amount !== 'number' || !Number.isFinite(refundData.amount) || refundData.amount <= 0) {
    return json({ error: 'Invalid refund amount in record' }, 400)
  }
  if (!VALID_DENOMINATION_TIERS.has(refundData.amount)) {
    return json({ error: 'Refund amount is not a valid denomination tier' }, 400)
  }
  if (refundData.fee !== undefined && (typeof refundData.fee !== 'number' || !Number.isFinite(refundData.fee) || refundData.fee < 0)) {
    return json({ error: 'Invalid fee in refund record' }, 400)
  }
  if ((refundData.fee || 0) > MAX_RELAY_FEE) {
    return json({ error: 'Refund fee exceeds maximum' }, 400)
  }

  // Claim immediately to prevent double-refund race condition
  await env.RELAY_KV.put(refundKey, JSON.stringify({ ...refundData, status: 'processing' }), { expirationTtl: 30 * 86_400 })

  try {
    const algod = new algosdk.Algodv2('', env.ALGOD_URL)
    const relayer = algosdk.mnemonicToSecretKey(env.RELAYER_MNEMONIC)
    const params = await algod.getTransactionParams().do()

    // Refund deposit amount + relay fee (deposit never happened, user gets full refund)
    const refundAmount = refundData.amount + (refundData.fee || 0)
    const refundTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      sender: relayer.addr.toString(),
      receiver: refundData.senderAddr,
      amount: refundAmount,
      suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
      note: new TextEncoder().encode(`refund:${body.payTxId}`),
    })

    const signedRefund = refundTxn.signTxn(relayer.sk)
    const resp = await algod.sendRawTransaction(signedRefund).do()
    const txId = (resp as any).txid ?? (resp as any).txId
    await algosdk.waitForConfirmation(algod, txId, 4)

    // Remove refund record
    await env.RELAY_KV.delete(refundKey)

    return json({ status: 'refunded', txId, amount: refundAmount })
  } catch (err: any) {
    // Restore refund record so it can be retried
    await env.RELAY_KV.put(refundKey, JSON.stringify({ ...refundData, status: 'pending' }), { expirationTtl: 30 * 86_400 })
    console.error('Refund failed:', err?.message)
    return json({ error: 'Refund transaction failed' }, 500)
  }
}
