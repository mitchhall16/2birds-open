/**
 * Privacy Pool Relayer — Cloudflare Worker
 *
 * TRUST MODEL:
 * Standard /api/withdraw uses IP-based rate limiting (HMAC-hashed with IP_HASH_SECRET).
 * The relayer operator and Cloudflare can still see raw IPs on that endpoint.
 *
 * For stronger IP privacy:
 *   - POST /api/withdraw-anonymous — requires proof-of-work, never reads/logs IP
 *   - Tor users hitting /api/withdraw are auto-detected and required to provide PoW
 *   - GET /api/pow-challenge — returns current difficulty and server nonce
 *
 * The frontend automatically fetches a PoW challenge and solves it before submission,
 * so all relayer withdrawals now go through the anonymous endpoint by default.
 *
 * Submits withdrawal and deposit transactions on behalf of users so the on-chain
 * sender is the relayer address, not the user's wallet (preserving privacy).
 *
 * Supports two verification modes:
 *   - PLONK LogicSig (default): 1 LogicSig + 5 padding txns + pool pay + app call (8-txn group)
 *   - Groth16 app call (legacy): verifier app call + pool app call
 *
 * POST /api/withdraw
 * Body: { mode, proof, signals, poolAppId, nullifierHash, root, recipient, fee, inverses? }
 *
 * POST /api/withdraw-anonymous  (PoW required via X-PoW-Nonce + X-PoW-Server-Nonce headers)
 * Body: same as /api/withdraw
 *
 * GET /api/pow-challenge
 * Returns: { serverNonce, difficulty, algorithm, hint }
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
  IP_HASH_SECRET?: string             // HMAC secret for IP hashing (set via wrangler secret put IP_HASH_SECRET)
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

// Compiled PLONK deposit verifier (too large for CF secrets, embedded here)
const PLONK_DEPOSIT_VERIFIER_TEAL_EMBEDDED = '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'
const PLONK_DEPOSIT_VERIFIER_ADDR_EMBEDDED = 'Q4NKMNKJFOQYPWHVHODP7LUDIBPL3ZSTZLVUQ5UW6JORPWQ4N57UB7XQMQ'
const PLONK_DEPOSIT_VK_HEX_EMBEDDED = '00000004000000100000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000300eeb2cb5981ed45649abebde081dcff16c8601de4347e7dd1628ba2daac43b7219fba44a8bb21cb80bf3478c945161c258855ba7665049755e67df45eb816ee00cf67e193d31b42fa308bd01733eed3025576cc53d1d70a224e22d7107dc76b29f6b7541048617ace867f78f9218e3e248ae3edeb100173a87f85975ae94c0e077a92780c6cc21da44162c59014d20847dd3fe47da420ea08eafd0dbbf40d091335c110b4a2c3f028b96303e4afc15461e54946bbaafe85fe64fbe44c4f4b7b03bf455f54afdce670ca43d3cdc7693d56e652ae4229ce42650fa59262b1a6cb255328f6d5c3c6a91656c712ed372b61efc27f468a1eda437ed2dffa683d9ac31a406b7b05095f6f74324d3595dfcb5a41e95c067cdbcc3165bc52325b917fcd1a0a01f36dadf49f77b80479312456282a49644f1738368f34c31dea18b79f372ddcad5a9a51d8c5daa3489d0006219c40b42516ab27e459921d7760f187272424efe9ac0f5be474cf9fafa145173ef315a58bb5dd7cf93403b289e83f7188070d24975b49b2c59dee137e7940426ed5657e2b9368b422e7900211e8a1d2d48e0746f44674f7201dcb9f92dbd2beb756b5ae8e638847a8d86c1e9343f638fc170a6d786362920b0f1fb1ac0c95940c69a476fd5b7241a675ca08513cfa4aba3428b9f8042c3f344e6d898cd429139a3a34d14d28dda56c79f2e67ae0c1e6d9a82964d870330e3c62ef013d9f36be4febc988a31f5e85c2f80d8dbb680fc116d930441fd1b5d3370482c42152a8899027716989a6996c2535bc9f7fee8aaef79e26186a2d65ee4d2f9c9a5b91f86597d35f192cd120caf7e935d8443d1938e23d054793348f12c0cf5622c340573cb277586319de359ab9389778f689786b1e481970ea81dd6992adfbc571effb03503adbbb6a857f578403c6c40e22d65b3c02'

// Compiled PLONK withdraw verifier (too large for CF secrets, embedded here)
const PLONK_WITHDRAW_VERIFIER_TEAL_EMBEDDED = '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'
const PLONK_WITHDRAW_VERIFIER_ADDR_EMBEDDED = 'PBVB7NKXKETOSI4ORWQY7A77PFNRUD4I2PL5L7HZ7EQSHNGIT4R2R6FXFY'
const PLONK_WITHDRAW_VK_HEX_EMBEDDED = '000000060000000f000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000032d1ba66f5941dc91017171fa69ec2bd0022a2a2d4115a009a93458fd4e26ecfb0a680a0c5b6167b76bb177f86df653468fdb4bdaedb73a7f1d44f3a9cf9c736108d7eb1c7afdf2bcc4185ba340a93e70b0fbabb53cc94f43de358cf72831b3ae11363a803100245bbb63f994adce3b1ddea7f163ac8c88378df1d2ab29b21e4402a2bae4e12f275888e4920029b11202c9c5e6b4ebce685cdae49f8416fb3a7303de0db1c5b6d9068a50655ed178e5aa9068f6ed6dbd0fbae7e2dfac2f698555217f5566f5ca2a6dacbc8c9b046cf5295623add5d09003f43e40e757d952c52901fe5b0a618eea7ffc9205b9a050094610ec08341f56883fb7f613e3686a93ac1aac63b0fe283dc28cd850b8cfe09bc1f3219cf0136a791e8528ef6a5af7d85709d1de037a6c9a375564211617326e08dfcf6406e22f854544d70ac582a869331eedc11c5aa73612b3ae0c2d817a06626273da68d76dd1663889535cc34ea640170b3e4f6a92d4cea661fbb82e7e1d052f704ff4df291981cad77c691d4e2d7c28764ec5eb33400ff5caa575ac9770233941f2ae962cb42c46dbe5937f96f6671fc90a70a6a9a2481479de4f2903ec851700092a8a0892cc38cdee1fdf2759261405f9970edd9f718d41e79aa5563457980cbb94584ca6853c06fa3bf53888a40c5b0c39868b1dec789de3baad402321e2aef25ea2451d3cf23e92368fccfd6f072ae0c4d25e47eb375499f49f18cf87c0187e732f193392be1cb5317ad2420730441fd1b5d3370482c42152a8899027716989a6996c2535bc9f7fee8aaef79e26186a2d65ee4d2f9c9a5b91f86597d35f192cd120caf7e935d8443d1938e23d054793348f12c0cf5622c340573cb277586319de359ab9389778f689786b1e481970ea81dd6992adfbc571effb03503adbbb6a857f578403c6c40e22d65b3c02'

const PLONK_MIN_RELAY_FEE = 10_000  // 0.01 ALGO (PLONK is cheap)
const GROTH16_MIN_RELAY_FEE = 1_000 // 0.001 ALGO (testnet: relayer absorbs 213K verifier txn fee)
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
    'Access-Control-Allow-Headers': 'Content-Type, X-PoW-Nonce, X-PoW-Server-Nonce',
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

// ── Proof-of-Work anti-spam (for Tor / anonymous submissions) ──
// SHA-256(bodyJson + nonce) must have POW_DIFFICULTY leading zero bits.
// 16 bits ≈ 65 536 hashes — fraction of a second on any modern device.
const POW_DIFFICULTY = 16

// Server nonce rotates every 5 minutes to prevent pre-computation
let powServerNonce = crypto.randomUUID()
let powNonceExpiry = Date.now() + 5 * 60_000

function getServerNonce(): string {
  const now = Date.now()
  if (now > powNonceExpiry) {
    powServerNonce = crypto.randomUUID()
    powNonceExpiry = now + 5 * 60_000
  }
  return powServerNonce
}

/** Verify proof-of-work: SHA-256(serverNonce + bodyJson + clientNonce) has N leading zero bits */
async function verifyPoW(serverNonce: string, bodyJson: string, clientNonce: string): Promise<boolean> {
  // Accept the current nonce or the previous one (in case of rotation during solve)
  if (serverNonce !== powServerNonce && serverNonce !== powServerNonce) {
    return false
  }
  const payload = serverNonce + bodyJson + clientNonce
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload))
  const bytes = new Uint8Array(hash)
  // Check POW_DIFFICULTY leading zero bits
  const fullBytes = Math.floor(POW_DIFFICULTY / 8)
  const remainBits = POW_DIFFICULTY % 8
  for (let i = 0; i < fullBytes; i++) {
    if (bytes[i] !== 0) return false
  }
  if (remainBits > 0 && fullBytes < bytes.length) {
    if (bytes[fullBytes] >> (8 - remainBits) !== 0) return false
  }
  return true
}

/** Check if a request is coming through Tor */
function isTorRequest(request: Request): boolean {
  // Cloudflare sets Cf-Is-Tor header for known Tor exit nodes
  if (request.headers.get('Cf-Is-Tor') === '1') return true
  // Also check the connecting IP — Tor exit nodes are well-known
  const ip = request.headers.get('CF-Connecting-IP') ?? ''
  // CF-Connecting-IP of '0.0.0.0' or T1/Tor identifiers
  if (ip === '0.0.0.0') return true
  return false
}

// Payment replay protection uses KV (persistent across isolate recycles)
// KV key: "pay:<txnId>" → "1", TTL 24 hours (txns expire after ~1000 rounds anyway)
const KV_PAY_PREFIX = 'pay:'
const KV_PAY_TTL_SECONDS = 86_400 // 24 hours

// Refund queue uses KV: "refund:<senderAddr>:<payTxId>" → JSON { amount, commitment, timestamp }
const KV_REFUND_PREFIX = 'refund:'

/**
 * HMAC-SHA256 hash of IP with a per-deployment secret so the hash can't be
 * reversed by brute-forcing the ~4 billion IPv4 address space.
 * Falls back to plain SHA-256 if IP_HASH_SECRET is not set (dev/testing only).
 */
async function hashIp(ip: string, secret?: string): Promise<string> {
  const enc = new TextEncoder()
  if (secret) {
    const key = await crypto.subtle.importKey(
      'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    )
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(ip))
    return Array.from(new Uint8Array(sig)).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('')
  }
  // Fallback: plain SHA-256 (NOT safe against brute-force — set IP_HASH_SECRET in production)
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(ip))
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

    // ── PoW challenge endpoint (for anonymous/Tor submissions) ──
    if (url.pathname === '/api/pow-challenge' && request.method === 'GET') {
      return jsonResponse({
        serverNonce: getServerNonce(),
        difficulty: POW_DIFFICULTY,
        algorithm: 'sha256',
        hint: `SHA-256(serverNonce + requestBodyJson + clientNonce) must have ${POW_DIFFICULTY} leading zero bits`,
      }, 200, env, request)
    }

    // ── Anonymous withdraw (Tor-friendly, no IP logging, PoW required) ──
    if (url.pathname === '/api/withdraw-anonymous' && request.method === 'POST') {
      // Read body first to verify PoW before any processing
      const contentLength = parseInt(request.headers.get('Content-Length') ?? '0', 10)
      if (contentLength > MAX_REQUEST_BYTES) {
        return jsonResponse({ error: 'Request too large' }, 413, env, request)
      }
      let bodyText: string
      try { bodyText = await request.text() } catch {
        return jsonResponse({ error: 'Failed to read request body' }, 400, env, request)
      }
      const powNonce = request.headers.get('X-PoW-Nonce')
      const powServerNonceHeader = request.headers.get('X-PoW-Server-Nonce')
      if (!powNonce || !powServerNonceHeader) {
        return jsonResponse({ error: 'Missing proof-of-work headers (X-PoW-Nonce, X-PoW-Server-Nonce)' }, 400, env, request)
      }
      const valid = await verifyPoW(powServerNonceHeader, bodyText, powNonce)
      if (!valid) {
        return jsonResponse({ error: 'Invalid proof-of-work. Fetch /api/pow-challenge for current parameters.' }, 403, env, request)
      }
      // PoW verified — process withdrawal without any IP logging or rate limiting
      return handleWithdrawFromBody(bodyText, env, request)
    }

    if (url.pathname === '/api/withdraw' && request.method === 'POST') {
      // Check if request is from Tor — if so, require PoW instead of IP rate limiting
      if (isTorRequest(request)) {
        const contentLength = parseInt(request.headers.get('Content-Length') ?? '0', 10)
        if (contentLength > MAX_REQUEST_BYTES) {
          return jsonResponse({ error: 'Request too large' }, 413, env, request)
        }
        let bodyText: string
        try { bodyText = await request.text() } catch {
          return jsonResponse({ error: 'Failed to read request body' }, 400, env, request)
        }
        const powNonce = request.headers.get('X-PoW-Nonce')
        const powServerNonceHeader = request.headers.get('X-PoW-Server-Nonce')
        if (!powNonce || !powServerNonceHeader) {
          return jsonResponse({
            error: 'Tor detected — proof-of-work required. Include X-PoW-Nonce and X-PoW-Server-Nonce headers. See /api/pow-challenge.',
            requiresPoW: true,
          }, 403, env, request)
        }
        const valid = await verifyPoW(powServerNonceHeader, bodyText, powNonce)
        if (!valid) {
          return jsonResponse({ error: 'Invalid proof-of-work. Fetch /api/pow-challenge for current parameters.' }, 403, env, request)
        }
        return handleWithdrawFromBody(bodyText, env, request)
      }
      // Standard IP-based rate limiting for non-Tor requests
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown', env.IP_HASH_SECRET)
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded. Max 5 requests per minute.' }, 429, env, request)
      }
      return handleWithdraw(request, env)
    }

    if (url.pathname === '/api/deposit' && request.method === 'POST') {
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown', env.IP_HASH_SECRET)
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
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown', env.IP_HASH_SECRET)
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded.' }, 429, env, request)
      }
      return handleRefundCheck(url, env, request)
    }

    // Process refund: POST /api/process-refund (operator only — requires OPERATOR_API_KEY)
    if (url.pathname === '/api/process-refund' && request.method === 'POST') {
      const ipHash = await hashIp(request.headers.get('CF-Connecting-IP') ?? 'unknown', env.IP_HASH_SECRET)
      if (!checkRateLimit(ipHash)) {
        return jsonResponse({ error: 'Rate limit exceeded.' }, 429, env, request)
      }
      return handleProcessRefund(request, env)
    }

    return jsonResponse({ error: 'Not found' }, 404, env, request)
  },
}

/** Handle withdraw when body has already been read (for PoW-verified requests) */
async function handleWithdrawFromBody(bodyText: string, env: Env, request: Request): Promise<Response> {
  const json = (data: object, status = 200) => jsonResponse(data, status, env, request)

  if (!env.RELAYER_MNEMONIC) {
    return json({ error: 'Relayer not configured' }, 500)
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

  return processWithdraw(body, env, request)
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

  return processWithdraw(body, env, request)
}

async function processWithdraw(body: WithdrawRequest, env: Env, request: Request): Promise<Response> {
  const json = (data: object, status = 200) => jsonResponse(data, status, env, request)

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
      suggestedParams: { ...params, fee: BigInt(5000), flatFee: true },
    })

    let signedTxns: Uint8Array[]
    let txId: string

    if (mode === 'plonk') {
      // ── PLONK LogicSig mode (2-LogicSig, 16-txn group) ──
      // [0]  LogicSig Payment (verifier→verifier, Note=proof 768 bytes)
      // [1]  Relayer Payment  (relayer→relayer,   Note=VK 744 bytes)
      // [2]  Relayer Payment  (relayer→relayer,   Note=inverses 192 bytes)
      // [3]  LogicSig Payment (verifier→verifier, Note=signals 192 bytes)
      // [4]  Withdraw App Call (relayer, poolAppId)
      // [5-15] 11 Relayer Padding Payments (random notes)
      // 16-txn group = 16,000 byte budget (2 LogicSigs × ~7.6 KB = ~15.2 KB fits)
      const tealB64 = env.PLONK_VERIFIER_TEAL || PLONK_WITHDRAW_VERIFIER_TEAL_EMBEDDED
      const verifierAddr = env.PLONK_VERIFIER_ADDR || PLONK_WITHDRAW_VERIFIER_ADDR_EMBEDDED
      if (!tealB64 || !verifierAddr) {
        return json({ error: 'PLONK verifier not configured on relayer' }, 500)
      }

      const inversesBytes = hexToBytes(body.inverses!)
      const programBytes = new Uint8Array(
        atob(tealB64).split('').map(c => c.charCodeAt(0))
      )

      // Decode VK bytes for Note field
      const withdrawVkHex = env.PLONK_VK_HEX || PLONK_WITHDRAW_VK_HEX_EMBEDDED
      const vkBytes = withdrawVkHex ? hexToBytes(withdrawVkHex) : new Uint8Array(0)

      // [0] LogicSig Payment — proof in Note (TEAL reads txn Note)
      const lsigTxn0 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: verifierAddr,
        receiver: verifierAddr,
        amount: 0,
        note: proofBytes,
        suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
      })

      const makePadding = (note?: Uint8Array) =>
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: relayerAddrStr,
          receiver: relayerAddrStr,
          amount: 0,
          suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
          note: note || crypto.getRandomValues(new Uint8Array(8)),
        })

      const paddingTxn1 = makePadding(vkBytes)        // [1] VK in Note
      const paddingTxn2 = makePadding(inversesBytes)   // [2] inverses in Note

      // [3] LogicSig Payment — signals in Note (budget_padding branch; pool reads prevTxn.note)
      const lsigTxn3 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: verifierAddr,
        receiver: verifierAddr,
        amount: 0,
        note: signalsBytes,
        suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
      })

      // [5-15] 11 padding txns for byte budget
      const paddingAfter: algosdk.Transaction[] = []
      for (let i = 0; i < 11; i++) {
        paddingAfter.push(makePadding())
      }

      const group = [lsigTxn0, paddingTxn1, paddingTxn2, lsigTxn3, withdrawAppCall, ...paddingAfter]
      algosdk.assignGroupID(group)

      // Sign both LogicSig txns — NO args (TEAL reads data from Note fields)
      const lsig = new algosdk.LogicSigAccount(programBytes)
      const signedLsig0 = algosdk.signLogicSigTransaction(lsigTxn0, lsig).blob
      const signedLsig3 = algosdk.signLogicSigTransaction(lsigTxn3, lsig).blob

      // Sign relayer txns
      const signedPad1 = paddingTxn1.signTxn(relayer.sk)
      const signedPad2 = paddingTxn2.signTxn(relayer.sk)
      const signedWithdraw = withdrawAppCall.signTxn(relayer.sk)
      const signedPaddingAfter = paddingAfter.map(txn => txn.signTxn(relayer.sk))

      signedTxns = [signedLsig0, signedPad1, signedPad2, signedLsig3, signedWithdraw, ...signedPaddingAfter]
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
        suggestedParams: { ...params, fee: BigInt(220_000), flatFee: true },
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
    const errMsg = err?.message || 'unknown'
    // Extract just the rejection reason (skip the serialized transaction bytes)
    const logicEvalIdx = errMsg.indexOf('logic eval')
    const rejectedIdx = errMsg.indexOf('rejected by logic')
    const exceedsIdx = errMsg.indexOf('exceeds')
    const budgetIdx = errMsg.indexOf('budget')
    const signalPart = logicEvalIdx >= 0 ? errMsg.slice(logicEvalIdx, logicEvalIdx + 500)
      : rejectedIdx >= 0 ? errMsg.slice(rejectedIdx, rejectedIdx + 500)
      : exceedsIdx >= 0 ? errMsg.slice(exceedsIdx, exceedsIdx + 500)
      : errMsg.slice(-500)
    console.error('Relayer withdraw error:', signalPart)
    return json({ error: 'Transaction failed', detail: signalPart }, 500)
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
      // ── PLONK LogicSig mode (2-LogicSig, 16-txn group) ──
      // [0]  LogicSig Payment (verifier→verifier, Note=proof 768 bytes)
      // [1]  Relayer Payment  (relayer→relayer,   Note=VK bytes)
      // [2]  Relayer Payment  (relayer→relayer,   Note=inverses bytes)
      // [3]  LogicSig Payment (verifier→verifier, Note=signals 128 bytes)  ← VERIFIER
      // [4]  Pool Funding Payment (relayer→pool, denomination amount)
      // [5]  Deposit App Call (relayer, poolAppId)  ← groupIndex=5, verifierTxn=group[3] ✓
      // [6-15] 10 Relayer Padding Payments (random notes)
      // 16-txn group = 16,000 byte budget (2 LogicSigs × ~6.7 KB = ~13.4 KB fits)
      const tealB64 = env.PLONK_DEPOSIT_VERIFIER_TEAL || PLONK_DEPOSIT_VERIFIER_TEAL_EMBEDDED
      const verifierAddr = env.PLONK_DEPOSIT_VERIFIER_ADDR || PLONK_DEPOSIT_VERIFIER_ADDR_EMBEDDED
      if (!tealB64 || !verifierAddr) {
        return json({ error: 'PLONK deposit verifier not configured' }, 500)
      }

      const inversesBytes = hexToBytes(body.inverses!)
      const programBytes = new Uint8Array(
        atob(tealB64).split('').map(c => c.charCodeAt(0))
      )

      const depositVkHex = env.PLONK_DEPOSIT_VK_HEX || PLONK_DEPOSIT_VK_HEX_EMBEDDED
      const vkBytes = depositVkHex ? hexToBytes(depositVkHex) : new Uint8Array(0)

      // [0] LogicSig Payment — proof in Note (TEAL reads txn Note)
      const lsigTxn0 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: verifierAddr,
        receiver: verifierAddr,
        amount: 0,
        note: proofBytes,
        suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
      })

      const makePadding = (note?: Uint8Array) =>
        algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender: relayerAddrStr,
          receiver: relayerAddrStr,
          amount: 0,
          suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
          note: note || crypto.getRandomValues(new Uint8Array(8)),
        })

      const paddingTxn1 = makePadding(vkBytes)        // [1] VK in Note
      const paddingTxn2 = makePadding(inversesBytes)   // [2] inverses in Note

      // [3] LogicSig Payment — signals in Note (budget_padding branch; pool reads group[appCallIndex-2].note)
      const lsigTxn3 = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: verifierAddr,
        receiver: verifierAddr,
        amount: 0,
        note: signalsBytes,
        suggestedParams: { ...params, fee: BigInt(1000), flatFee: true },
      })

      // [4] poolPayTxn (already created above)
      // [5] depositAppCall (already created above)

      // [6-15] 10 padding txns for byte budget
      const paddingAfter: algosdk.Transaction[] = []
      for (let i = 0; i < 10; i++) {
        paddingAfter.push(makePadding())
      }

      // Deposit: verifier at [3], payment at [4], app call at [5]
      // Pool reads verifierTxn = group[appCallIndex - 2] = group[3] ✓
      const group = [lsigTxn0, paddingTxn1, paddingTxn2, lsigTxn3, poolPayTxn, depositAppCall, ...paddingAfter]
      algosdk.assignGroupID(group)

      // Sign both LogicSig txns — NO args (TEAL reads data from Note fields)
      const lsig = new algosdk.LogicSigAccount(programBytes)
      const signedLsig0 = algosdk.signLogicSigTransaction(lsigTxn0, lsig).blob
      const signedLsig3 = algosdk.signLogicSigTransaction(lsigTxn3, lsig).blob

      // Sign relayer txns
      const signedPad1 = paddingTxn1.signTxn(relayer.sk)
      const signedPad2 = paddingTxn2.signTxn(relayer.sk)
      const signedPoolPay = poolPayTxn.signTxn(relayer.sk)
      const signedDeposit = depositAppCall.signTxn(relayer.sk)
      const signedPaddingAfter = paddingAfter.map(txn => txn.signTxn(relayer.sk))

      signedTxns = [signedLsig0, signedPad1, signedPad2, signedLsig3, signedPoolPay, signedDeposit, ...signedPaddingAfter]
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
      detail: err?.message || 'unknown',
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
