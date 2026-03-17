export const NETWORK = (import.meta.env.VITE_NETWORK || 'testnet') as 'testnet' | 'mainnet'

const NETWORK_CONFIGS = {
  testnet: {
    algod: { baseServer: 'https://testnet-api.algonode.cloud', port: '', token: '' },
    indexer: { baseServer: 'https://testnet-idx.algonode.cloud', port: '', token: '' },
    explorer: 'https://testnet.explorer.perawallet.app',
  },
  mainnet: {
    algod: { baseServer: 'https://mainnet-api.algonode.cloud', port: '', token: '' },
    indexer: { baseServer: 'https://mainnet-idx.algonode.cloud', port: '', token: '' },
    explorer: 'https://explorer.perawallet.app',
  },
} as const

export const ALGOD_CONFIG = NETWORK_CONFIGS[NETWORK].algod
export const INDEXER_CONFIG = NETWORK_CONFIGS[NETWORK].indexer

const DEFAULT_POOL_APP_ID = 756862851
const DEFAULT_POOL_APP_ADDRESS = 'NS4D6MJC47T3YITWPITMYJ2USQUUI4PI7PX6UXL3K6O34PZRYRAW6DDKFM'

function getPoolConfig() {
  const storedId = localStorage.getItem('privacy_pool_app_id')
  if (storedId) {
    // Validate against known pool contracts — reject untrusted app IDs
    // Check flat POOL_CONTRACTS first, then search all pool entries in POOL_REGISTRY
    const allPools = Object.values(POOL_REGISTRY).flat()
    const pool = allPools.find(p => p.appId === parseInt(storedId, 10))
    if (pool) return { appId: pool.appId, appAddress: pool.appAddress }
  }
  return { appId: DEFAULT_POOL_APP_ID, appAddress: DEFAULT_POOL_APP_ADDRESS }
}

export const CONTRACTS = {
  StealthRegistry: {
    appId: 756386179,
    appAddress: 'NIRHYSPNJHSHLQ3DKKMG7BGXM6L4FXATD4W6NGXO7MPQSA32YC6FFLO5FQ',
  },
  get PrivacyPool() { return getPoolConfig() },
  ShieldedPool: {
    appId: 756386192,
    appAddress: 'PTTTWTO7OYNAKWE3IEBBY7D734IPD47QAOHNXR4BIP5PAKVUKTAVW6NOS4',
  },
  ConfidentialAsset: {
    appId: 756386193,
    appAddress: 'CH7INM5MMOLMB4ZYXVD7LVA2U3WS7CEPUMVCRXTFO4UVOP4T4X3X5AZ43Y',
  },
  ZkVerifier: {
    appId: 756420114,
    budgetHelperAppId: 756420102,
  },
  DepositVerifier: {
    appId: 756420115,
    budgetHelperAppId: 756420102,
  },
  PrivateSendVerifier: {
    appId: 756420116,
    budgetHelperAppId: 756420102,
  },
} as const

// Fixed denomination tiers (microAlgos)
export const DENOMINATION_TIERS = [
  { label: '0.1', microAlgos: 100_000n },
  { label: '0.5', microAlgos: 500_000n },
  { label: '1.0', microAlgos: 1_000_000n },
] as const

export type DenominationTier = (typeof DENOMINATION_TIERS)[number]

/** Check if a microAlgo amount is a valid tier */
export function isValidTier(microAlgos: bigint): boolean {
  return DENOMINATION_TIERS.some(t => t.microAlgos === microAlgos)
}

// Default denomination: 1 ALGO = 1_000_000 microAlgos
export const POOL_DENOMINATION = 1_000_000n

// Pool status: 'active' accepts deposits, 'full'/'retiring' only allow withdrawals
export type PoolStatus = 'active' | 'full' | 'retiring'

export interface PoolEntry {
  appId: number
  appAddress: string
  status: PoolStatus
}

// Per-denomination pool contracts — each denomination can have MULTIPLE pools (rotation)
export const POOL_REGISTRY: Record<string, PoolEntry[]> = {
  '100000': [
    { appId: 756813724, appAddress: 'D6K6AS3AMFWVU3LH3PM6WT3YLIP64OMVNMWKJEBIZBTTJTLJ7YPL3T4BTY', status: 'active' },
  ],
  '500000': [
    { appId: 756862750, appAddress: 'FY4LKY5OGPVCQF3XSG52AOSZZWYQYFGPRFR74RN3AUCQKVVRWVZEG7YZZY', status: 'active' },
  ],
  '1000000': [
    { appId: 756862851, appAddress: 'NS4D6MJC47T3YITWPITMYJ2USQUUI4PI7PX6UXL3K6O34PZRYRAW6DDKFM', status: 'active' },
  ],
}

/**
 * Backward-compatible flat pool map: denomination → first pool entry.
 * Used by existing code that iterates POOL_CONTRACTS for tree sync, note validation, etc.
 * This map includes ALL pools across ALL generations (not just active ones).
 */
export const POOL_CONTRACTS: Record<string, { appId: number; appAddress: string }> = (() => {
  const flat: Record<string, { appId: number; appAddress: string }> = {}
  for (const [denom, pools] of Object.entries(POOL_REGISTRY)) {
    // Use the active pool as the default for each denomination
    const active = pools.find(p => p.status === 'active')
    if (active) flat[denom] = { appId: active.appId, appAddress: active.appAddress }
    else if (pools.length > 0) flat[denom] = { appId: pools[0].appId, appAddress: pools[0].appAddress }
  }
  return flat
})()

/** Get ALL pool entries across all denominations (for tree sync, note validation, etc.) */
export function getAllPools(): PoolEntry[] {
  return Object.values(POOL_REGISTRY).flat()
}

/** Get all pool entries for a specific denomination */
export function getPoolsForDenom(microAlgos: bigint): PoolEntry[] {
  return POOL_REGISTRY[microAlgos.toString()] ?? []
}

/** Get the active pool for deposits (the one currently accepting new deposits) */
export function getActivePoolForTier(microAlgos: bigint): PoolEntry {
  const pools = POOL_REGISTRY[microAlgos.toString()]
  if (!pools || pools.length === 0) throw new Error(`No pool configured for denomination ${microAlgos} microAlgos`)
  const active = pools.find(p => p.status === 'active')
  if (!active) throw new Error(`No active pool for denomination ${microAlgos} microAlgos — all pools are full or retiring`)
  return active
}

/** Get pool config by appId (for withdrawals — find the specific pool a note belongs to) */
export function getPoolByAppId(appId: number): (PoolEntry & { denomination: string }) | undefined {
  for (const [denom, pools] of Object.entries(POOL_REGISTRY)) {
    const pool = pools.find(p => p.appId === appId)
    if (pool) return { ...pool, denomination: denom }
  }
  return undefined
}

/** Get the pool generation number (1-indexed) for display purposes */
export function getPoolGeneration(appId: number): number {
  for (const pools of Object.values(POOL_REGISTRY)) {
    const idx = pools.findIndex(p => p.appId === appId)
    if (idx >= 0) return idx + 1
  }
  return 1
}

/** Get total number of pool generations for a denomination */
export function getPoolGenerationCount(microAlgos: bigint): number {
  return (POOL_REGISTRY[microAlgos.toString()] ?? []).length
}

/** Check if a tier's pool contract is deployed */
export function isTierDeployed(microAlgos: bigint): boolean {
  const pools = POOL_REGISTRY[microAlgos.toString()]
  return !!pools && pools.length > 0 && pools.some(p => p.appId !== 0)
}

/** Get pool config for a specific tier (microAlgos) — returns the active pool for deposits */
export function getPoolForTier(microAlgos: bigint): { appId: number; appAddress: string } {
  return getActivePoolForTier(microAlgos)
}

// LogicSig relayer (trustless, no server needed)
export const LSIG_RELAYER_ENABLED = true
export const LSIG_RELAYER_FEE = 200_000n  // 0.2 ALGO (covers verifier gas + margin)

// Worker relayer configuration — multiple relayers for privacy (no single operator sees all withdrawals)
// Frontend randomly picks one per operation. Add more as operators join.
export const RELAYERS = [
  {
    url: import.meta.env.VITE_RELAYER_1_URL || 'https://privacy-pool-relayer.mitchhall16.workers.dev',
    address: import.meta.env.VITE_RELAYER_1_ADDRESS || 'MCH3ZDYI6NEP2EFGZVLOH7BZH6ZEUYBZWERNJT7JGYK4GMUJDL6TLHZTIA',
    fee: 50_000n, // 0.05 ALGO
  },
  {
    url: import.meta.env.VITE_RELAYER_2_URL || 'https://privacy-pool-relayer-2.mitchhall16.workers.dev',
    address: import.meta.env.VITE_RELAYER_2_ADDRESS || 'EVDMCOHJVAOKKSWBTRQN5JYIMRQHJV2YGPUE2HHVBWLOZCKZOJXATZPOYE',
    fee: 50_000n, // 0.05 ALGO
  },
]

/** Pick a random relayer for this operation (crypto-secure randomness) */
export function pickRelayer(): { url: string; address: string; fee: bigint } {
  const buf = new Uint8Array(1)
  crypto.getRandomValues(buf)
  return RELAYERS[buf[0] % RELAYERS.length]
}


// Whether to use PLONK LogicSig verification (cheaper) or Groth16 app verification
export const USE_PLONK_LSIG = import.meta.env.VITE_USE_PLONK_LSIG !== 'false'

// Fee estimates (in microAlgos) — network fees paid by sender, not deducted from transfer
// Groth16 app-based fees (legacy, ~0.2 ALGO per operation)
const GROTH16_FEES = {
  deposit: 206_000n,
  withdraw: 215_000n,
  privateSend: 226_000n,
  split: 440_000n,
  combine: 440_000n,
  verifierCall: 203_000n,
  withdrawVerifierCall: 213_000n,
  privateSendVerifierCall: 223_000n,
  splitVerifierCall: 233_000n,
  combineVerifierCall: 233_000n,
  minBalance: 100_000n,
}

// PLONK LogicSig fees (~0.018 ALGO per operation, 16-txn group)
const PLONK_LSIG_FEES = {
  deposit: 20_000n,              // 16 txns (0.016) + payment (0.001) + pool app call (0.002) + margin
  withdraw: 20_000n,             // 16 txns (0.016) + pool app call (0.002) + margin
  privateSend: 21_000n,          // 16 txns (0.016) + payment (0.001) + pool app call (0.002) + margin
  split: 40_000n,                // 2x verification groups
  combine: 40_000n,              // 2x verification groups
  verifierCall: 16_000n,         // 16 txns (2 LogicSigs + 14 padding)
  withdrawVerifierCall: 16_000n,
  privateSendVerifierCall: 16_000n,
  splitVerifierCall: 16_000n,
  combineVerifierCall: 16_000n,
  minBalance: 100_000n,
}

export const FEES = USE_PLONK_LSIG ? PLONK_LSIG_FEES : GROTH16_FEES

// Falcon LogicSig extra fees (when quantum-safe mode is active)
// Groth16 groups need padding txns because Falcon LogicSig is ~3093 bytes.
// PLONK groups (6+ txns) already have enough byte budget from fee pooling.
// EXPERIMENTAL: Falcon signing is PQ-secure but HPKE note encryption (X25519) is not.
export const FALCON_EXTRA_FEE = {
  groth16Padding: 2_000n, // 1-2 padding txns × 0.001 ALGO
  plonk: 0n,
} as const

// Batch window interval (minutes) — UI-only, used for optional timing batches
export const BATCH_WINDOW_MINUTES = 15

// Treasury address for protocol fees
export const TREASURY_ADDRESS = 'MCH3ZDYI6NEP2EFGZVLOH7BZH6ZEUYBZWERNJT7JGYK4GMUJDL6TLHZTIA'

// Protocol fee per operation (microAlgos)
export const PROTOCOL_FEE = 5_000n // 0.005 ALGO

// Pool operations since note creation before suggesting churn
export const STALE_NOTE_THRESHOLD = 20

// ── Anti-correlation protections ──

// Minimum deposits that must exist in a pool after your deposit before you can withdraw.
// Prevents "deposit then immediately withdraw" deanonymization.
export const MIN_SOAK_DEPOSITS = 3

// Minimum seconds between operations from the same session.
// Prevents rapid deposit-withdraw clustering that creates linkable patterns.
export const OPERATION_COOLDOWN_MS = 120_000 // 2 minutes

// Maximum operations per session before warning about cluster correlation.
// If a user deposits 5x in a row, the cluster is obvious even if individual txns aren't linked.
export const CLUSTER_WARNING_THRESHOLD = 3

// Random delay range (ms) added before withdrawal submission.
// Jitters timing so withdrawals don't happen at predictable offsets from batch windows.
export const WITHDRAW_JITTER_MS = { min: 5_000, max: 30_000 }

// Optional subsidy tiers — user can pay extra to reduce fees for the next depositor
export const SUBSIDY_TIERS = [
  { label: '0.01', microAlgos: 10_000n },
  { label: '0.05', microAlgos: 50_000n },
  { label: '0.10', microAlgos: 100_000n },
] as const

export type SubsidyTier = (typeof SUBSIDY_TIERS)[number]

export const EXPLORER_BASE = NETWORK_CONFIGS[NETWORK].explorer

export function txnUrl(txId: string): string {
  return `${EXPLORER_BASE}/tx/${txId}`
}

export function addrUrl(addr: string): string {
  return `${EXPLORER_BASE}/address/${addr}`
}

// PLONK LogicSig verifier addresses (set after deployment)
// These are the deterministic addresses of compiled PLONK verifier LogicSig programs
export const PLONK_VERIFIER_ADDRESSES: Record<string, {
  withdraw?: string
  deposit?: string
  privateSend?: string
}> = {
  testnet: {
    withdraw: 'PBVB7NKXKETOSI4ORWQY7A77PFNRUD4I2PL5L7HZ7EQSHNGIT4R2R6FXFY',
    deposit: 'Q4NKMNKJFOQYPWHVHODP7LUDIBPL3ZSTZLVUQ5UW6JORPWQ4N57UB7XQMQ',
    privateSend: 'F53SJ3YAMXG4LTDZT5RMS7JJTJKD5HVVBYWT3XRLWIZSGLGHUSJSBH7JNQ',
  },
  mainnet: {
    withdraw: undefined,
    deposit: undefined,
    privateSend: undefined,
  },
}

// Mainnet pool contracts (set after deployment)
export const MAINNET_POOL_REGISTRY: Record<string, PoolEntry[]> = {
  '100000': [{ appId: 0, appAddress: '', status: 'active' }],
  '500000': [{ appId: 0, appAddress: '', status: 'active' }],
  '1000000': [{ appId: 0, appAddress: '', status: 'active' }],
}
