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

const DEFAULT_POOL_APP_ID = 756480627
const DEFAULT_POOL_APP_ADDRESS = '624W56BLCEIXUMOYCDYACW3QOJEKQTCC6YXY4Q7Z3Z4WQUOBERZTUEHP7I'

function getPoolConfig() {
  const storedId = localStorage.getItem('privacy_pool_app_id')
  if (storedId) {
    // Validate against known pool contracts — reject untrusted app IDs
    const pool = POOL_CONTRACTS[storedId] ?? Object.values(POOL_CONTRACTS).find(p => p.appId === parseInt(storedId, 10))
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
  { label: '5.0', microAlgos: 5_000_000n },
  { label: '10.0', microAlgos: 10_000_000n },
] as const

export type DenominationTier = (typeof DENOMINATION_TIERS)[number]

/** Check if a microAlgo amount is a valid tier */
export function isValidTier(microAlgos: bigint): boolean {
  return DENOMINATION_TIERS.some(t => t.microAlgos === microAlgos)
}

// Default denomination: 1 ALGO = 1_000_000 microAlgos
export const POOL_DENOMINATION = 1_000_000n

// Per-denomination pool contracts
export const POOL_CONTRACTS: Record<string, { appId: number; appAddress: string }> = {
  '100000': { appId: 756478534, appAddress: 'KKBAABJWKQADOM6HG4JPDQDQMCD5JSMJR2HCNDQGQRW4KL5UDVVUWGMU5E' },
  '500000': { appId: 756478549, appAddress: 'E5TRMAZSX6FCSFVZU6OLS372YB56GAW662CHX2NAD6C7VATSYYVXECKDG4' },
  '1000000': { appId: 756480627, appAddress: '624W56BLCEIXUMOYCDYACW3QOJEKQTCC6YXY4Q7Z3Z4WQUOBERZTUEHP7I' },
  '5000000': { appId: 0, appAddress: '' },   // deploy needed
  '10000000': { appId: 0, appAddress: '' },  // deploy needed
}

/** Check if a tier's pool contract is deployed */
export function isTierDeployed(microAlgos: bigint): boolean {
  const pool = POOL_CONTRACTS[microAlgos.toString()]
  return !!pool && pool.appId !== 0
}

/** Get pool config for a specific tier (microAlgos) */
export function getPoolForTier(microAlgos: bigint): { appId: number; appAddress: string } {
  const pool = POOL_CONTRACTS[microAlgos.toString()]
  if (!pool) throw new Error(`No pool configured for denomination ${microAlgos} microAlgos`)
  return pool
}

// LogicSig relayer (trustless, no server needed)
export const LSIG_RELAYER_ENABLED = true
export const LSIG_RELAYER_FEE = 200_000n  // 0.2 ALGO (covers verifier gas + margin)

// Worker relayer configuration — multiple relayers for privacy (no single operator sees all withdrawals)
// Frontend randomly picks one per operation. Add more as operators join.
export const RELAYERS = [
  {
    url: 'https://privacy-pool-relayer.mitchhall16.workers.dev',
    address: 'MCH3ZDYI6NEP2EFGZVLOH7BZH6ZEUYBZWERNJT7JGYK4GMUJDL6TLHZTIA',
    fee: 50_000n, // 0.05 ALGO
  },
  {
    url: 'https://privacy-pool-relayer-2.mitchhall16.workers.dev',
    address: 'EVDMCOHJVAOKKSWBTRQN5JYIMRQHJV2YGPUE2HHVBWLOZCKZOJXATZPOYE',
    fee: 50_000n, // 0.05 ALGO
  },
] as const

/** Pick a random relayer for this operation (crypto-secure randomness) */
export function pickRelayer(): typeof RELAYERS[number] {
  const buf = new Uint8Array(1)
  crypto.getRandomValues(buf)
  return RELAYERS[buf[0] % RELAYERS.length]
}


// Whether to use PLONK LogicSig verification (cheaper) or Groth16 app verification
export const USE_PLONK_LSIG = (import.meta.env.VITE_USE_PLONK_LSIG === 'true') || false

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

// PLONK LogicSig fees (~0.007 ALGO per operation)
const PLONK_LSIG_FEES = {
  deposit: 7_000n,               // 4 LogicSig (0.004) + payment (0.001) + pool app call (0.002)
  withdraw: 6_000n,              // 4 LogicSig (0.004) + pool app call (0.002)
  privateSend: 7_000n,           // 4 LogicSig (0.004) + payment (0.001) + pool app call (0.002)
  split: 14_000n,                // 2x verification groups
  combine: 14_000n,              // 2x verification groups
  verifierCall: 4_000n,          // 4 LogicSig txns
  withdrawVerifierCall: 4_000n,
  privateSendVerifierCall: 4_000n,
  splitVerifierCall: 4_000n,
  combineVerifierCall: 4_000n,
  minBalance: 100_000n,
}

export const FEES = USE_PLONK_LSIG ? PLONK_LSIG_FEES : GROTH16_FEES

// Falcon LogicSig extra fees (when quantum-safe mode is active)
// Groth16 groups need padding txns because Falcon LogicSig is ~3093 bytes.
// PLONK groups (6+ txns) already have enough byte budget from fee pooling.
export const FALCON_EXTRA_FEE = {
  groth16Padding: 2_000n, // 1-2 padding txns × 0.001 ALGO
  plonk: 0n,
} as const

// Batch window interval (minutes). Deposits snap to :00, :15, :30, :45
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
    withdraw: 'Y5EGJIAMTCQJ5VYEPPNHUXLJ2QOAQRFION77ILEOFM63V5DOURIOSLE2XE',
    deposit: 'T7LRWUZ3PL5RPGNMFDQNU7KETGLG2KKXV2YWODJ4KZFJSN5I3IPQEH7E44',
    privateSend: 'ANQG655MULTMHGQVJEEBKUDISGQ7OFNG7WBQXQPHQOKH4LSO5QMNA2KLIE',
  },
  mainnet: {
    withdraw: undefined,
    deposit: undefined,
    privateSend: undefined,
  },
}

// Mainnet pool contracts (set after deployment)
export const MAINNET_POOL_CONTRACTS: Record<string, { appId: number; appAddress: string }> = {
  '100000': { appId: 0, appAddress: '' },
  '500000': { appId: 0, appAddress: '' },
  '1000000': { appId: 0, appAddress: '' },
}
