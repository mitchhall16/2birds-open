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

const DEFAULT_POOL_APP_ID = 756420132
const DEFAULT_POOL_APP_ADDRESS = 'O3I26T6EZ2UCCSWHQGMD6R5XJUX2AK3DU5I7S76M2SA2AE63IFZFUMPKEU'

function getPoolConfig() {
  const storedId = localStorage.getItem('privacy_pool_app_id')
  const storedAddr = localStorage.getItem('privacy_pool_app_address')
  if (storedId && storedAddr) {
    return { appId: parseInt(storedId, 10), appAddress: storedAddr }
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

// Per-denomination pool contracts
export const POOL_CONTRACTS: Record<string, { appId: number; appAddress: string }> = {
  '100000': { appId: 756420118, appAddress: 'DOIY26VVBDURORVRC52UHGXUFCZ2FB725T3YNDJJOIM2BQTQFDGO75XBTQ' },
  '500000': { appId: 756420130, appAddress: 'W2IBUIN32FL7JIHTDVDFDVG6F4HHWP4X2CJRDVFBKC6Y7MVJ22INRVGEIY' },
  '1000000': { appId: 756420132, appAddress: 'O3I26T6EZ2UCCSWHQGMD6R5XJUX2AK3DU5I7S76M2SA2AE63IFZFUMPKEU' },
}

/** Get pool config for a specific tier (microAlgos) */
export function getPoolForTier(microAlgos: bigint): { appId: number; appAddress: string } {
  const pool = POOL_CONTRACTS[microAlgos.toString()]
  if (!pool) throw new Error(`No pool configured for denomination ${microAlgos} microAlgos`)
  return pool
}

// Relayer configuration (set RELAYER_URL to enable relayed withdrawals)
export const RELAYER_URL = 'https://privacy-pool-relayer.mitchhall16.workers.dev'
export const RELAYER_ADDRESS = 'MCH3ZDYI6NEP2EFGZVLOH7BZH6ZEUYBZWERNJT7JGYK4GMUJDL6TLHZTIA'
export const RELAYER_FEE = 250_000n // 0.25 ALGO — covers verifier gas + margin

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

// Batch window interval (minutes). Deposits snap to :00, :15, :30, :45
export const BATCH_WINDOW_MINUTES = 15

// Treasury address for protocol fees
export const TREASURY_ADDRESS = '' // Set before deployment

// Protocol fee per operation (microAlgos)
export const PROTOCOL_FEE = 5_000n // 0.005 ALGO

// Pool operations since note creation before suggesting churn
export const STALE_NOTE_THRESHOLD = 20

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
    withdraw: undefined,  // Set after compiling PLONK verifier
    deposit: undefined,
    privateSend: undefined,
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
