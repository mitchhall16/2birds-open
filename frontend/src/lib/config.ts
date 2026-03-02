export const NETWORK = 'testnet' as const

export const ALGOD_CONFIG = {
  baseServer: 'https://testnet-api.algonode.cloud',
  port: '',
  token: '',
}

export const INDEXER_CONFIG = {
  baseServer: 'https://testnet-idx.algonode.cloud',
  port: '',
  token: '',
}

const DEFAULT_POOL_APP_ID = 756386181
const DEFAULT_POOL_APP_ADDRESS = 'FMRABDCQUIZAVWTKIYAZEQZUWC6546MZZTOI2A3YG34PVY3SXBZH4NHQNY'

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
    appId: 756401238,
    budgetHelperAppId: 756401228,
  },
} as const

// Fixed denomination: 1 ALGO = 1_000_000 microAlgos
export const POOL_DENOMINATION = 1_000_000n

// Fee estimates (in microAlgos) — network fees paid by sender, not deducted from transfer
export const FEES = {
  deposit: 2_000n, // 0.002 ALGO — payment (0.001) + app call (0.001), only 3 box refs
  verifierCall: BigInt(228_000), // 0.228 ALGO — covers ~225 inner NoOp calls for opcode budget padding
  withdraw: 230_000n, // 0.230 ALGO — verifier app call (0.228) + pool app call (0.002)
  minBalance: 100_000n, // 0.1 ALGO minimum balance
}

export const EXPLORER_BASE = 'https://testnet.explorer.perawallet.app'

export function txnUrl(txId: string): string {
  return `${EXPLORER_BASE}/tx/${txId}`
}

export function addrUrl(addr: string): string {
  return `${EXPLORER_BASE}/address/${addr}`
}
