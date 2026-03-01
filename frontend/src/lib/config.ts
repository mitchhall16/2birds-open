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

const DEFAULT_POOL_APP_ID = 756343976
const DEFAULT_POOL_APP_ADDRESS = '5MQPZZ3B56TL5724W2SJAGIY6BSJUBD4HFSUVXIL7NZI3LNNBCVF73TTLE'

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
    appId: 756343974,
    appAddress: 'LLAKWAU47I5EFCPLJMIV2M74OYGXWY6EQYLYSZLPVZOTZVWFYBIVHW7UTI',
  },
  get PrivacyPool() { return getPoolConfig() },
  ShieldedPool: {
    appId: 756343978,
    appAddress: 'NJ3ZQNXFSKPUUFO4MSA26NKPDJVB3BGMA5ENIT2ZT6HT24GKJR374ERJDE',
  },
  ConfidentialAsset: {
    appId: 756343979,
    appAddress: '5SBTJCUQAVAIZ4OZNLWCPVSQLY6JZGU7V4P6L5BBZGN4WGXYEFPC5LZFYI',
  },
} as const

// Fixed denomination: 1 ALGO = 1_000_000 microAlgos
export const POOL_DENOMINATION = 1_000_000n

// Fee estimates (in microAlgos) — network fees paid by sender, not deducted from transfer
export const FEES = {
  deposit: 2_000n, // 0.002 ALGO — payment (0.001) + app call (0.001), only 3 box refs
  withdraw: 9_000n, // 0.009 ALGO — fund LogicSig (0.001) + LogicSig verifier (0.006) + app call (0.002)
  minBalance: 100_000n, // 0.1 ALGO minimum balance
}

export const EXPLORER_BASE = 'https://testnet.explorer.perawallet.app'

export function txnUrl(txId: string): string {
  return `${EXPLORER_BASE}/tx/${txId}`
}

export function addrUrl(addr: string): string {
  return `${EXPLORER_BASE}/address/${addr}`
}
