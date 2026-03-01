import { useState, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { StatusBar } from './components/StatusBar'
import { PoolBlob } from './components/PoolBlob'
import { TransactionFlow } from './components/TransactionFlow'
import { usePoolState } from './hooks/usePoolState'
import { useDeploy } from './hooks/useDeploy'

export function App() {
  const { activeAddress } = useWallet()
  const pool = usePoolState()
  const deployer = useDeploy()
  const [depositAnim, setDepositAnim] = useState(false)
  const [withdrawAnim, setWithdrawAnim] = useState(false)

  const needsDeploy = !localStorage.getItem('privacy_pool_app_id')

  const handleDeposit = useCallback(() => {
    setDepositAnim(true)
    setTimeout(() => setDepositAnim(false), 2000)
  }, [])

  const handleWithdraw = useCallback(() => {
    setWithdrawAnim(true)
    setTimeout(() => setWithdrawAnim(false), 2000)
  }, [])

  const handleComplete = useCallback(() => {
    pool.refresh()
  }, [pool])

  return (
    <>
      <div className="status-bar">
        <StatusBar />
      </div>

      {/* Blob — full viewport background */}
      <div className="blob-fullscreen">
        <PoolBlob
          poolBalance={pool.totalDeposited}
          onDeposit={depositAnim}
          onWithdraw={withdrawAnim}
        />
      </div>

      {/* Pool balance — bottom right */}
      <div className="pool-badge">
        <span className="pool-badge__label">Pool Balance</span>
        <span className="pool-badge__value">{pool.totalDeposited.toFixed(3)} ALGO</span>
      </div>

      {/* Deploy banner */}
      {activeAddress && needsDeploy && !deployer.appId && (
        <div className="deploy-banner">
          <span>New contract needs deployment</span>
          <button
            className="deploy-banner__btn"
            onClick={deployer.deploy}
            disabled={deployer.deploying}
          >
            {deployer.deploying ? 'Deploying...' : 'Deploy'}
          </button>
          {deployer.error && <span className="deploy-banner__error">{deployer.error}</span>}
        </div>
      )}

      {deployer.appId && needsDeploy && (
        <div className="deploy-banner deploy-banner--success">
          Deployed! App ID: {deployer.appId} — Refresh the page to use it.
        </div>
      )}

      {/* Transaction panel — top left */}
      {activeAddress && (
        <div className="tx-panel">
          <TransactionFlow
            onDeposit={handleDeposit}
            onWithdraw={handleWithdraw}
            onComplete={handleComplete}
          />
        </div>
      )}
    </>
  )
}
