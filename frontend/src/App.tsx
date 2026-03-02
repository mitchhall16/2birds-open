import { useState, useCallback } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { StatusBar } from './components/StatusBar'
import { PoolBlob } from './components/PoolBlob'
import { TransactionFlow } from './components/TransactionFlow'
import { ToastContainer } from './components/ToastContainer'
import { usePoolState } from './hooks/usePoolState'
import { useDeploy } from './hooks/useDeploy'

export function App() {
  const { activeAddress } = useWallet()
  const pool = usePoolState()
  const deployer = useDeploy()
  const [depositAnim, setDepositAnim] = useState(false)
  const [withdrawAnim, setWithdrawAnim] = useState(false)

  // Contracts are already deployed — hardcoded in config.ts
  const needsDeploy = false

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

      {/* Balances — bottom right */}
      <div className="pool-badges">
        {pool.userBalance > 0 && (
          <div className="pool-badge pool-badge--user">
            <span className="pool-badge__label">Your Balance</span>
            <span className="pool-badge__value">{pool.userBalance.toFixed(3)} ALGO</span>
          </div>
        )}
        <div className="pool-badge">
          <span className="pool-badge__label">Pool Balance</span>
          <span className="pool-badge__value">{pool.totalDeposited.toFixed(3)} ALGO</span>
        </div>
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
            walletBalance={pool.walletBalance}
          />
        </div>
      )}

      <ToastContainer />
    </>
  )
}
