import { useState, useCallback, Component, type ReactNode } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { StatusBar } from './components/StatusBar'
import { PoolBlob } from './components/PoolBlob'
import { TransactionFlow } from './components/TransactionFlow'
import { ToastContainer } from './components/ToastContainer'
import { usePoolState } from './hooks/usePoolState'
import { HowItWorks } from './components/HowItWorks'

// Error boundary — catches render errors and shows fallback UI
class ErrorBoundary extends Component<{ children: ReactNode }, { hasError: boolean }> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('Uncaught render error:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          gap: '16px',
          color: 'var(--text-primary)',
          fontFamily: 'var(--font-body)',
        }}>
          <h1 style={{ fontSize: '20px', fontWeight: 500 }}>Something went wrong</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
            An unexpected error occurred. Please refresh the page.
          </p>
          <button
            onClick={() => window.location.reload()}
            style={{
              padding: '8px 20px',
              borderRadius: '8px',
              background: 'var(--accent)',
              color: '#000',
              fontWeight: 500,
              fontSize: '14px',
              cursor: 'pointer',
              border: 'none',
            }}
          >
            Refresh
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

export function App() {
  const { activeAddress } = useWallet()
  const pool = usePoolState()
  const [depositAnim, setDepositAnim] = useState(false)
  const [withdrawAnim, setWithdrawAnim] = useState(false)
  const [showHowItWorks, setShowHowItWorks] = useState(false)

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
  }, [pool.refresh])

  return (
    <ErrorBoundary>
      {/* Background blob — full screen, atmospheric */}
      <div className="blob-bg">
        <PoolBlob
          poolBalance={pool.totalDeposited}
          onDeposit={depositAnim}
          onWithdraw={withdrawAnim}
        />
      </div>

      <div className="status-bar">
        <StatusBar />
      </div>

      <div className="app-centered">
        {/* Pool stats bar */}
        <div className="pool-stats-bar">
          {activeAddress && pool.userBalance > 0 && (
            <div className="pool-stat">
              <span className="pool-stat__label">Your Balance</span>
              <span className="pool-stat__value pool-stat__value--accent">{pool.userBalance.toFixed(3)} ALGO</span>
            </div>
          )}
          <div className="pool-stat">
            <span className="pool-stat__label">Pool Balance</span>
            <span className="pool-stat__value">{pool.totalDeposited.toFixed(3)} ALGO</span>
          </div>
        </div>

        {/* Centered transaction panel */}
        <div className="app-panel">
          {activeAddress ? (
            <TransactionFlow
              onDeposit={handleDeposit}
              onWithdraw={handleWithdraw}
              onComplete={handleComplete}
              walletBalance={pool.walletBalance}
            />
          ) : (
            <div className="app-hero">
              <h1 className="app-hero__title">Private transactions on Algorand</h1>
              <p className="app-hero__desc">
                Deposit ALGO into a shared pool, withdraw to any address. Zero-knowledge proofs guarantee your deposit without revealing which one is yours.
              </p>
              <div className="app-hero__steps">
                <div className="app-hero__step">
                  <span className="app-hero__step-num">1</span>
                  <span>Deposit ALGO into the pool</span>
                </div>
                <div className="app-hero__step">
                  <span className="app-hero__step-num">2</span>
                  <span>Wait for others to deposit</span>
                </div>
                <div className="app-hero__step">
                  <span className="app-hero__step-num">3</span>
                  <span>Withdraw to any address — unlinkable</span>
                </div>
              </div>
              <p className="app-hero__connect-hint">Connect your wallet to get started</p>
            </div>
          )}
        </div>
      </div>

      {/* How it Works — fixed bottom-left */}
      <button className="hiw-trigger" onClick={() => setShowHowItWorks(true)}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
        How it Works
      </button>
      <HowItWorks open={showHowItWorks} onClose={() => setShowHowItWorks(false)} />

      <ToastContainer />
    </ErrorBoundary>
  )
}
