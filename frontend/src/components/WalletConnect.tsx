import { useState, useRef, useEffect } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'

function truncateAddr(addr: string): string {
  return `${addr.slice(0, 4)}...${addr.slice(-4)}`
}

export function WalletConnect({ walletBalance }: { walletBalance?: number }) {
  const { wallets, activeWallet, activeAddress, activeAccount } = useWallet()
  const [showModal, setShowModal] = useState(false)
  const [showDropdown, setShowDropdown] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setShowDropdown(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  async function handleConnect(walletId: string) {
    const wallet = wallets.find((w) => w.id === walletId)
    if (wallet) {
      try {
        await wallet.connect()
        setShowModal(false)
      } catch (err) {
        console.error('Failed to connect:', err)
      }
    }
  }

  async function handleDisconnect() {
    if (activeWallet) {
      await activeWallet.disconnect()
      setShowDropdown(false)
    }
  }

  // Not connected — show connect button
  if (!activeAddress) {
    return (
      <div className="wallet-connect">
        <button
          className="wallet-btn wallet-btn--connect"
          onClick={() => setShowModal(true)}
        >
          Connect Wallet
        </button>

        {showModal && (
          <div className="wallet-modal-overlay" onClick={() => setShowModal(false)}>
            <div className="wallet-modal" onClick={(e) => e.stopPropagation()}>
              <div className="wallet-modal__title">Connect Wallet</div>
              <div className="wallet-modal__list">
                {wallets.map((wallet) => (
                  <button
                    key={wallet.id}
                    className="wallet-modal__option"
                    onClick={() => handleConnect(wallet.id)}
                  >
                    {wallet.metadata.icon && (
                      <img src={wallet.metadata.icon} alt={wallet.metadata.name} />
                    )}
                    {wallet.metadata.name}
                  </button>
                ))}
              </div>
              <button
                className="wallet-modal__close"
                onClick={() => setShowModal(false)}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    )
  }

  // Connected — show address + dropdown
  return (
    <div className="wallet-connect" ref={dropdownRef}>
      <button
        className="wallet-btn wallet-btn--connected"
        onClick={() => setShowDropdown(!showDropdown)}
      >
        <span className="wallet-btn__dot" />
        <span className="wallet-btn__address">{truncateAddr(activeAddress)}</span>
        {walletBalance !== undefined && (
          <span className="wallet-btn__balance">{walletBalance.toFixed(3)}</span>
        )}
      </button>

      {showDropdown && (
        <div className="wallet-dropdown">
          <div className="wallet-dropdown__item" style={{ cursor: 'default' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: 11, fontWeight: 200, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              {activeWallet?.metadata.name}
            </span>
          </div>
          <div className="wallet-dropdown__item" style={{ cursor: 'default' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
              {activeAddress}
            </span>
          </div>
          {activeWallet && wallets.length > 1 && (
            <>
              <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />
              {wallets
                .filter((w) => w.id !== activeWallet.id)
                .map((w) => (
                  <button
                    key={w.id}
                    className="wallet-dropdown__item"
                    onClick={async () => {
                      await activeWallet.disconnect()
                      await w.connect()
                      setShowDropdown(false)
                    }}
                  >
                    Switch to {w.metadata.name}
                  </button>
                ))}
            </>
          )}
          <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />
          <button
            className="wallet-dropdown__item wallet-dropdown__item--danger"
            onClick={handleDisconnect}
          >
            Disconnect
          </button>
        </div>
      )}
    </div>
  )
}
