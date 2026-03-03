import { useState, useEffect, useRef } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { useTransaction, type TxStage } from '../hooks/useTransaction'
import { CostBreakdown } from './CostBreakdown'
import { txnUrl, DENOMINATION_TIERS, type DenominationTier, SUBSIDY_TIERS, TREASURY_ADDRESS } from '../lib/config'
import { loadNotes, removeNote, deriveMasterKey, deriveMasterKeyFromPassword, getCachedMasterKey, recoverNotes, initMimc, PasswordRequiredError, hasPasswordKey, type DepositNote } from '../lib/privacy'
import { PasswordModal } from './PasswordModal'
import { NoteBackup } from './NoteBackup'
import { ALGOD_CONFIG, POOL_CONTRACTS } from '../lib/config'
import { isPrivacyAddress } from '../lib/address'
import { privacyAddressFromWallet } from '../lib/address'
import algosdk from 'algosdk'

interface TransactionFlowProps {
  onDeposit: () => void
  onWithdraw: () => void
  onComplete: () => void
  walletBalance?: number
}

type Tab = 'deposit' | 'send' | 'manage' | 'convert'

export function TransactionFlow({ onDeposit, onWithdraw, onComplete, walletBalance }: TransactionFlowProps) {
  const { activeAddress, signData, algodClient } = useWallet()
  const tx = useTransaction()
  const [tab, setTab] = useState<Tab>('deposit')
  const [selectedTier, setSelectedTier] = useState<DenominationTier>(DENOMINATION_TIERS[2]) // default 1.0 ALGO
  const [destination, setDestination] = useState('')
  const [notes, setNotes] = useState<DepositNote[]>([])
  const [sendingIdx, setSendingIdx] = useState<number | null>(null)
  const [manageDestination, setManageDestination] = useState('')
  const [recovering, setRecovering] = useState(false)
  const [recoveryResult, setRecoveryResult] = useState<{ recovered: number; total: number; spent: number } | null>(null)
  const [rebuildingTrees, setRebuildingTrees] = useState(false)
  const [confirmDeleteIdx, setConfirmDeleteIdx] = useState<number | null>(null)
  const [rebuildProgress, setRebuildProgress] = useState('')
  const [showPasswordModal, setShowPasswordModal] = useState(false)
  const [pendingAction, setPendingAction] = useState<(() => Promise<void>) | null>(null)
  const [passwordError, setPasswordError] = useState('')
  const [privacyAcknowledged, setPrivacyAcknowledged] = useState(false)
  const [selectedSubsidy, setSelectedSubsidy] = useState<bigint>(0n)
  const prevStage = useRef<TxStage>('idle')

  // Load notes, treasury balance, and pool indices on mount
  useEffect(() => { loadNotes().then(setNotes).catch(console.error) }, [])
  useEffect(() => { tx.refreshTreasuryBalance().catch(console.error) }, [])
  useEffect(() => { tx.refreshStaleNotes().catch(console.error) }, []) // also populates poolNextIndices

  const [scanningChain, setScanningChain] = useState(false)
  const [scanResult, setScanResult] = useState<{ recovered: number; newNotes: number } | null>(null)
  const [privacyAddress, setPrivacyAddress] = useState<string | null>(null)

  // Derive privacy address when wallet is connected
  useEffect(() => {
    if (!activeAddress) { setPrivacyAddress(null); return }
    getCachedMasterKey().then(mk => {
      if (mk) setPrivacyAddress(privacyAddressFromWallet(activeAddress, mk))
    }).catch(() => {})
  }, [activeAddress])

  // Refresh stale notes when switching to manage tab
  useEffect(() => {
    if (tab === 'manage' && activeAddress) {
      tx.refreshStaleNotes().catch(console.error)
    }
  }, [tab, activeAddress])

  const tierAmount = Number(selectedTier.microAlgos) / 1_000_000
  const isValidDest = destination.length > 0 && (algosdk.isValidAddress(destination) || isPrivacyAddress(destination))
  const isValidManageDest = manageDestination.length > 0 && algosdk.isValidAddress(manageDestination)

  const isIdle = tx.stage === 'idle' || tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete'
  const canDeposit = !!activeAddress && isIdle
  const canSend = !!activeAddress && isValidDest && isIdle && privacyAcknowledged

  async function refreshNotes() {
    setNotes(await loadNotes())
  }

  useEffect(() => {
    const prev = prevStage.current
    prevStage.current = tx.stage
    if (tx.stage === 'deposit_complete' && prev !== 'deposit_complete') onDeposit()
    if (tx.stage === 'withdraw_complete' && prev !== 'withdraw_complete') onWithdraw()
    if ((tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete') && prev !== tx.stage) {
      onComplete()
      refreshNotes()
    }
  }, [tx.stage, onDeposit, onWithdraw, onComplete])

  /** Wrap an async action: if it throws PasswordRequiredError, show modal and retry on password entry */
  async function withPasswordFallback(action: () => Promise<void>) {
    try {
      await action()
    } catch (err) {
      if (err instanceof PasswordRequiredError) {
        setPendingAction(() => action)
        setShowPasswordModal(true)
        setPasswordError('')
      } else {
        throw err
      }
    }
  }

  async function handlePasswordSubmit(password: string) {
    try {
      await deriveMasterKeyFromPassword(password)
      setShowPasswordModal(false)
      setPasswordError('')
      // Retry the pending action now that master key is cached
      if (pendingAction) {
        const action = pendingAction
        setPendingAction(null)
        await action()
      }
    } catch (err: any) {
      setPasswordError(err?.message || 'Failed to derive key')
    }
  }

  function handlePasswordCancel() {
    setShowPasswordModal(false)
    setPendingAction(null)
    setPasswordError('')
  }

  async function handleDeposit() {
    if (!canDeposit) return
    await withPasswordFallback(() => tx.deposit(selectedTier.microAlgos, false, selectedSubsidy))
  }

  async function handleSend() {
    if (!canSend) return
    await withPasswordFallback(() => tx.privateSend(selectedTier.microAlgos, destination, false, selectedSubsidy))
  }

  async function handleManageSend(noteCommitment: bigint) {
    if (!isValidManageDest || !activeAddress) return
    setSendingIdx(null)
    await withPasswordFallback(async () => {
      await tx.withdraw(noteCommitment, manageDestination)
      setManageDestination('')
      refreshNotes()
    })
  }

  async function handleDelete(idx: number) {
    await removeNote(idx)
    setConfirmDeleteIdx(null)
    await refreshNotes()
  }

  function handleReset() {
    tx.reset()
    refreshNotes()
  }

  async function handleRecover() {
    if (recovering) return
    setRecovering(true)
    setRecoveryResult(null)
    try {
      await withPasswordFallback(async () => {
        await initMimc()
        const masterKey = await deriveMasterKey(signData)
        const client = algodClient ?? new algosdk.Algodv2(
          ALGOD_CONFIG.token,
          ALGOD_CONFIG.baseServer,
          ALGOD_CONFIG.port,
        )
        const result = await recoverNotes(masterKey, client)
        setRecoveryResult({ recovered: result.recovered.length, total: result.total, spent: result.spent })
        refreshNotes()
      })
    } catch (err) {
      console.error('Recovery failed:', err)
      setRecoveryResult({ recovered: 0, total: 0, spent: 0 })
    } finally {
      setRecovering(false)
    }
  }

  async function handleChainScan() {
    if (scanningChain) return
    setScanningChain(true)
    setScanResult(null)
    try {
      await withPasswordFallback(async () => {
        await initMimc()
        await deriveMasterKey(signData)
        const result = await tx.scanForNotes()
        setScanResult(result)
        refreshNotes()
      })
    } catch (err) {
      console.error('Chain scan failed:', err)
      setScanResult({ recovered: 0, newNotes: 0 })
    } finally {
      setScanningChain(false)
    }
  }

  async function handleRebuildTrees() {
    if (rebuildingTrees) return
    setRebuildingTrees(true)
    setRebuildProgress('Starting...')
    try {
      await tx.rebuildAllTrees((pool, done) => {
        setRebuildProgress(done ? `${pool} done` : `Syncing ${pool}...`)
      })
      setRebuildProgress('All trees rebuilt')
    } catch (err) {
      console.error('Tree rebuild failed:', err)
      setRebuildProgress('Rebuild failed')
    } finally {
      setRebuildingTrees(false)
    }
  }

  const isProcessing = tx.stage === 'depositing' || tx.stage === 'withdrawing' || tx.stage === 'generating_proof' || tx.stage === 'waiting_batch'
  const isDone = tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete'
  const isIdleUI = !isProcessing && !isDone && tx.stage !== 'error'

  return (
    <div className="tx-flow reveal reveal-3">

      {/* Tabs — always visible */}
      <div className="tx-tab-bar">
        <button className={`tx-tab ${tab === 'deposit' ? 'tx-tab--active' : ''}`} onClick={() => { setTab('deposit'); setPrivacyAcknowledged(false) }}>
          Deposit
        </button>
        <button className={`tx-tab ${tab === 'send' ? 'tx-tab--active' : ''}`} onClick={() => { setTab('send'); setPrivacyAcknowledged(false) }}>
          Quick Send
        </button>
        <button className={`tx-tab ${tab === 'manage' ? 'tx-tab--active' : ''}`} onClick={() => { setTab('manage'); refreshNotes() }}>
          Manage{notes.length > 0 ? ` (${notes.length})` : ''}
        </button>
        <button className={`tx-tab ${tab === 'convert' ? 'tx-tab--active' : ''}`} onClick={() => setTab('convert')}>
          Convert
        </button>
      </div>

      {/* ── Deposit / Send tabs ── */}
      {(tab === 'deposit' || tab === 'send') && isIdleUI && (
        <>
          {/* Tier selector */}
          <div className="tx-field">
            <label className="tx-field__label">Amount</label>
            <div className="tx-tier-row">
              {DENOMINATION_TIERS.map(tier => (
                <button
                  key={tier.label}
                  className={`tx-tier-btn ${selectedTier.microAlgos === tier.microAlgos ? 'tx-tier-btn--active' : ''}`}
                  onClick={() => setSelectedTier(tier)}
                >
                  {tier.label} ALGO
                </button>
              ))}
            </div>
          </div>

          {/* Send: destination */}
          {tab === 'send' && (
            <>
              <div className="tx-field">
                <label className="tx-field__label">To</label>
                <input
                  className={`tx-field__input ${destination.length > 0 && !isValidDest ? 'tx-field__input--invalid' : ''}`}
                  type="text"
                  placeholder="priv1... address or Algorand address..."
                  value={destination}
                  onChange={(e) => setDestination(e.target.value.trim())}
                  spellCheck={false}
                />
                {destination.length > 0 && !isValidDest && (
                  <div className="tx-field__error">Invalid address (use priv1... or Algorand address)</div>
                )}
                {destination.length > 0 && isValidDest && isPrivacyAddress(destination) && (
                  <div className="tx-field__hint">Privacy address detected — note will be encrypted for recipient</div>
                )}
              </div>
              {tx.relayerAvailable && (
                <label className="tx-relayer-toggle">
                  <input
                    type="checkbox"
                    checked={tx.useRelayer}
                    onChange={e => tx.setUseRelayer(e.target.checked)}
                  />
                  <span>Use relayer (hides your wallet address, 0.25 ALGO fee)</span>
                </label>
              )}
              <div className="privacy-warning privacy-warning--strong">
                <strong>Reduced privacy:</strong> Quick Send deposits and withdraws in the same block, publicly linking both transactions on-chain. Your anonymity set is effectively zero.
                <br /><br />
                For maximum privacy, use{' '}
                <button className="tx-info-link" onClick={() => setTab('deposit')}>Deposit</button>{' '}
                first, wait for other pool activity, then withdraw from{' '}
                <button className="tx-info-link" onClick={() => setTab('manage')}>Manage</button>.
              </div>
              <label className="privacy-ack">
                <input
                  type="checkbox"
                  checked={privacyAcknowledged}
                  onChange={e => setPrivacyAcknowledged(e.target.checked)}
                />
                <span>I understand this trade-off: lower fees, reduced privacy</span>
              </label>
            </>
          )}

          {tab === 'deposit' && (
            <>
              <div className="tx-info-box">
                <strong>How it works:</strong> Depositing shields your ALGO in the privacy pool. To send it to another address later, go to <button className="tx-info-link" onClick={() => setTab('manage')}>Manage</button> and withdraw.
              </div>

              {/* Anonymity set indicator */}
              {tx.poolNextIndices.size > 0 && (
                <div className="anonymity-indicator">
                  <div className="anonymity-indicator__title">Pool Activity</div>
                  {DENOMINATION_TIERS.map(tier => {
                    const pool = POOL_CONTRACTS[tier.microAlgos.toString()]
                    if (!pool) return null
                    const count = tx.poolNextIndices.get(pool.appId) ?? 0
                    const level = count >= 50 ? 'good' : count >= 10 ? 'moderate' : 'low'
                    return (
                      <div key={tier.label} className="anonymity-indicator__row">
                        <span className="anonymity-indicator__tier">{tier.label} ALGO</span>
                        <span className="anonymity-indicator__count">{count} deposits</span>
                        <span className={`anonymity-indicator__level anonymity-indicator__level--${level}`}>
                          {level === 'good' ? 'Good privacy' : level === 'moderate' ? 'Moderate' : 'Low privacy'}
                        </span>
                      </div>
                    )
                  })}
                </div>
              )}
            </>
          )}

          {/* Subsidy selector — help grow the pool */}
          {!!TREASURY_ADDRESS && (
            <div className="subsidy-selector">
              <div className="subsidy-selector__label">
                {tx.subsidyActive
                  ? 'Protocol fee subsidized! Pay it forward?'
                  : 'Help grow the pool (optional)'}
              </div>
              <div className="subsidy-selector__row">
                <button
                  className={`subsidy-btn ${selectedSubsidy === 0n ? 'subsidy-btn--active' : ''}`}
                  onClick={() => setSelectedSubsidy(0n)}
                >
                  None
                </button>
                {SUBSIDY_TIERS.map(tier => (
                  <button
                    key={tier.label}
                    className={`subsidy-btn ${selectedSubsidy === tier.microAlgos ? 'subsidy-btn--active' : ''}`}
                    onClick={() => setSelectedSubsidy(tier.microAlgos)}
                  >
                    +{tier.label}
                  </button>
                ))}
              </div>
              {selectedSubsidy > 0n && (
                <div className="subsidy-selector__hint">
                  Reduces fees for the next user, attracting more deposits and strengthening privacy for everyone.
                </div>
              )}
            </div>
          )}

          <CostBreakdown
            amount={tierAmount}
            mode={tab === 'deposit' ? 'deposit' : 'send'}
            walletBalance={walletBalance}
            subsidyMicroAlgos={selectedSubsidy}
            subsidyActive={tx.subsidyActive}
          />

          <div className="tx-flow__spacer" />

          {tab === 'deposit' ? (
            <>
              <button
                className={`tx-execute ${canDeposit ? 'tx-execute--ready' : 'tx-execute--disabled'}`}
                onClick={handleDeposit}
                disabled={!canDeposit}
              >
                Deposit {selectedTier.label} ALGO
              </button>
              <div className="tx-info-box" style={{ marginTop: 14 }}>
                <strong>Refreshed or new device?</strong> Go to <button className="tx-info-link" onClick={() => setTab('manage')}>Manage</button> and tap <strong>Recover Notes</strong> to restore your deposits.
              </div>
            </>
          ) : (
            <button
              className={`tx-execute ${canSend ? 'tx-execute--ready' : 'tx-execute--disabled'}`}
              onClick={handleSend}
              disabled={!canSend}
            >
              {!isValidDest
                ? 'Enter destination'
                : `Send ${selectedTier.label} ALGO`}
            </button>
          )}
        </>
      )}

      {/* ── Manage tab ── */}
      {tab === 'manage' && isIdleUI && (
        <>
          {notes.length === 0 ? (
            <div className="manage-empty">No deposits yet</div>
          ) : (
            <>
              <div className="manage-list">
                {notes.map((note, i) => {
                  const noteAlgo = Number(note.denomination) / 1_000_000
                  return (
                    <div key={i} className="manage-note">
                      <div className="manage-note__info">
                        <span className="manage-note__amount">
                          {noteAlgo.toFixed(2)} ALGO
                        </span>
                        <span className="manage-note__date">
                          {new Date(note.timestamp).toLocaleDateString()} {new Date(note.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        </span>
                      </div>

                      {sendingIdx === i ? (
                        <div className="manage-note__send-form">
                          <input
                            className="tx-field__input"
                            type="text"
                            placeholder="Destination address..."
                            value={manageDestination}
                            onChange={e => setManageDestination(e.target.value.trim())}
                            spellCheck={false}
                            autoFocus
                          />
                          {tx.relayerAvailable && (
                            <label className="tx-relayer-toggle" style={{ marginTop: 6, marginBottom: 2 }}>
                              <input
                                type="checkbox"
                                checked={tx.useRelayer}
                                onChange={e => tx.setUseRelayer(e.target.checked)}
                              />
                              <span>Use relayer</span>
                            </label>
                          )}
                          {isValidManageDest && (
                            <CostBreakdown amount={noteAlgo} mode="withdraw" subsidyActive={tx.subsidyActive} />
                          )}
                          <div className="manage-note__actions">
                            <button
                              className="manage-btn manage-btn--send"
                              disabled={!isValidManageDest}
                              onClick={() => handleManageSend(note.commitment)}
                            >
                              Send
                            </button>
                            <button
                              className="manage-btn manage-btn--cancel"
                              onClick={() => { setSendingIdx(null); setManageDestination('') }}
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : confirmDeleteIdx === i ? (
                        <div className="manage-note__confirm-delete">
                          <span className="manage-note__confirm-text">Delete this note? You will lose access to these funds.</span>
                          <div className="manage-note__actions">
                            <button
                              className="manage-btn manage-btn--delete"
                              onClick={() => handleDelete(i)}
                            >
                              Delete
                            </button>
                            <button
                              className="manage-btn manage-btn--cancel"
                              onClick={() => setConfirmDeleteIdx(null)}
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="manage-note__actions">
                          <button
                            className="manage-btn manage-btn--send"
                            onClick={() => { setSendingIdx(i); setManageDestination('') }}
                          >
                            Send
                          </button>
                          <button
                            className="manage-btn manage-btn--delete-icon"
                            onClick={() => setConfirmDeleteIdx(i)}
                            title="Delete note"
                          >
                            ×
                          </button>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </>
          )}

          {/* Churn prompt for stale notes */}
          {tx.staleNotes.length > 0 && (
            <div className="churn-prompt">
              <div className="churn-prompt__title">Privacy refresh recommended</div>
              <div className="churn-prompt__body">
                {tx.staleNotes.length} note{tx.staleNotes.length > 1 ? 's' : ''} sitting
                idle while pool activity continued. Churn to refresh position.
              </div>
              <button
                className="manage-btn manage-btn--recover"
                onClick={() => {
                  withPasswordFallback(() => tx.churnNote(tx.staleNotes[0]))
                }}
                disabled={isProcessing}
              >
                Churn oldest note
              </button>
            </div>
          )}

          {/* Privacy address display */}
          {privacyAddress && (
            <div className="manage-privacy-address">
              <div className="manage-privacy-address__label">Your Privacy Address</div>
              <div className="manage-privacy-address__value" title={privacyAddress}>
                {privacyAddress.slice(0, 20)}...{privacyAddress.slice(-8)}
              </div>
              <button
                className="manage-btn manage-btn--copy"
                onClick={() => { navigator.clipboard.writeText(privacyAddress); }}
              >
                Copy
              </button>
              <div className="manage-privacy-address__hint">
                Share this address to receive private transfers with encrypted notes.
              </div>
            </div>
          )}

          {/* Note backup */}
          <NoteBackup notes={notes} onImport={refreshNotes} />

          <div className="manage-recovery-section">
            <div className="manage-recovery-section__header">Recovery</div>
            <div className="manage-recovery-section__desc">
              New device, cleared browser data, or refreshed the page? Use these tools to restore your deposits.
            </div>

            <div className="manage-recovery-item">
              <button
                className={`manage-btn manage-btn--recover ${recovering ? 'manage-btn--loading' : ''}`}
                onClick={handleRecover}
                disabled={recovering || !activeAddress}
                style={{ width: '100%' }}
              >
                {recovering ? 'Scanning chain...' : 'Recover Notes'}
              </button>
              <div className="manage-recovery-item__desc">
                Scans the blockchain for your deposits using your wallet key. Run this first on a new device.
              </div>
            </div>
            {recoveryResult && (
              <div className="manage-recovery-result">
                {recoveryResult.recovered > 0
                  ? `Found ${recoveryResult.recovered} note${recoveryResult.recovered > 1 ? 's' : ''} (${recoveryResult.spent} spent)`
                  : recoveryResult.total > 0
                    ? `All ${recoveryResult.total} deposits already accounted for`
                    : 'No deposits found for this wallet'}
              </div>
            )}

            <div className="manage-recovery-item">
              <button
                className={`manage-btn manage-btn--recover ${scanningChain ? 'manage-btn--loading' : ''}`}
                onClick={handleChainScan}
                disabled={scanningChain || !activeAddress}
                style={{ width: '100%' }}
              >
                {scanningChain ? 'Scanning encrypted notes...' : 'Scan Chain (HPKE)'}
              </button>
              <div className="manage-recovery-item__desc">
                Scans on-chain transaction notes for HPKE-encrypted deposits sent to your view key.
              </div>
            </div>
            {scanResult && (
              <div className="manage-recovery-result">
                {scanResult.newNotes > 0
                  ? `Found ${scanResult.newNotes} new encrypted note${scanResult.newNotes > 1 ? 's' : ''} (${scanResult.recovered} total on-chain)`
                  : scanResult.recovered > 0
                    ? `All ${scanResult.recovered} on-chain notes already imported`
                    : 'No encrypted notes found for your view key'}
              </div>
            )}

            <div className="manage-recovery-item">
              <button
                className={`manage-btn manage-btn--recover ${rebuildingTrees ? 'manage-btn--loading' : ''}`}
                onClick={handleRebuildTrees}
                disabled={rebuildingTrees}
                style={{ width: '100%' }}
              >
                {rebuildingTrees ? rebuildProgress : 'Rebuild Trees from Chain'}
              </button>
              <div className="manage-recovery-item__desc">
                Re-syncs the Merkle trees from on-chain data. Needed if withdrawals fail with a root mismatch error.
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Convert tab (split/combine) ── */}
      {tab === 'convert' && isIdleUI && (
        <div className="tx-convert-section">
          <div className="tx-info-box">
            <strong>Split &amp; Combine</strong> — Convert between denomination tiers across pools.
            Split breaks a larger note into two smaller ones. Combine merges two smaller notes into one larger note.
          </div>
          <div className="tx-convert-grid">
            <div className="tx-convert-card">
              <div className="tx-convert-card__title">Split</div>
              <div className="tx-convert-card__desc">1.0 ALGO → 2 × 0.5 ALGO</div>
              <div className="tx-convert-card__desc">0.5 ALGO → 5 × 0.1 ALGO (future)</div>
              <button className="manage-btn manage-btn--recover" disabled style={{ width: '100%', marginTop: 12 }}>
                Coming Soon
              </button>
              <div className="tx-convert-card__note">Requires split circuit deployment</div>
            </div>
            <div className="tx-convert-card">
              <div className="tx-convert-card__title">Combine</div>
              <div className="tx-convert-card__desc">2 × 0.5 ALGO → 1.0 ALGO</div>
              <div className="tx-convert-card__desc">5 × 0.1 ALGO → 0.5 ALGO (future)</div>
              <button className="manage-btn manage-btn--recover" disabled style={{ width: '100%', marginTop: 12 }}>
                Coming Soon
              </button>
              <div className="tx-convert-card__note">Requires combine circuit deployment</div>
            </div>
          </div>
        </div>
      )}

      {/* ── In-progress (shared across all tabs) ── */}
      {isProcessing && (
        <div className="tx-status">
          <div className="tx-status__text">{tx.message}</div>
          {tx.stage === 'waiting_batch' && tx.batchCountdown && (
            <div className="batch-countdown">
              <div className="batch-countdown__time">{tx.batchCountdown}</div>
              <div className="batch-countdown__label">until next batch window</div>
              <button
                className="batch-countdown__skip"
                onClick={() => tx.skipBatchWait()}
              >
                Skip (reduced privacy)
              </button>
            </div>
          )}
          {tx.stage === 'generating_proof' && (
            <div className="tx-proof-progress">
              <div className="tx-proof-progress__bar">
                <div className="tx-proof-progress__fill" />
              </div>
              <div className="tx-proof-progress__label">Generating ZK proof</div>
            </div>
          )}
          {tx.txId && (
            <a className="tx-status__txid" href={txnUrl(tx.txId)} target="_blank" rel="noopener noreferrer">
              {tx.txId.slice(0, 12)}...
            </a>
          )}
          <button className="tx-execute tx-execute--loading" disabled style={{ marginTop: 20 }}>
            {tx.stage === 'waiting_batch' ? 'Waiting...' : tx.stage === 'depositing' ? 'Depositing...' : tx.stage === 'generating_proof' ? 'Proving...' : 'Sending...'}
          </button>
        </div>
      )}

      {/* Complete */}
      {isDone && (
        <div className="tx-status">
          <div className="tx-status__text">
            <strong>{tx.stage === 'deposit_complete' ? 'Deposit confirmed.' : 'Transfer complete.'}</strong>
            <br />
            {tx.message}
          </div>
          {tx.txId && (
            <div>
              <a className="tx-status__txid" href={txnUrl(tx.txId)} target="_blank" rel="noopener noreferrer">
                TX: {tx.txId.slice(0, 16)}...
              </a>
            </div>
          )}
          <button className="tx-execute tx-execute--ready" style={{ marginTop: 24 }} onClick={handleReset}>
            Done
          </button>
        </div>
      )}

      {/* Error */}
      {tx.stage === 'error' && (
        <div className="tx-status">
          <div className="tx-status__text" style={{ color: 'var(--danger)' }}>
            {tx.error}
          </div>
          <button className="tx-execute tx-execute--ready" style={{ marginTop: 20 }} onClick={handleReset}>
            Try Again
          </button>
        </div>
      )}

      {/* Password modal for Pera / wallets without signData */}
      <PasswordModal
        open={showPasswordModal}
        mode={hasPasswordKey() ? 'unlock' : 'create'}
        onSubmit={handlePasswordSubmit}
        onCancel={handlePasswordCancel}
        externalError={passwordError}
      />
    </div>
  )
}
