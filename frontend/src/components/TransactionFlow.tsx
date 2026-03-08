import { useState, useEffect, useRef } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { useToast } from '../contexts/ToastContext'
import { useTransaction, type TxStage } from '../hooks/useTransaction'
import { CostBreakdown } from './CostBreakdown'
import { txnUrl, DENOMINATION_TIERS, type DenominationTier, SUBSIDY_TIERS, TREASURY_ADDRESS } from '../lib/config'
import { loadNotes, removeNote, removeNoteByCommitment, deriveMasterKey, deriveMasterKeyFromPassword, getCachedMasterKey, clearMasterKey, recoverNotes, initMimc, PasswordRequiredError, hasPasswordKey, isNoteSpent, type DepositNote } from '../lib/privacy'
import { PasswordModal } from './PasswordModal'
import { NoteBackup } from './NoteBackup'
import { ALGOD_CONFIG, POOL_CONTRACTS } from '../lib/config'
import { isPrivacyAddress } from '../lib/address'
import { privacyAddressFromWallet } from '../lib/address'
import { useFalcon } from '../contexts/FalconContext'
import { sweepFalconToWallet } from '../lib/falcon'
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
  const { addToast } = useToast()
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
  const [splitNote, setSplitNote] = useState<bigint | null>(null)
  const [combineNote1, setCombineNote1] = useState<bigint | null>(null)
  const [combineNote2, setCombineNote2] = useState<bigint | null>(null)
  const prevStage = useRef<TxStage>('idle')

  // Load notes, treasury balance, and pool indices on mount
  useEffect(() => { loadNotes().then(setNotes).catch(console.error) }, [])
  useEffect(() => { tx.refreshTreasuryBalance().catch(console.error) }, [])
  useEffect(() => { tx.refreshStaleNotes().catch(console.error) }, []) // also populates poolNextIndices

  const [scanningChain, setScanningChain] = useState(false)
  const [scanResult, setScanResult] = useState<{ recovered: number; newNotes: number } | null>(null)
  const [privacyAddress, setPrivacyAddress] = useState<string | null>(null)

  // Falcon post-quantum mode
  const falcon = useFalcon()
  const [sweeping, setSweeping] = useState(false)

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

  // Clear master key from memory when user leaves the tab (XSS mitigation)
  useEffect(() => {
    function handleVisibility() {
      if (document.hidden) clearMasterKey()
    }
    document.addEventListener('visibilitychange', handleVisibility)
    return () => document.removeEventListener('visibilitychange', handleVisibility)
  }, [])

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
      if (err instanceof PasswordRequiredError || (err as any)?.name === 'PasswordRequiredError') {
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
    } catch (err: any) {
      setPasswordError(err?.message || 'Failed to derive key')
      return
    }
    setShowPasswordModal(false)
    setPasswordError('')
    // Retry the pending action now that master key is cached
    if (pendingAction) {
      const action = pendingAction
      setPendingAction(null)
      try {
        await action()
      } catch (err: any) {
        // Deposit/withdraw handle their own errors via toast + state,
        // but if something unexpected escapes, show it
        console.error('Action failed after password:', err)
        addToast('error', err?.message || 'Operation failed')
      }
    }
  }

  function handlePasswordCancel() {
    setShowPasswordModal(false)
    setPendingAction(null)
    setPasswordError('')
    tx.reset()
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
        <button className={`tx-tab ${tab === 'convert' ? 'tx-tab--active' : ''}`} onClick={() => { setTab('convert'); refreshNotes() }}>
          Convert
        </button>
      </div>

      {/* Falcon funding banner — shown when quantum-safe mode is enabled but address has no funds */}
      {falcon.enabled && falcon.account && !falcon.funded && isIdleUI && (
        <div className="tx-info-box" style={{ borderColor: 'var(--accent)', marginBottom: 16 }}>
          <strong>Quantum-Safe Mode Active</strong>
          <br />
          Fund your Falcon address to start using post-quantum signing.
          <div style={{ fontFamily: 'monospace', fontSize: 11, marginTop: 8, wordBreak: 'break-all', color: 'var(--text-secondary)' }}>
            {falcon.account.address}
          </div>
          <button
            className="manage-btn manage-btn--copy"
            style={{ marginTop: 8 }}
            onClick={() => {
              navigator.clipboard.writeText(falcon.account!.address)
              addToast('success', 'Falcon address copied')
            }}
          >
            Copy Address
          </button>
        </div>
      )}

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
              <div className="privacy-warning privacy-warning--strong">
                <strong>Heads up:</strong> Quick Send deposits and withdraws in the same block — fast but less private. For best privacy, <button className="tx-info-link" onClick={() => setTab('deposit')}>Deposit</button> first, wait, then withdraw from <button className="tx-info-link" onClick={() => setTab('manage')}>Manage</button>.
              </div>
              <label className="privacy-ack">
                <input
                  type="checkbox"
                  checked={privacyAcknowledged}
                  onChange={e => setPrivacyAcknowledged(e.target.checked)}
                />
                <span>I understand — quick but less private</span>
              </label>
            </>
          )}

          {tab === 'deposit' && tx.poolNextIndices.size > 0 && (
            <div className="anonymity-indicator anonymity-indicator--compact">
              {DENOMINATION_TIERS.map(tier => {
                const pool = POOL_CONTRACTS[tier.microAlgos.toString()]
                if (!pool) return null
                const count = tx.poolNextIndices.get(pool.appId) ?? 0
                const level = count >= 50 ? 'good' : count >= 10 ? 'moderate' : 'low'
                return (
                  <div key={tier.label} className="anonymity-indicator__row">
                    <span className="anonymity-indicator__tier">{tier.label}</span>
                    <span className="anonymity-indicator__count">{count}</span>
                    <span className={`anonymity-indicator__level anonymity-indicator__level--${level}`}>
                      {level === 'good' ? 'Good' : level === 'moderate' ? 'OK' : 'Low'}
                    </span>
                  </div>
                )
              })}
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
              <button
                className={`tx-execute ${canDeposit ? 'tx-execute--ready' : 'tx-execute--disabled'}`}
                onClick={handleDeposit}
                disabled={!canDeposit}
              >
                Deposit {selectedTier.label} ALGO
              </button>
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
                          {isValidManageDest && (
                            <CostBreakdown amount={noteAlgo} mode="withdraw" subsidyActive={tx.subsidyActive} />
                          )}
                          {(() => {
                            const notePool = POOL_CONTRACTS[note.denomination.toString()]
                            const poolDeposits = notePool ? (tx.poolNextIndices.get(notePool.appId) ?? 0) : 0
                            return poolDeposits < 5 ? (
                              <div style={{ color: 'var(--danger)', fontSize: 12, marginBottom: 4 }}>
                                Pool has {poolDeposits} deposit{poolDeposits === 1 ? '' : 's'} — withdrawal blocked for privacy (need 5+)
                              </div>
                            ) : null
                          })()}
                          <div className="manage-note__actions">
                            <button
                              className="manage-btn manage-btn--send"
                              disabled={!isValidManageDest || (() => {
                                const notePool = POOL_CONTRACTS[note.denomination.toString()]
                                return notePool ? (tx.poolNextIndices.get(notePool.appId) ?? 0) < 5 : false
                              })()}
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

          {/* Privacy address — compact inline */}
          {privacyAddress && (
            <div className="manage-compact-row">
              <span className="manage-compact-row__label">Privacy Address</span>
              <span className="manage-compact-row__value" title={privacyAddress}>
                {privacyAddress.slice(0, 12)}...{privacyAddress.slice(-6)}
              </span>
              <button
                className="manage-btn manage-btn--copy"
                onClick={() => { navigator.clipboard.writeText(privacyAddress); addToast('success', 'Copied') }}
              >
                Copy
              </button>
            </div>
          )}

          {/* Collapsible: Backup & Recovery */}
          <details className="manage-collapsible">
            <summary className="manage-collapsible__summary">Backup & Recovery</summary>
            <div className="manage-collapsible__content">
              <NoteBackup notes={notes} onImport={refreshNotes} />

              <div style={{ marginTop: 12 }}>
                <button
                  className={`manage-btn manage-btn--recover ${recovering || scanningChain ? 'manage-btn--loading' : ''}`}
                  onClick={async () => {
                    await handleRecover()
                    await handleChainScan()
                  }}
                  disabled={recovering || scanningChain || !activeAddress}
                  style={{ width: '100%' }}
                >
                  {recovering || scanningChain ? 'Scanning chain...' : 'Recover Notes from Chain'}
                </button>
                {recoveryResult && (
                  <div className="manage-recovery-result">
                    {recoveryResult.recovered > 0
                      ? `Found ${recoveryResult.recovered} note${recoveryResult.recovered > 1 ? 's' : ''} (${recoveryResult.spent} spent)`
                      : recoveryResult.total > 0
                        ? `All ${recoveryResult.total} deposits already accounted for`
                        : 'No deposits found for this wallet'}
                  </div>
                )}
                {scanResult && (
                  <div className="manage-recovery-result">
                    {scanResult.newNotes > 0
                      ? `Found ${scanResult.newNotes} new encrypted note${scanResult.newNotes > 1 ? 's' : ''}`
                      : scanResult.recovered > 0
                        ? `All on-chain notes already imported`
                        : 'No encrypted notes found'}
                  </div>
                )}
              </div>

              <button
                className={`manage-btn manage-btn--recover ${rebuildingTrees ? 'manage-btn--loading' : ''}`}
                onClick={handleRebuildTrees}
                disabled={rebuildingTrees}
                style={{ width: '100%', marginTop: 8 }}
              >
                {rebuildingTrees ? rebuildProgress : 'Fix Withdrawal Errors'}
              </button>
            </div>
          </details>

          {/* Collapsible: Advanced */}
          <details className="manage-collapsible">
            <summary className="manage-collapsible__summary">Advanced</summary>
            <div className="manage-collapsible__content">
              {/* Falcon quantum-safe mode */}
              <label className="tx-relayer-toggle">
                <input
                  type="checkbox"
                  checked={falcon.enabled}
                  onChange={e => falcon.setEnabled(e.target.checked)}
                />
                <span>Falcon-1024 Post-Quantum Signing</span>
              </label>
              {falcon.enabled && falcon.loading && (
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 8 }}>
                  Deriving Falcon keypair...
                </div>
              )}
              {falcon.enabled && falcon.error && (
                <div style={{ fontSize: 12, color: 'var(--danger)', marginTop: 8 }}>
                  {falcon.error}
                </div>
              )}
              {falcon.enabled && falcon.account && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all', color: 'var(--text-primary)' }}>
                    {falcon.account.address}
                  </div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
                    <button
                      className="manage-btn manage-btn--copy"
                      onClick={() => {
                        navigator.clipboard.writeText(falcon.account!.address)
                        addToast('success', 'Falcon address copied')
                      }}
                    >
                      Copy
                    </button>
                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {(Number(falcon.balance) / 1_000_000).toFixed(3)} ALGO
                      {falcon.funded ? '' : ' (unfunded)'}
                    </span>
                    <button
                      className="manage-btn manage-btn--copy"
                      style={{ marginLeft: 'auto' }}
                      onClick={() => falcon.refresh()}
                    >
                      Refresh
                    </button>
                  </div>
                  {falcon.funded && (
                    <button
                      className="manage-btn manage-btn--cancel"
                      style={{ width: '100%', marginTop: 8 }}
                      disabled={sweeping}
                      onClick={async () => {
                        if (!activeAddress || !falcon.account) return
                        setSweeping(true)
                        try {
                          const client = algodClient ?? new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)
                          await sweepFalconToWallet(client, falcon.account, activeAddress)
                          addToast('success', 'Funds swept back to wallet')
                          await falcon.refresh()
                        } catch (err: any) {
                          addToast('error', err?.message || 'Sweep failed')
                        } finally {
                          setSweeping(false)
                        }
                      }}
                    >
                      {sweeping ? 'Sweeping...' : 'Sweep Funds to Wallet'}
                    </button>
                  )}
                </div>
              )}
            </div>
          </details>
        </>
      )}

      {/* ── Convert tab (split/combine) ── */}
      {tab === 'convert' && isIdleUI && (() => {
        const MIN_POOL_DEPOSITS_UI = 5
        const splittableNotes = notes.filter(n => {
          const half = n.denomination / 2n
          return DENOMINATION_TIERS.some(t => t.microAlgos === half)
        })
        const combinableNotes = notes.filter(n => {
          const doubled = n.denomination * 2n
          return DENOMINATION_TIERS.some(t => t.microAlgos === doubled)
        })
        // Group combinable notes by denomination for pairing
        const combinableDenoms = new Map<string, typeof combinableNotes>()
        for (const n of combinableNotes) {
          const key = n.denomination.toString()
          const arr = combinableDenoms.get(key) || []
          arr.push(n)
          combinableDenoms.set(key, arr)
        }
        // Only show denominations with 2+ notes
        const pairableDenoms = Array.from(combinableDenoms.entries()).filter(([, arr]) => arr.length >= 2)

        // Check pool sizes for split/combine eligibility
        const getPoolDeposits = (microAlgos: bigint) => {
          const pool = POOL_CONTRACTS[microAlgos.toString()]
          return pool ? (tx.poolNextIndices.get(pool.appId) ?? 0) : 0
        }
        const splitSourcePoolLow = splittableNotes.length > 0 && getPoolDeposits(splittableNotes[0].denomination) < MIN_POOL_DEPOSITS_UI
        const combineSourcePoolLow = pairableDenoms.length > 0 && getPoolDeposits(BigInt(pairableDenoms[0][0])) < MIN_POOL_DEPOSITS_UI

        return (
          <div className="tx-convert-section">
            <div className="tx-info-box">
              <strong>Split &amp; Combine</strong> — Convert between denomination tiers.
              Split breaks a larger note into two smaller ones. Combine merges two smaller notes into one larger note.
            </div>
            <div className="tx-convert-grid">
              {/* Split card */}
              <div className="tx-convert-card">
                <div className="tx-convert-card__title">Split</div>
                <div className="tx-convert-card__desc">1.0 ALGO → 2 × 0.5 ALGO</div>
                {splittableNotes.length > 0 ? (
                  <>
                    <select
                      className="tx-field__input"
                      style={{ marginTop: 8 }}
                      value={splitNote?.toString() ?? ''}
                      onChange={e => setSplitNote(e.target.value ? BigInt(e.target.value) : null)}
                    >
                      <option value="">Select a note to split...</option>
                      {splittableNotes.map((n, i) => (
                        <option key={i} value={n.commitment.toString()}>
                          {(Number(n.denomination) / 1_000_000).toFixed(1)} ALGO — {new Date(n.timestamp).toLocaleDateString()}
                        </option>
                      ))}
                    </select>
                    {splitNote !== null && (() => {
                      const note = splittableNotes.find(n => n.commitment === splitNote)
                      if (!note) return null
                      const srcAlgo = (Number(note.denomination) / 1_000_000).toFixed(1)
                      const dstAlgo = (Number(note.denomination / 2n) / 1_000_000).toFixed(1)
                      return (
                        <div className="tx-convert-card__preview">
                          {srcAlgo} ALGO → 2 × {dstAlgo} ALGO
                        </div>
                      )
                    })()}
                    {splitSourcePoolLow && (
                      <div style={{ color: 'var(--danger)', fontSize: 12, marginTop: 8 }}>
                        Pool has fewer than {MIN_POOL_DEPOSITS_UI} deposits — split blocked for privacy
                      </div>
                    )}
                    <button
                      className={`manage-btn manage-btn--send`}
                      disabled={!splitNote || splitSourcePoolLow}
                      style={{ width: '100%', marginTop: 12 }}
                      onClick={() => {
                        if (!splitNote) return
                        withPasswordFallback(() => tx.split(splitNote))
                        setSplitNote(null)
                      }}
                    >
                      {splitSourcePoolLow ? 'Blocked — Low Privacy' : 'Split'}
                    </button>
                  </>
                ) : (
                  <>
                    <button className="manage-btn manage-btn--recover" disabled style={{ width: '100%', marginTop: 12 }}>
                      No splittable notes
                    </button>
                    <div className="tx-convert-card__note">Deposit 1.0 ALGO first</div>
                  </>
                )}
              </div>

              {/* Combine card */}
              <div className="tx-convert-card">
                <div className="tx-convert-card__title">Combine</div>
                <div className="tx-convert-card__desc">2 × 0.5 ALGO → 1.0 ALGO</div>
                {pairableDenoms.length > 0 ? (
                  <>
                    {pairableDenoms.map(([denomStr, denomNotes]) => {
                      const denomAlgo = (Number(denomStr) / 1_000_000).toFixed(1)
                      const destAlgo = (Number(denomStr) * 2 / 1_000_000).toFixed(1)
                      return (
                        <div key={denomStr}>
                          <select
                            className="tx-field__input"
                            style={{ marginTop: 8 }}
                            value={combineNote1?.toString() ?? ''}
                            onChange={e => {
                              setCombineNote1(e.target.value ? BigInt(e.target.value) : null)
                              setCombineNote2(null)
                            }}
                          >
                            <option value="">Note 1...</option>
                            {denomNotes.map((n, i) => (
                              <option key={i} value={n.commitment.toString()}>
                                {denomAlgo} ALGO — {new Date(n.timestamp).toLocaleDateString()}
                              </option>
                            ))}
                          </select>
                          <select
                            className="tx-field__input"
                            style={{ marginTop: 4 }}
                            value={combineNote2?.toString() ?? ''}
                            onChange={e => setCombineNote2(e.target.value ? BigInt(e.target.value) : null)}
                            disabled={!combineNote1}
                          >
                            <option value="">Note 2...</option>
                            {denomNotes
                              .filter(n => n.commitment !== combineNote1)
                              .map((n, i) => (
                                <option key={i} value={n.commitment.toString()}>
                                  {denomAlgo} ALGO — {new Date(n.timestamp).toLocaleDateString()}
                                </option>
                              ))}
                          </select>
                          {combineNote1 !== null && combineNote2 !== null && (
                            <div className="tx-convert-card__preview">
                              2 × {denomAlgo} ALGO → {destAlgo} ALGO
                            </div>
                          )}
                        </div>
                      )
                    })}
                    {combineSourcePoolLow && (
                      <div style={{ color: 'var(--danger)', fontSize: 12, marginTop: 8 }}>
                        Pool has fewer than {MIN_POOL_DEPOSITS_UI} deposits — combine blocked for privacy
                      </div>
                    )}
                    <button
                      className="manage-btn manage-btn--send"
                      disabled={!combineNote1 || !combineNote2 || combineSourcePoolLow}
                      style={{ width: '100%', marginTop: 12 }}
                      onClick={() => {
                        if (!combineNote1 || !combineNote2) return
                        withPasswordFallback(() => tx.combine(combineNote1, combineNote2))
                        setCombineNote1(null)
                        setCombineNote2(null)
                      }}
                    >
                      {combineSourcePoolLow ? 'Blocked — Low Privacy' : 'Combine'}
                    </button>
                  </>
                ) : (
                  <>
                    <button className="manage-btn manage-btn--recover" disabled style={{ width: '100%', marginTop: 12 }}>
                      No combinable notes
                    </button>
                    <div className="tx-convert-card__note">Need 2+ notes of the same denomination (0.5 ALGO)</div>
                  </>
                )}
              </div>
            </div>
          </div>
        )
      })()}

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
          <button className="manage-btn manage-btn--cancel" style={{ marginTop: 10, width: '100%' }} onClick={handleReset}>
            Cancel
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

      {/* Soak time privacy warning modal */}
      {tx.soakWarning && (
        <div className="wallet-modal-overlay" onClick={() => tx.soakWarning?.resolve(false)}>
          <div className="wallet-modal" onClick={e => e.stopPropagation()} style={{ minWidth: 360, maxWidth: 420 }}>
            <div className="wallet-modal__title">Low Privacy Warning</div>

            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>
              <p style={{ marginBottom: 12 }}>
                Only <strong style={{ color: 'var(--warning, #FF9800)' }}>{tx.soakWarning.depositsSince}</strong> deposit(s) have been made since yours.
                We recommend waiting for at least <strong>{tx.soakWarning.needed} more</strong> to grow your anonymity set.
              </p>
              <p style={{ marginBottom: 0 }}>
                Withdrawing now makes it easier for an observer to link your deposit and withdrawal by process of elimination.
              </p>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="tx-execute"
                style={{ flex: 1, background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}
                onClick={() => tx.soakWarning?.resolve(false)}
              >
                Wait
              </button>
              <button
                className="tx-execute"
                style={{ flex: 1, background: 'var(--warning, #FF9800)', color: '#fff' }}
                onClick={() => tx.soakWarning?.resolve(true)}
              >
                Accept Risk
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
