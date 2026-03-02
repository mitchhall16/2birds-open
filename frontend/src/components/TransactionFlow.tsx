import { useState, useEffect, useRef } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { useTransaction, type TxStage } from '../hooks/useTransaction'
import { CostBreakdown } from './CostBreakdown'
import { txnUrl } from '../lib/config'
import { loadNotes, removeNote, deriveMasterKey, recoverNotes, initMimc, type DepositNote } from '../lib/privacy'
import { ALGOD_CONFIG } from '../lib/config'
import algosdk from 'algosdk'

interface TransactionFlowProps {
  onDeposit: () => void
  onWithdraw: () => void
  onComplete: () => void
  walletBalance?: number
}

type Tab = 'deposit' | 'send' | 'manage'

export function TransactionFlow({ onDeposit, onWithdraw, onComplete, walletBalance }: TransactionFlowProps) {
  const { activeAddress, signData, algodClient } = useWallet()
  const tx = useTransaction()
  const [tab, setTab] = useState<Tab>('deposit')
  const [amount, setAmount] = useState('1')
  const [destination, setDestination] = useState('')
  const [notes, setNotes] = useState<DepositNote[]>(loadNotes)
  const [sendingIdx, setSendingIdx] = useState<number | null>(null)
  const [splittingIdx, setSplittingIdx] = useState<number | null>(null)
  const [splitPct, setSplitPct] = useState(50)
  const [selectedForCombine, setSelectedForCombine] = useState<Set<number>>(new Set())
  const [manageDestination, setManageDestination] = useState('')
  const [recovering, setRecovering] = useState(false)
  const [recoveryResult, setRecoveryResult] = useState<{ recovered: number; total: number; spent: number } | null>(null)
  const prevStage = useRef<TxStage>('idle')

  const numAmount = parseFloat(amount) || 0
  const validAmount = numAmount > 0 && numAmount <= 1
  const isValidDest = destination.length > 0 && algosdk.isValidAddress(destination)
  const isValidManageDest = manageDestination.length > 0 && algosdk.isValidAddress(manageDestination)

  const canDeposit = !!activeAddress && validAmount && (tx.stage === 'idle' || tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete')
  const canSend = !!activeAddress && validAmount && isValidDest && (tx.stage === 'idle' || tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete')

  function refreshNotes() {
    setNotes(loadNotes())
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

  async function handleDeposit() {
    if (!canDeposit) return
    await tx.deposit(numAmount)
  }

  async function handleSend() {
    if (!canSend) return
    await tx.privateSend(numAmount, destination)
  }

  async function handleManageSend(idx: number) {
    if (!isValidManageDest || !activeAddress) return
    setSendingIdx(null)
    await tx.withdraw(idx, manageDestination)
    setManageDestination('')
    refreshNotes()
  }

  async function handleSplit(idx: number, noteAlgo: number) {
    const leftAlgo = Math.round(noteAlgo * splitPct / 100 * 1_000_000) / 1_000_000
    if (leftAlgo <= 0 || leftAlgo >= noteAlgo) return
    setSplittingIdx(null)
    setSplitPct(50)
    setSelectedForCombine(new Set())
    await tx.splitNote(idx, leftAlgo)
    refreshNotes()
  }

  async function handleCombine() {
    const indices = Array.from(selectedForCombine).sort((a, b) => a - b)
    if (indices.length < 2) return
    setSelectedForCombine(new Set())
    setSplittingIdx(null)
    setSendingIdx(null)
    await tx.combineNotes(indices)
    refreshNotes()
  }

  function toggleCombineSelect(idx: number) {
    setSelectedForCombine(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx)
      else next.add(idx)
      return next
    })
  }

  function handleDelete(idx: number) {
    if (confirm('Delete this deposit note? You will lose access to these funds.')) {
      removeNote(idx)
      refreshNotes()
    }
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
    } catch (err) {
      console.error('Recovery failed:', err)
      setRecoveryResult({ recovered: 0, total: 0, spent: 0 })
    } finally {
      setRecovering(false)
    }
  }

  function handleAmountChange(val: string) {
    if (val === '' || val === '.') { setAmount(val); return }
    const n = parseFloat(val)
    if (!isNaN(n) && n >= 0 && n <= 1) setAmount(val)
  }

  const isProcessing = tx.stage === 'depositing' || tx.stage === 'withdrawing' || tx.stage === 'generating_proof' || tx.stage === 'splitting' || tx.stage === 'combining'
  const isDone = tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete' || tx.stage === 'split_complete' || tx.stage === 'combine_complete'
  const isIdle = !isProcessing && !isDone && tx.stage !== 'error'

  return (
    <div className="tx-flow reveal reveal-3">

      {/* Tabs — always visible */}
      <div className="tx-tab-bar">
        <button className={`tx-tab ${tab === 'deposit' ? 'tx-tab--active' : ''}`} onClick={() => setTab('deposit')}>
          Deposit
        </button>
        <button className={`tx-tab ${tab === 'send' ? 'tx-tab--active' : ''}`} onClick={() => setTab('send')}>
          Send
        </button>
        <button className={`tx-tab ${tab === 'manage' ? 'tx-tab--active' : ''}`} onClick={() => { setTab('manage'); refreshNotes() }}>
          Manage{notes.length > 0 ? ` (${notes.length})` : ''}
        </button>
      </div>

      {/* ── Deposit / Send tabs ── */}
      {(tab === 'deposit' || tab === 'send') && isIdle && (
        <>
          {/* Amount */}
          <div className="tx-field">
            <label className="tx-field__label">Amount</label>
            <div className="tx-amount-input-wrap">
              <input
                className="tx-amount-input"
                type="text"
                inputMode="decimal"
                value={amount}
                onChange={(e) => handleAmountChange(e.target.value)}
                placeholder="0.00"
              />
              <span className="tx-amount-input__unit">ALGO</span>
              <button className="tx-amount-input__max" onClick={() => setAmount('1')}>MAX</button>
            </div>
          </div>

          {/* Send: destination */}
          {tab === 'send' && (
            <div className="tx-field">
              <label className="tx-field__label">To</label>
              <input
                className={`tx-field__input ${destination.length > 0 && !isValidDest ? 'tx-field__input--invalid' : ''}`}
                type="text"
                placeholder="Algorand address..."
                value={destination}
                onChange={(e) => setDestination(e.target.value.trim())}
                spellCheck={false}
              />
              {destination.length > 0 && !isValidDest && (
                <div className="tx-field__error">Invalid Algorand address</div>
              )}
            </div>
          )}

          <CostBreakdown amount={numAmount} mode={tab === 'deposit' ? 'deposit' : 'send'} walletBalance={walletBalance} />

          <div className="tx-flow__spacer" />

          {tab === 'deposit' ? (
            <button
              className={`tx-execute ${canDeposit ? 'tx-execute--ready' : 'tx-execute--disabled'}`}
              onClick={handleDeposit}
              disabled={!canDeposit}
            >
              Deposit {validAmount ? `${amount} ALGO` : ''}
            </button>
          ) : (
            <button
              className={`tx-execute ${canSend ? 'tx-execute--ready' : 'tx-execute--disabled'}`}
              onClick={handleSend}
              disabled={!canSend}
            >
              {!isValidDest
                ? 'Enter destination'
                : `Send ${validAmount ? amount + ' ALGO' : ''}`}
            </button>
          )}
        </>
      )}

      {/* ── Manage tab ── */}
      {tab === 'manage' && isIdle && (
        <>
          {notes.length === 0 ? (
            <div className="manage-empty">No deposits yet</div>
          ) : (
            <>
              <div className="manage-list">
                {notes.map((note, i) => {
                  const noteAlgo = Number(note.denomination) / 1_000_000
                  const leftAlgo = Math.round(noteAlgo * splitPct / 100 * 1_000_000) / 1_000_000
                  const rightAlgo = Math.round((noteAlgo - leftAlgo) * 1_000_000) / 1_000_000
                  const canSplit = leftAlgo > 0 && rightAlgo > 0
                  return (
                    <div key={i} className={`manage-note ${selectedForCombine.has(i) ? 'manage-note--selected' : ''}`}>
                      <div className="manage-note__info">
                        <label className="manage-note__checkbox-wrap">
                          <input
                            type="checkbox"
                            checked={selectedForCombine.has(i)}
                            onChange={() => toggleCombineSelect(i)}
                            className="manage-note__checkbox"
                          />
                          <span className="manage-note__amount">
                            {noteAlgo.toFixed(2)} ALGO
                          </span>
                        </label>
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
                          <div className="manage-note__actions">
                            <button
                              className="manage-btn manage-btn--send"
                              disabled={!isValidManageDest}
                              onClick={() => handleManageSend(i)}
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
                      ) : splittingIdx === i ? (
                        <div className="manage-note__send-form">
                          <div className="manage-split__slider-wrap">
                            <div className="manage-split__labels">
                              <span className="manage-split__label-left">{leftAlgo.toFixed(3)}</span>
                              <span className="manage-split__label-right">{rightAlgo.toFixed(3)}</span>
                            </div>
                            <div className="manage-split__track">
                              <div className="manage-split__track-left" style={{ width: `${splitPct}%` }} />
                              <div className="manage-split__track-right" style={{ width: `${100 - splitPct}%` }} />
                            </div>
                            <input
                              type="range"
                              min={1}
                              max={99}
                              value={splitPct}
                              onChange={e => setSplitPct(Number(e.target.value))}
                              className="manage-split__range"
                            />
                            <div className="manage-split__units">
                              <span>ALGO</span>
                              <span>ALGO</span>
                            </div>
                          </div>
                          <CostBreakdown
                            amount={noteAlgo}
                            mode="split"
                            splitLeft={leftAlgo}
                            splitRight={rightAlgo}
                            walletBalance={walletBalance}
                          />
                          <div className="manage-note__actions">
                            <button
                              className="manage-btn manage-btn--send"
                              disabled={!canSplit}
                              onClick={() => handleSplit(i, noteAlgo)}
                            >
                              Split
                            </button>
                            <button
                              className="manage-btn manage-btn--cancel"
                              onClick={() => { setSplittingIdx(null); setSplitPct(50) }}
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="manage-note__actions">
                          <button
                            className="manage-btn manage-btn--send"
                            onClick={() => { setSendingIdx(i); setSplittingIdx(null); setManageDestination('') }}
                          >
                            Send
                          </button>
                          <button
                            className="manage-btn manage-btn--split"
                            onClick={() => { setSplittingIdx(i); setSendingIdx(null); setSplitPct(50) }}
                          >
                            Split
                          </button>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>

              {selectedForCombine.size < 2 && notes.length >= 2 && (
                <div className="manage-hint">Select 2 or more checkboxes to combine deposits</div>
              )}

              {selectedForCombine.size >= 2 && (
                <div className="manage-combine-bar">
                  <CostBreakdown
                    amount={Array.from(selectedForCombine).reduce((sum, i) => sum + Number(notes[i].denomination), 0) / 1_000_000}
                    mode="combine"
                    combineCount={selectedForCombine.size}
                    walletBalance={walletBalance}
                  />
                  <button className="manage-btn manage-btn--send" onClick={handleCombine}>
                    Combine {selectedForCombine.size} Notes
                  </button>
                </div>
              )}
            </>
          )}

          <button
            className={`manage-btn manage-btn--recover ${recovering ? 'manage-btn--loading' : ''}`}
            onClick={handleRecover}
            disabled={recovering || !activeAddress}
            style={{ marginTop: 12, width: '100%' }}
          >
            {recovering ? 'Scanning chain...' : 'Recover Notes'}
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
        </>
      )}

      {/* ── In-progress (shared across all tabs) ── */}
      {isProcessing && (
        <div className="tx-status">
          <div className="tx-status__text">{tx.message}</div>
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
            {tx.stage === 'depositing' ? 'Depositing...' : tx.stage === 'generating_proof' ? 'Proving...' : tx.stage === 'splitting' ? 'Splitting...' : tx.stage === 'combining' ? 'Combining...' : 'Sending...'}
          </button>
        </div>
      )}

      {/* Complete */}
      {isDone && (
        <div className="tx-status">
          <div className="tx-status__text">
            <strong>{tx.stage === 'deposit_complete' ? 'Deposit confirmed.' : tx.stage === 'split_complete' ? 'Split complete.' : tx.stage === 'combine_complete' ? 'Combine complete.' : 'Transfer complete.'}</strong>
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
    </div>
  )
}
