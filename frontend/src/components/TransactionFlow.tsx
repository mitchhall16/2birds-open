import { useState, useEffect, useRef } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { useTransaction, type TxStage } from '../hooks/useTransaction'
import { CostBreakdown } from './CostBreakdown'
import { txnUrl } from '../lib/config'
import { loadNotes, removeNote, type DepositNote } from '../lib/privacy'
import algosdk from 'algosdk'

interface TransactionFlowProps {
  onDeposit: () => void
  onWithdraw: () => void
  onComplete: () => void
}

type Tab = 'deposit' | 'send' | 'manage'

export function TransactionFlow({ onDeposit, onWithdraw, onComplete }: TransactionFlowProps) {
  const { activeAddress } = useWallet()
  const tx = useTransaction()
  const [tab, setTab] = useState<Tab>('deposit')
  const [amount, setAmount] = useState('1')
  const [destination, setDestination] = useState('')
  const [notes, setNotes] = useState<DepositNote[]>(loadNotes)
  const [sendingIdx, setSendingIdx] = useState<number | null>(null)
  const [manageDestination, setManageDestination] = useState('')
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
    if (tx.stage === 'depositing' && prev !== 'depositing') onDeposit()
    if (tx.stage === 'withdrawing' && prev !== 'withdrawing') onWithdraw()
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

  function handleAmountChange(val: string) {
    if (val === '' || val === '.') { setAmount(val); return }
    const n = parseFloat(val)
    if (!isNaN(n) && n >= 0 && n <= 1) setAmount(val)
  }

  const isProcessing = tx.stage === 'depositing' || tx.stage === 'withdrawing' || tx.stage === 'generating_proof'
  const isDone = tx.stage === 'deposit_complete' || tx.stage === 'withdraw_complete'
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

          <CostBreakdown amount={numAmount} mode={tab === 'deposit' ? 'deposit' : 'send'} />

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
            <div className="manage-list">
              {notes.map((note, i) => (
                <div key={i} className="manage-note">
                  <div className="manage-note__info">
                    <span className="manage-note__amount">
                      {(Number(note.denomination) / 1_000_000).toFixed(2)} ALGO
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
                  ) : (
                    <div className="manage-note__actions">
                      <button
                        className="manage-btn manage-btn--send"
                        onClick={() => { setSendingIdx(i); setManageDestination('') }}
                      >
                        Send
                      </button>
                      <button
                        className="manage-btn manage-btn--delete"
                        onClick={() => handleDelete(i)}
                      >
                        Delete
                      </button>
                    </div>
                  )}
                </div>
              ))}
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
            {tx.stage === 'depositing' ? 'Depositing...' : tx.stage === 'generating_proof' ? 'Proving...' : 'Sending...'}
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
    </div>
  )
}
