import { useState } from 'react'
import { useWallet } from '@txnlab/use-wallet-react'
import { loadNotes, removeNote, type DepositNote } from '../lib/privacy'
import { useTransaction } from '../hooks/useTransaction'
import { txnUrl } from '../lib/config'
import algosdk from 'algosdk'

interface ManageDepositsProps {
  open: boolean
  onClose: () => void
  onWithdraw: () => void
  onComplete: () => void
}

export function ManageDeposits({ open, onClose, onWithdraw, onComplete }: ManageDepositsProps) {
  const { activeAddress } = useWallet()
  const tx = useTransaction()
  const [notes, setNotes] = useState<DepositNote[]>(loadNotes)
  const [sendingIdx, setSendingIdx] = useState<number | null>(null)
  const [destination, setDestination] = useState('')

  if (!open) return null

  const isValidDest = destination.length > 0 && algosdk.isValidAddress(destination)

  function refreshNotes() {
    setNotes(loadNotes())
  }

  async function handleSend(idx: number) {
    if (!isValidDest || !activeAddress) return
    setSendingIdx(null)
    onWithdraw()
    try {
      await tx.withdraw(idx, destination)
      onComplete()
      setDestination('')
      refreshNotes()
    } catch {
      refreshNotes()
    }
  }

  function handleDelete(idx: number) {
    if (confirm('Delete this deposit note? You will lose access to these funds.')) {
      removeNote(idx)
      refreshNotes()
    }
  }

  return (
    <div className="manage-overlay" onClick={onClose}>
      <div className="manage-panel" onClick={e => e.stopPropagation()}>
        <div className="manage-header">
          <span className="manage-title">Your Deposits</span>
          <button className="manage-close" onClick={onClose}>&times;</button>
        </div>

        {tx.stage === 'withdrawing' && (
          <div className="manage-status">
            <div className="tx-status__text">{tx.message}</div>
            <button className="tx-execute tx-execute--loading" disabled style={{ marginTop: 12 }}>
              Sending...
            </button>
          </div>
        )}

        {tx.stage === 'withdraw_complete' && (
          <div className="manage-status">
            <div className="tx-status__text">
              <strong>Sent!</strong><br />{tx.message}
            </div>
            {tx.txId && (
              <a className="tx-status__txid" href={txnUrl(tx.txId)} target="_blank" rel="noopener noreferrer">
                TX: {tx.txId.slice(0, 16)}...
              </a>
            )}
            <button className="tx-execute tx-execute--ready" style={{ marginTop: 12 }} onClick={() => { tx.reset(); refreshNotes() }}>
              Done
            </button>
          </div>
        )}

        {tx.stage === 'error' && (
          <div className="manage-status">
            <div className="tx-status__text" style={{ color: 'var(--danger)' }}>{tx.error}</div>
            <button className="tx-execute tx-execute--ready" style={{ marginTop: 12 }} onClick={() => tx.reset()}>
              Dismiss
            </button>
          </div>
        )}

        {tx.stage !== 'withdrawing' && tx.stage !== 'withdraw_complete' && tx.stage !== 'error' && (
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
                          value={destination}
                          onChange={e => setDestination(e.target.value.trim())}
                          spellCheck={false}
                          autoFocus
                        />
                        <div className="manage-note__actions">
                          <button
                            className="manage-btn manage-btn--send"
                            disabled={!isValidDest}
                            onClick={() => handleSend(i)}
                          >
                            Send
                          </button>
                          <button
                            className="manage-btn manage-btn--cancel"
                            onClick={() => { setSendingIdx(null); setDestination('') }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="manage-note__actions">
                        <button
                          className="manage-btn manage-btn--send"
                          onClick={() => { setSendingIdx(i); setDestination('') }}
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
      </div>
    </div>
  )
}
