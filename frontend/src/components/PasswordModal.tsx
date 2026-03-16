import { useState, useEffect } from 'react'

interface PasswordModalProps {
  open: boolean
  mode: 'create' | 'unlock'
  onSubmit: (password: string) => void
  onCancel: () => void
  onReset?: () => void
  externalError?: string
}

export function PasswordModal({ open, mode, onSubmit, onCancel, onReset, externalError }: PasswordModalProps) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [showReset, setShowReset] = useState(false)

  // Clear state when modal closes
  useEffect(() => {
    if (!open) {
      setPassword('')
      setConfirm('')
      setError('')
      setShowReset(false)
    }
  }, [open])

  // Escape key closes modal
  useEffect(() => {
    if (!open) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, onCancel])

  if (!open) return null

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')

    if (password.length < 12) {
      setError('Password must be at least 12 characters')
      return
    }

    if (mode === 'create' && password !== confirm) {
      setError('Passwords do not match')
      return
    }

    onSubmit(password)
    setPassword('')
    setConfirm('')
  }

  if (showReset) {
    return (
      <div className="wallet-modal-overlay" onClick={onCancel}>
        <div className="wallet-modal" onClick={e => e.stopPropagation()} style={{ minWidth: 360 }}>
          <div className="wallet-modal__title">Reset Password</div>

          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 12, lineHeight: 1.5 }}>
            This will clear your locally stored notes and password. Your deposit notes are backed up on-chain via encrypted HPKE envelopes.
          </p>

          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.5 }}>
            After resetting, you can recover your notes using <strong>Scan Chain</strong> in the Manage tab.
          </p>

          <button
            className="tx-execute tx-execute--ready"
            style={{ width: '100%', marginTop: 4, background: 'var(--danger)' }}
            onClick={() => {
              setShowReset(false)
              onReset?.()
            }}
          >
            Reset & Start Fresh
          </button>

          <button
            className="wallet-modal__close"
            onClick={() => setShowReset(false)}
            style={{ marginTop: 8 }}
          >
            Go Back
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="wallet-modal-overlay" onClick={onCancel}>
      <div className="wallet-modal" onClick={e => e.stopPropagation()} style={{ minWidth: 360 }}>
        <div className="wallet-modal__title">
          {mode === 'create' ? 'Secure Your Privacy Notes' : 'Unlock Privacy Notes'}
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.5 }}>
          {mode === 'create'
            ? 'Your wallet doesn\'t support automatic key derivation. Set a password to encrypt your deposit notes. You\'ll need this each session.'
            : 'Enter your password to decrypt your deposit notes for this session.'}
        </p>

        <form onSubmit={handleSubmit}>
          <div className="tx-field" style={{ marginBottom: 12 }}>
            <label className="tx-field__label">Password</label>
            <input
              className="tx-field__input"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Min 12 characters"
              autoFocus
              autoComplete="off"
            />
          </div>

          {mode === 'create' && (
            <div className="tx-field" style={{ marginBottom: 12 }}>
              <label className="tx-field__label">Confirm Password</label>
              <input
                className="tx-field__input"
                type="password"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                placeholder="Re-enter password"
                autoComplete="off"
              />
            </div>
          )}

          {(error || externalError) && (
            <div style={{ color: 'var(--danger)', fontSize: 13, marginBottom: 12 }}>{error || externalError}</div>
          )}

          <button
            type="submit"
            className="tx-execute tx-execute--ready"
            style={{ width: '100%', marginTop: 4 }}
          >
            {mode === 'create' ? 'Set Password' : 'Unlock'}
          </button>
        </form>

        {mode === 'unlock' && onReset && (
          <button
            className="wallet-modal__close"
            onClick={() => setShowReset(true)}
            style={{ marginTop: 12, fontSize: 12, color: 'var(--text-secondary)', opacity: 0.8 }}
          >
            Forgot password?
          </button>
        )}

        <button className="wallet-modal__close" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  )
}
