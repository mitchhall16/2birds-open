import { useState, useEffect } from 'react'

interface PasswordModalProps {
  open: boolean
  mode: 'create' | 'unlock'
  onSubmit: (password: string) => void
  onCancel: () => void
  externalError?: string
}

export function PasswordModal({ open, mode, onSubmit, onCancel, externalError }: PasswordModalProps) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')

  // Clear state when modal closes
  useEffect(() => {
    if (!open) {
      setPassword('')
      setConfirm('')
      setError('')
    }
  }, [open])

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

  return (
    <div className="wallet-modal-overlay" onClick={onCancel}>
      <div className="wallet-modal" onClick={e => e.stopPropagation()} style={{ minWidth: 360 }}>
        <div className="wallet-modal__title">
          {mode === 'create' ? 'Set Encryption Password' : 'Enter Password'}
        </div>

        <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.5 }}>
          {mode === 'create'
            ? 'Your wallet does not support signData. Set a password to encrypt your deposit notes. You will need this password each session.'
            : 'Enter your password to decrypt your deposit notes.'}
        </p>

        <form onSubmit={handleSubmit}>
          <div className="tx-field" style={{ marginBottom: 12 }}>
            <label className="tx-field__label">Password</label>
            <input
              className="tx-field__input"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Min 8 characters"
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

        <button className="wallet-modal__close" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  )
}
