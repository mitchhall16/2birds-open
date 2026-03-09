import { txnUrl } from '../lib/config'

export type StepStatus = 'pending' | 'active' | 'proving' | 'submitting' | 'waiting_batch' | 'done' | 'error'

export interface ExecutionStep {
  label: string              // "Deposit 1.0 ALGO"
  status: StepStatus
  txId?: string
  batchCountdown?: string
  error?: string
}

interface ExecutionProgressProps {
  steps: ExecutionStep[]
  onSkipBatch?: () => void
}

const STATUS_ICONS: Record<StepStatus, string> = {
  done: '\u2713',
  active: '\u25CF',
  proving: '\u25CF',
  submitting: '\u25CF',
  waiting_batch: '\u25CF',
  pending: '\u25CB',
  error: '\u2717',
}

const STATUS_COLORS: Record<StepStatus, string> = {
  done: 'var(--success)',
  active: 'var(--status-active)',
  proving: 'var(--status-proving)',
  submitting: 'var(--status-submitting)',
  waiting_batch: 'var(--status-waiting)',
  pending: 'var(--status-pending)',
  error: 'var(--danger)',
}

const STATUS_LABELS: Record<StepStatus, string> = {
  done: '',
  active: 'Processing...',
  proving: 'Generating ZK proof...',
  submitting: 'Submitting to chain...',
  waiting_batch: 'Waiting for batch window...',
  pending: 'Queued',
  error: 'Failed',
}

export function ExecutionProgress({ steps, onSkipBatch }: ExecutionProgressProps) {
  const completed = steps.filter(s => s.status === 'done').length
  const total = steps.length
  const progress = total > 0 ? (completed / total) * 100 : 0

  return (
    <div className="execution-progress" style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-md)',
      padding: '16px',
    }}>
      {/* Progress bar */}
      <div style={{
        height: '3px',
        background: 'var(--border)',
        borderRadius: '2px',
        marginBottom: '12px',
        overflow: 'hidden',
      }}>
        <div style={{
          height: '100%',
          width: `${progress}%`,
          background: `linear-gradient(90deg, var(--status-active), var(--success))`,
          borderRadius: '2px',
          transition: 'width 0.5s ease',
        }} />
      </div>

      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '8px' }}>
        {completed}/{total} steps complete
      </div>

      {steps.map((step, i) => (
        <div
          key={i}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '10px',
            padding: '8px 4px',
            borderBottom: i < steps.length - 1 ? '1px solid var(--border-subtle)' : 'none',
            opacity: step.status === 'pending' ? 0.5 : 1,
          }}
        >
          <span style={{
            color: STATUS_COLORS[step.status],
            fontSize: '14px',
            width: '18px',
            textAlign: 'center',
            fontWeight: step.status === 'done' || step.status === 'error' ? 'bold' : 'normal',
          }}>
            {STATUS_ICONS[step.status]}
          </span>

          <span style={{
            color: 'var(--text-secondary)',
            fontSize: '11px',
            minWidth: '42px',
          }}>
            Step {i + 1}
          </span>

          <span style={{
            color: 'var(--text-primary)',
            fontSize: '13px',
            flex: 1,
          }}>
            {step.label}
          </span>

          <span style={{ fontSize: '12px' }}>
            {step.txId ? (
              <a
                href={txnUrl(step.txId)}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: 'var(--status-link)', textDecoration: 'none' }}
              >
                {step.txId.slice(0, 8)}...
              </a>
            ) : step.error ? (
              <span style={{ color: 'var(--danger)' }}>{step.error}</span>
            ) : (
              <span style={{ color: STATUS_COLORS[step.status] }}>
                {STATUS_LABELS[step.status]}
              </span>
            )}
          </span>

          {step.status === 'waiting_batch' && step.batchCountdown && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px' }}>
              <span style={{ color: 'var(--status-waiting)' }}>{step.batchCountdown}</span>
              {onSkipBatch && (
                <button
                  onClick={onSkipBatch}
                  style={{
                    background: 'color-mix(in srgb, var(--status-waiting) 15%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--status-waiting) 30%, transparent)',
                    color: 'var(--status-waiting)',
                    padding: '2px 8px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontSize: '11px',
                  }}
                >
                  Skip
                </button>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
