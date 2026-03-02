import type { Toast } from '../contexts/ToastContext'

const ICONS: Record<string, string> = {
  success: '\u2713',
  error: '\u2717',
  warning: '\u26A0',
  info: '\u2139',
}

interface ToastItemProps {
  toast: Toast
  onDismiss: () => void
}

export function ToastItem({ toast, onDismiss }: ToastItemProps) {
  const className = [
    'toast',
    `toast--${toast.type}`,
    toast.exiting ? 'toast--exit' : '',
  ].filter(Boolean).join(' ')

  return (
    <div className={className} onClick={onDismiss} role="alert">
      <span className="toast__icon">{ICONS[toast.type]}</span>
      <span className="toast__message">{toast.message}</span>
      <button className="toast__close" aria-label="Dismiss">&times;</button>
    </div>
  )
}
