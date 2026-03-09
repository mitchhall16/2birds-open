import { useEffect } from 'react'

interface HowItWorksProps {
  open: boolean
  onClose: () => void
}

const FAQ: { q: string; a: string }[] = [
  {
    q: 'What is 2birds?',
    a: 'A privacy pool on Algorand. Deposit ALGO into a shared pool, withdraw the same amount to a different wallet. Nobody can connect the two.',
  },
  {
    q: 'Is my money safe?',
    a: "Held by an immutable smart contract — not a person or company. You can withdraw anytime with your secret deposit note.",
  },
  {
    q: 'How much does it cost?',
    a: 'Deposit: pool amount + ~0.057 ALGO fees. Withdraw: 0.05 ALGO. No subscriptions, no hidden fees.',
  },
  {
    q: "What's a zero-knowledge proof?",
    a: 'A way to prove "I deposited" without revealing which deposit is yours. The math guarantees it — no trust required.',
  },
  {
    q: 'Can I lose my funds?',
    a: "Only if you lose your deposit note AND forgot your password. Notes are encrypted on-chain as backup — reconnect your wallet to recover.",
  },
  {
    q: 'How do I get better privacy?',
    a: "Wait longer between deposit and withdrawal. The more people who deposit after you, the bigger the crowd you're hiding in.",
  },
]

export function HowItWorks({ open, onClose }: HowItWorksProps) {
  useEffect(() => {
    if (!open) return
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="hiw-overlay" onClick={onClose}>
      <div className="hiw-page" onClick={e => e.stopPropagation()}>
        <button className="hiw-close" onClick={onClose}>&times;</button>

        {/* Top section: title + flow */}
        <div className="hiw-top">
          <h1 className="hiw-title">How 2birds Works</h1>
          <p className="hiw-subtitle">
            Private transactions in three steps. No accounts, no sign-ups — just math.
          </p>

          <div className="hiw-flow">
            <div className="hiw-step">
              <div className="hiw-step__icon">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2v6m0 0l3-3m-3 3L9 5" />
                  <rect x="3" y="10" width="18" height="11" rx="2" />
                  <circle cx="12" cy="15.5" r="2.5" />
                </svg>
              </div>
              <h3 className="hiw-step__title">Deposit</h3>
              <p className="hiw-step__desc">
                Pick an amount and deposit into the shared pool. You get a secret note — your receipt.
              </p>
            </div>

            <div className="hiw-flow__arrow">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12h14m0 0l-4-4m4 4l-4 4" />
              </svg>
            </div>

            <div className="hiw-step">
              <div className="hiw-step__icon hiw-step__icon--mix">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="7" cy="8" r="2.5" />
                  <circle cx="17" cy="8" r="2.5" />
                  <circle cx="12" cy="16" r="2.5" />
                  <circle cx="5" cy="16" r="1.5" />
                  <circle cx="19" cy="16" r="1.5" />
                  <circle cx="12" cy="7" r="1.5" />
                </svg>
              </div>
              <h3 className="hiw-step__title">Mix</h3>
              <p className="hiw-step__desc">
                Your deposit joins everyone else's. The bigger the crowd, the better your privacy.
              </p>
            </div>

            <div className="hiw-flow__arrow">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M5 12h14m0 0l-4-4m4 4l-4 4" />
              </svg>
            </div>

            <div className="hiw-step">
              <div className="hiw-step__icon hiw-step__icon--withdraw">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22v-6m0 0l3 3m-3-3l-3 3" />
                  <rect x="3" y="3" width="18" height="11" rx="2" />
                  <path d="M8 8.5h8" />
                  <path d="M8 11h5" />
                </svg>
              </div>
              <h3 className="hiw-step__title">Withdraw</h3>
              <p className="hiw-step__desc">
                Withdraw to any address. A ZK proof confirms you deposited without revealing which one. Unlinkable.
              </p>
            </div>
          </div>
        </div>

        {/* Middle: the tracking problem explained */}
        <div className="hiw-compare">
          <div className="hiw-compare__side hiw-compare__side--problem">
            <div className="hiw-compare__header">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8" />
                <path d="M21 21l-4.35-4.35" />
              </svg>
              <span>Without 2birds</span>
            </div>
            <div className="hiw-compare__flow">
              <span className="hiw-compare__addr">Your Wallet</span>
              <span className="hiw-compare__link hiw-compare__link--visible">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14m0 0l-4-4m4 4l-4 4" /></svg>
              </span>
              <span className="hiw-compare__addr">Recipient</span>
            </div>
            <p className="hiw-compare__desc">
              Every transaction on a blockchain is public. Anyone can look up your wallet address and see exactly where your ALGO went, when, and how much. Block explorers, analytics tools, and chain watchers all follow the trail directly from sender to receiver.
            </p>
          </div>

          <div className="hiw-compare__side hiw-compare__side--solution">
            <div className="hiw-compare__header">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0110 0v4" />
              </svg>
              <span>With 2birds</span>
            </div>
            <div className="hiw-compare__flow">
              <span className="hiw-compare__addr">Your Wallet</span>
              <span className="hiw-compare__link hiw-compare__link--broken">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h5" /><path d="M14 12h5" /></svg>
              </span>
              <span className="hiw-compare__pool">Pool</span>
              <span className="hiw-compare__link hiw-compare__link--broken">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h5" /><path d="M14 12h5" /></svg>
              </span>
              <span className="hiw-compare__addr">Any Address</span>
            </div>
            <p className="hiw-compare__desc">
              Your deposit goes into a shared pool with everyone else's. When you withdraw, a relayer submits the transaction — not your wallet. A zero-knowledge proof confirms you deposited without revealing which deposit. The trail goes cold at the pool.
            </p>
          </div>
        </div>

        {/* Bottom: FAQ grid */}
        <div className="hiw-bottom">
          <h2 className="hiw-faq-title">FAQ</h2>
          <div className="hiw-faq-grid">
            {FAQ.map((item, i) => (
              <div key={i} className="hiw-faq-card">
                <h4 className="hiw-faq-card__q">{item.q}</h4>
                <p className="hiw-faq-card__a">{item.a}</p>
              </div>
            ))}
          </div>
        </div>

        <button className="hiw-cta" onClick={onClose}>
          Got it — take me back
        </button>
      </div>
    </div>
  )
}
