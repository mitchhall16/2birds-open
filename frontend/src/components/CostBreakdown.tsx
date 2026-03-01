import { FEES } from '../lib/config'
import { formatAlgo } from '../lib/privacy'

interface CostBreakdownProps {
  amount?: number
  mode?: 'deposit' | 'send'
}

export function CostBreakdown({ amount = 1, mode = 'send' }: CostBreakdownProps) {
  const amountMicro = BigInt(Math.round(amount * 1_000_000))

  if (mode === 'deposit') {
    return (
      <div className="cost-breakdown">
        <div className="cost-breakdown__title">Cost Breakdown</div>
        <div className="cost-row">
          <span className="cost-row__label">Deposit amount</span>
          <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
        </div>
        <div className="cost-row">
          <span className="cost-row__label">Network fees</span>
          <span className="cost-row__value">{formatAlgo(FEES.deposit)} ALGO</span>
        </div>
        <div className="cost-row cost-row--total">
          <span className="cost-row__label">Total from wallet</span>
          <span className="cost-row__value">{formatAlgo(amountMicro + FEES.deposit)} ALGO</span>
        </div>
      </div>
    )
  }

  const totalFees = FEES.deposit + FEES.withdraw

  return (
    <div className="cost-breakdown">
      <div className="cost-breakdown__title">Cost Breakdown</div>
      <div className="cost-row">
        <span className="cost-row__label">Transfer amount</span>
        <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
      </div>
      <div className="cost-row">
        <span className="cost-row__label">Network fees</span>
        <span className="cost-row__value">{formatAlgo(totalFees)} ALGO</span>
      </div>
      <div className="cost-row cost-row--total">
        <span className="cost-row__label">Recipient gets</span>
        <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
      </div>
    </div>
  )
}
