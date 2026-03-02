import { FEES } from '../lib/config'
import { formatAlgo } from '../lib/privacy'

interface CostBreakdownProps {
  amount?: number
  mode?: 'deposit' | 'send' | 'split' | 'combine'
  splitLeft?: number
  splitRight?: number
  combineCount?: number
  walletBalance?: number
}

function FeeTooltip({ text }: { text: string }) {
  return (
    <span className="fee-tooltip-wrap">
      <span className="fee-tooltip__icon">?</span>
      <span className="fee-tooltip__body">{text}</span>
    </span>
  )
}

const FEE_TIPS = {
  deposit: `Payment txn (0.001) + app call (0.001) = ${formatAlgo(FEES.deposit)} ALGO`,
  send: `Deposit (${formatAlgo(FEES.deposit)}) + ZK proof verification with ~225 inner calls for opcode budget (${formatAlgo(FEES.verifierCall)}) + pool withdrawal (0.002) = ${formatAlgo(FEES.deposit + FEES.withdraw)} ALGO`,
  split: `ZK proof verification (${formatAlgo(FEES.verifierCall)}) + pool withdrawal (0.002) + 2 new deposits (${formatAlgo(FEES.deposit * 2n)}) = ${formatAlgo(FEES.withdraw + FEES.deposit * 2n)} ALGO`,
  combine: (n: number) =>
    `${n} ZK proof verifications (${n} x ${formatAlgo(FEES.withdraw)}) + 1 deposit (${formatAlgo(FEES.deposit)}) = ${formatAlgo(FEES.withdraw * BigInt(n) + FEES.deposit)} ALGO`,
}

function WalletRow({ balance }: { balance?: number }) {
  if (balance === undefined) return null
  return (
    <div className="cost-row cost-row--wallet">
      <span className="cost-row__label">Wallet balance</span>
      <span className="cost-row__value">{balance.toFixed(3)} ALGO</span>
    </div>
  )
}

export function CostBreakdown({ amount = 1, mode = 'send', splitLeft, splitRight, combineCount = 2, walletBalance }: CostBreakdownProps) {
  const amountMicro = BigInt(Math.round(amount * 1_000_000))

  if (mode === 'deposit') {
    return (
      <div className="cost-breakdown">
        <div className="cost-breakdown__title">Cost Breakdown</div>
        <WalletRow balance={walletBalance} />
        <div className="cost-row">
          <span className="cost-row__label">Deposit amount</span>
          <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
        </div>
        <div className="cost-row">
          <span className="cost-row__label">Network fees <FeeTooltip text={FEE_TIPS.deposit} /></span>
          <span className="cost-row__value">{formatAlgo(FEES.deposit)} ALGO</span>
        </div>
        <div className="cost-row cost-row--total">
          <span className="cost-row__label">Total from wallet</span>
          <span className="cost-row__value">{formatAlgo(amountMicro + FEES.deposit)} ALGO</span>
        </div>
      </div>
    )
  }

  if (mode === 'split') {
    const leftMicro = BigInt(Math.round((splitLeft ?? 0) * 1_000_000))
    const rightMicro = BigInt(Math.round((splitRight ?? 0) * 1_000_000))
    // Split = 1 withdraw + 2 deposits
    const splitFees = FEES.withdraw + FEES.deposit * 2n
    return (
      <div className="cost-breakdown">
        <div className="cost-breakdown__title">Cost Breakdown</div>
        <WalletRow balance={walletBalance} />
        <div className="cost-row">
          <span className="cost-row__label">Note amount</span>
          <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
        </div>
        <div className="cost-row">
          <span className="cost-row__label">Split into</span>
          <span className="cost-row__value">{formatAlgo(leftMicro)} + {formatAlgo(rightMicro)} ALGO</span>
        </div>
        <div className="cost-row">
          <span className="cost-row__label">Network fees <FeeTooltip text={FEE_TIPS.split} /></span>
          <span className="cost-row__value">{formatAlgo(splitFees)} ALGO</span>
        </div>
        <div className="cost-row cost-row--total">
          <span className="cost-row__label">Total fee from wallet</span>
          <span className="cost-row__value">{formatAlgo(splitFees)} ALGO</span>
        </div>
      </div>
    )
  }

  if (mode === 'combine') {
    // Combine = N withdrawals + 1 deposit
    const combineFees = FEES.withdraw * BigInt(combineCount) + FEES.deposit
    return (
      <div className="cost-breakdown">
        <div className="cost-breakdown__title">Cost Breakdown</div>
        <WalletRow balance={walletBalance} />
        <div className="cost-row">
          <span className="cost-row__label">Combined amount</span>
          <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
        </div>
        <div className="cost-row">
          <span className="cost-row__label">Network fees <FeeTooltip text={FEE_TIPS.combine(combineCount)} /></span>
          <span className="cost-row__value">{formatAlgo(combineFees)} ALGO</span>
        </div>
        <div className="cost-row cost-row--total">
          <span className="cost-row__label">Total fee from wallet</span>
          <span className="cost-row__value">{formatAlgo(combineFees)} ALGO</span>
        </div>
      </div>
    )
  }

  const totalFees = FEES.deposit + FEES.withdraw

  return (
    <div className="cost-breakdown">
      <div className="cost-breakdown__title">Cost Breakdown</div>
      <WalletRow balance={walletBalance} />
      <div className="cost-row">
        <span className="cost-row__label">Transfer amount</span>
        <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
      </div>
      <div className="cost-row">
        <span className="cost-row__label">Network fees <FeeTooltip text={FEE_TIPS.send} /></span>
        <span className="cost-row__value">{formatAlgo(totalFees)} ALGO</span>
      </div>
      <div className="cost-row cost-row--total">
        <span className="cost-row__label">Total from wallet</span>
        <span className="cost-row__value">{formatAlgo(amountMicro + totalFees)} ALGO</span>
      </div>
      <div className="cost-row">
        <span className="cost-row__label">Recipient gets</span>
        <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
      </div>
    </div>
  )
}
