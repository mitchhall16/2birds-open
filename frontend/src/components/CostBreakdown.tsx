import { FEES, PROTOCOL_FEE, TREASURY_ADDRESS, USE_PLONK_LSIG } from '../lib/config'
import { formatAlgo } from '../lib/privacy'

interface CostBreakdownProps {
  amount?: number
  mode?: 'deposit' | 'send' | 'withdraw'
  walletBalance?: number
  subsidyMicroAlgos?: bigint
  subsidyActive?: boolean
}

/** Format microAlgos with fixed 3 decimal places (no trailing zero stripping) */
function feeAlgo(microAlgos: bigint): string {
  return (Number(microAlgos) / 1_000_000).toFixed(3)
}

function FeeTooltip({ text }: { text: string }) {
  return (
    <span className="fee-tooltip-wrap">
      <span className="fee-tooltip__icon">?</span>
      <span className="fee-tooltip__body">{text}</span>
    </span>
  )
}

const FEE_TIPS = USE_PLONK_LSIG ? {
  deposit: `PLONK LogicSig verification (${feeAlgo(FEES.verifierCall)}) + payment (0.001) + app call (0.002) = ${feeAlgo(FEES.deposit)} ALGO`,
  send: `PLONK LogicSig verification (${feeAlgo(FEES.privateSendVerifierCall)}) + payment (0.001) + app call (0.002) = ${feeAlgo(FEES.privateSend)} ALGO`,
} : {
  deposit: `Deposit verifier with ~202 inner calls (${feeAlgo(FEES.verifierCall)}) + payment txn (0.001) + app call (0.002) = ${feeAlgo(FEES.deposit)} ALGO`,
  send: `Combined privateSend verifier with ~221 inner calls (${feeAlgo(FEES.privateSendVerifierCall)}) + payment (0.001) + app call (0.002) = ${feeAlgo(FEES.privateSend)} ALGO`,
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

const showProtocolFee = !!TREASURY_ADDRESS && PROTOCOL_FEE > 0n

function ProtocolFeeRow({ subsidyActive }: { subsidyActive?: boolean }) {
  if (!showProtocolFee) return null
  if (subsidyActive) {
    return (
      <div className="cost-row">
        <span className="cost-row__label">Protocol fee <FeeTooltip text="Covered by the community subsidy pool. Someone paid it forward!" /></span>
        <span className="cost-row__value cost-row__value--subsidized">FREE</span>
      </div>
    )
  }
  return (
    <div className="cost-row">
      <span className="cost-row__label">Protocol fee <FeeTooltip text="Small fee that funds the community subsidy pool, reducing fees for future users and improving privacy for everyone." /></span>
      <span className="cost-row__value">{feeAlgo(PROTOCOL_FEE)} ALGO</span>
    </div>
  )
}

function SubsidyRow({ subsidyMicroAlgos }: { subsidyMicroAlgos?: bigint }) {
  if (!subsidyMicroAlgos || subsidyMicroAlgos <= 0n || !TREASURY_ADDRESS) return null
  return (
    <div className="cost-row">
      <span className="cost-row__label">Community subsidy <FeeTooltip text="Your contribution reduces fees for the next user, encouraging more deposits and strengthening everyone's privacy." /></span>
      <span className="cost-row__value cost-row__value--subsidy">{feeAlgo(subsidyMicroAlgos)} ALGO</span>
    </div>
  )
}

const protocolFeeAmount = showProtocolFee ? PROTOCOL_FEE : 0n

export function CostBreakdown({ amount = 1, mode = 'send', walletBalance, subsidyMicroAlgos, subsidyActive }: CostBreakdownProps) {
  const amountMicro = BigInt(Math.round(amount * 1_000_000))
  const subsidy = subsidyMicroAlgos ?? 0n

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
          <span className="cost-row__value">{feeAlgo(FEES.deposit)} ALGO</span>
        </div>
        <ProtocolFeeRow subsidyActive={subsidyActive} />
        <SubsidyRow subsidyMicroAlgos={subsidyMicroAlgos} />
        <div className="cost-row cost-row--total">
          <span className="cost-row__label">Total from wallet</span>
          <span className="cost-row__value">{formatAlgo(amountMicro + FEES.deposit + protocolFeeAmount + subsidy)} ALGO</span>
        </div>
      </div>
    )
  }

  if (mode === 'withdraw') {
    return (
      <div className="cost-breakdown" style={{ marginTop: 8 }}>
        <div className="cost-breakdown__title">Withdrawal Cost</div>
        <div className="cost-row">
          <span className="cost-row__label">Shielded amount</span>
          <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
        </div>
        <div className="cost-row">
          <span className="cost-row__label">Network fees <FeeTooltip text={`ZK proof verification with ~211 inner calls (${feeAlgo(FEES.withdrawVerifierCall)}) + pool withdrawal (0.002) = ${feeAlgo(FEES.withdraw)} ALGO`} /></span>
          <span className="cost-row__value">{feeAlgo(FEES.withdraw)} ALGO</span>
        </div>
        <ProtocolFeeRow subsidyActive={subsidyActive} />
        <div className="cost-row cost-row--total">
          <span className="cost-row__label">Recipient gets</span>
          <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
        </div>
      </div>
    )
  }

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
        <span className="cost-row__value">{feeAlgo(FEES.privateSend)} ALGO</span>
      </div>
      <ProtocolFeeRow subsidyActive={subsidyActive} />
      <SubsidyRow subsidyMicroAlgos={subsidyMicroAlgos} />
      <div className="cost-row cost-row--total">
        <span className="cost-row__label">Total from wallet</span>
        <span className="cost-row__value">{formatAlgo(amountMicro + FEES.privateSend + protocolFeeAmount + subsidy)} ALGO</span>
      </div>
      <div className="cost-row">
        <span className="cost-row__label">Recipient gets</span>
        <span className="cost-row__value">{formatAlgo(amountMicro)} ALGO</span>
      </div>
    </div>
  )
}
