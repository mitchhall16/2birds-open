import { WalletConnect } from './WalletConnect'
import { NETWORK } from '../lib/config'

export function StatusBar() {
  return (
    <>
      <div className="status-bar__left">
        <span className="status-bar__logo">Privacy Pool</span>
        <span className="status-bar__network">{NETWORK}</span>
      </div>
      <WalletConnect />
    </>
  )
}
