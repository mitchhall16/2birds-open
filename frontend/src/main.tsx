import React from 'react'
import ReactDOM from 'react-dom/client'
import {
  WalletProvider,
  WalletManager,
  WalletId,
  NetworkId,
  NetworkConfigBuilder,
} from '@txnlab/use-wallet-react'
import { App } from './App'
import { ToastProvider } from './contexts/ToastContext'
import './styles/globals.css'
import './styles/components.css'

const networks = new NetworkConfigBuilder()
  .testnet({
    algod: {
      baseServer: 'https://testnet-api.algonode.cloud',
      port: '',
      token: '',
    },
  })
  .build()

const walletManager = new WalletManager({
  wallets: [
    WalletId.PERA,
    WalletId.DEFLY,
    WalletId.LUTE,
  ],
  networks,
  defaultNetwork: NetworkId.TESTNET,
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ToastProvider>
      <WalletProvider manager={walletManager}>
        <App />
      </WalletProvider>
    </ToastProvider>
  </React.StrictMode>,
)
