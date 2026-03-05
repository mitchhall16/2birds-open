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
import { FalconProvider } from './contexts/FalconContext'
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
    {
      id: WalletId.WALLETCONNECT,
      options: {
        projectId: '2e4ff65c141a7b579c4faa40fab12821',
        themeMode: 'dark' as const,
      },
    },
  ],
  networks,
  defaultNetwork: NetworkId.TESTNET,
})

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ToastProvider>
      <WalletProvider manager={walletManager}>
        <FalconProvider>
          <App />
        </FalconProvider>
      </WalletProvider>
    </ToastProvider>
  </React.StrictMode>,
)
