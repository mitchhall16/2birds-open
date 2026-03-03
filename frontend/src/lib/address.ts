import { bech32 } from 'bech32'
import algosdk from 'algosdk'
import { getViewPublicKey } from './keys'

const HRP = 'priv'
const VERSION = 0x01
const NETWORK_TESTNET = 0x01
const NETWORK_MAINNET = 0x00

/**
 * Encode a privacy address in bech32 format: priv1...
 *
 * Payload: | version (1B) | network (1B) | algo_pubkey (32B) | view_pubkey (32B) | = 66 bytes
 */
export function encodePrivacyAddress(
  algoPubkey: Uint8Array,
  viewPubkey: Uint8Array,
  network: number = NETWORK_TESTNET,
): string {
  if (algoPubkey.length !== 32) throw new Error('algoPubkey must be 32 bytes')
  if (viewPubkey.length !== 32) throw new Error('viewPubkey must be 32 bytes')

  const payload = new Uint8Array(66)
  payload[0] = VERSION
  payload[1] = network
  payload.set(algoPubkey, 2)
  payload.set(viewPubkey, 34)

  const words = bech32.toWords(payload)
  return bech32.encode(HRP, words, 1023) // 1023 char limit for bech32
}

/**
 * Decode a priv1... privacy address back to its components.
 */
export function decodePrivacyAddress(addr: string): {
  version: number
  network: number
  algoPubkey: Uint8Array
  viewPubkey: Uint8Array
} {
  const { prefix, words } = bech32.decode(addr, 1023)
  if (prefix !== HRP) throw new Error(`Invalid privacy address prefix: expected "${HRP}", got "${prefix}"`)

  const payload = new Uint8Array(bech32.fromWords(words))
  if (payload.length !== 66) throw new Error(`Invalid privacy address payload length: expected 66, got ${payload.length}`)

  const version = payload[0]
  if (version !== VERSION) throw new Error(`Unsupported privacy address version: ${version}`)

  return {
    version,
    network: payload[1],
    algoPubkey: payload.slice(2, 34),
    viewPubkey: payload.slice(34, 66),
  }
}

/**
 * Extract the Algorand address string from a privacy address.
 */
export function algoAddressFromPrivacyAddress(addr: string): string {
  const { algoPubkey } = decodePrivacyAddress(addr)
  return algosdk.encodeAddress(algoPubkey)
}

/**
 * Build a priv1... privacy address from a wallet's Algorand address and master key.
 */
export function privacyAddressFromWallet(algoAddress: string, masterKey: bigint): string {
  const algoPubkey = algosdk.decodeAddress(algoAddress).publicKey
  const viewPubkey = getViewPublicKey(masterKey)
  return encodePrivacyAddress(algoPubkey, viewPubkey)
}

/**
 * Check if a string is a valid priv1... privacy address.
 */
export function isPrivacyAddress(addr: string): boolean {
  try {
    decodePrivacyAddress(addr)
    return true
  } catch {
    return false
  }
}
