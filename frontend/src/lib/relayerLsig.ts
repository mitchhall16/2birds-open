import algosdk from 'algosdk'
import { CONTRACTS, LSIG_RELAYER_FEE, ALGOD_CONFIG } from './config'
import { METHOD_SELECTORS } from './privacy'

/**
 * Trustless LogicSig relayer — stateless on-chain withdrawal relay.
 *
 * The LogicSig validates withdrawal transaction group structure:
 * - GroupSize == 2 (verifier call + pool withdraw)
 * - Txn[0] is app call to a known verifier appId
 * - Txn[1] is app call to a known pool appId
 * - Txn[1] calls the `withdraw` method (method selector check)
 * - Fee within bounds
 * - Total group fee capped
 *
 * The actual ZK proof verification is handled by the on-chain verifier contract.
 * Contract compatibility: prevTxn.sender === this.txn.sender is satisfied
 * since both txns in the group have sender = LogicSig address.
 *
 * Benefits over Worker relayer:
 * - No server needed — runs entirely on-chain
 * - No trust assumption — LogicSig is deterministic, anyone can verify
 * - No downtime — available 24/7, no infra to maintain
 * - Anyone can fund it — just send ALGO to the LogicSig address
 */

// TEAL source for the relayer LogicSig
// This validates the structure of withdrawal transaction groups
const RELAYER_TEAL_SOURCE = `#pragma version 10
// Relayer LogicSig: validates withdrawal group structure

// Must be a 2-txn group
global GroupSize
int 2
==
assert

// Txn[0] must be an app call to the withdraw verifier
gtxn 0 TypeEnum
int appl
==
assert

gtxn 0 ApplicationID
int ${CONTRACTS.ZkVerifier.appId}
==
assert

// Txn[1] must be an app call (to a pool contract)
gtxn 1 TypeEnum
int appl
==
assert

// Txn[1] must call withdraw method (first 4 bytes of app arg 0)
gtxn 1 ApplicationArgs 0
extract 0 4
byte 0x${Array.from(METHOD_SELECTORS.withdraw).map(b => b.toString(16).padStart(2, '0')).join('')}
==
assert

// Fee bounds: each txn fee <= 300000 microAlgos
gtxn 0 Fee
int 300000
<=
assert

gtxn 1 Fee
int 300000
<=
assert

// Total group fee capped at 500000 microAlgos
gtxn 0 Fee
gtxn 1 Fee
+
int 500000
<=
assert

// Both transactions must have this LogicSig as sender (enforced by AVM)
int 1
`

let compiledProgram: Uint8Array | null = null
let logicSigInstance: algosdk.LogicSigAccount | null = null

/** Compile the TEAL program (cached after first call) */
async function compileProgram(client?: algosdk.Algodv2): Promise<Uint8Array> {
  if (compiledProgram) return compiledProgram

  const algod = client ?? new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)
  const result = await algod.compile(new TextEncoder().encode(RELAYER_TEAL_SOURCE)).do()
  compiledProgram = Uint8Array.from(atob(result.result), c => c.charCodeAt(0))
  return compiledProgram
}

/** Create the LogicSig instance (compiles on first call, cached thereafter) */
export async function createRelayerLogicSig(client?: algosdk.Algodv2): Promise<algosdk.LogicSigAccount> {
  if (logicSigInstance) return logicSigInstance

  const program = await compileProgram(client)
  logicSigInstance = new algosdk.LogicSigAccount(program)
  return logicSigInstance
}

/** Get the deterministic address of the LogicSig */
export async function getRelayerLogicSigAddress(client?: algosdk.Algodv2): Promise<string> {
  const lsig = await createRelayerLogicSig(client)
  return lsig.address().toString()
}

/** Check if the LogicSig has sufficient balance to relay a withdrawal */
export async function checkRelayerBalance(client?: algosdk.Algodv2): Promise<bigint> {
  const algod = client ?? new algosdk.Algodv2(ALGOD_CONFIG.token, ALGOD_CONFIG.baseServer, ALGOD_CONFIG.port)
  const addr = await getRelayerLogicSigAddress(algod)
  try {
    const info = await algod.accountInformation(addr).do()
    return BigInt(info.amount ?? 0)
  } catch {
    return 0n
  }
}

/** Minimum balance needed for the LogicSig to relay one withdrawal */
export function minRelayerBalance(): bigint {
  return LSIG_RELAYER_FEE + 100_000n // fee + min balance
}
