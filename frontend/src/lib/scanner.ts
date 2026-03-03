import algosdk from 'algosdk'
import { INDEXER_CONFIG } from './config'
import { checkViewTag, decryptNote, HPKE_ENVELOPE_LEN, type TxnMetadata } from './hpke'
import { mimcHashTriple, initMimc, scalarToBytes, type DepositNote } from './privacy'

/**
 * Scan confirmed transactions for HPKE-encrypted notes addressed to the given view key.
 *
 * Algorithm:
 * 1. Use indexer to search transactions for each pool app ID
 * 2. For each transaction with a note field >= 190 bytes:
 *    a. Parse the HPKE envelope header (version, suite)
 *    b. Fast check: compute view tag, compare (skip if mismatch)
 *    c. Full decrypt: HPKE open, deserialize note
 *    d. Verify: recompute commitment from decrypted values
 * 3. Return all recovered notes
 */
export async function scanChainForNotes(
  viewKeypair: { privateKey: Uint8Array; publicKey: Uint8Array },
  poolAppIds: number[],
  fromRound?: number,
  onProgress?: (round: number, found: number) => void,
): Promise<DepositNote[]> {
  await initMimc()

  const indexer = new algosdk.Indexer(
    INDEXER_CONFIG.token,
    INDEXER_CONFIG.baseServer,
    INDEXER_CONFIG.port,
  )

  const recovered: DepositNote[] = []
  let lastRound = 0

  for (const appId of poolAppIds) {
    let nextToken: string | undefined
    let hasMore = true

    while (hasMore) {
      // Search for application transactions
      let query = indexer.searchForTransactions()
        .applicationID(appId)
        .txType('appl')
        .limit(100)

      if (fromRound !== undefined && fromRound > 0) {
        query = query.minRound(fromRound)
      }
      if (nextToken) {
        query = query.nextToken(nextToken)
      }

      let response: any
      try {
        response = await query.do()
      } catch {
        break // Indexer error, skip this pool
      }

      const txns = response.transactions || []
      if (txns.length === 0) {
        hasMore = false
        break
      }

      for (const txn of txns) {
        const round = txn['confirmed-round'] || txn.confirmedRound || 0
        if (round > lastRound) lastRound = round

        // Check for note field with HPKE envelope
        const noteB64 = txn.note || txn['application-transaction']?.note
        if (!noteB64) continue

        let noteBytes: Uint8Array
        try {
          noteBytes = typeof noteB64 === 'string'
            ? Uint8Array.from(atob(noteB64), c => c.charCodeAt(0))
            : new Uint8Array(noteB64)
        } catch {
          continue
        }

        if (noteBytes.length < HPKE_ENVELOPE_LEN) continue

        // Extract txn metadata for view tag verification
        const appTxn = txn['application-transaction'] || txn.applicationTransaction || {}
        const innerTxns = txn['inner-txns'] || txn.innerTxns || []
        const sender = txn.sender || ''
        let senderPubkey: Uint8Array
        try {
          senderPubkey = algosdk.decodeAddress(sender).publicKey
        } catch {
          continue
        }

        const firstValid = txn['first-valid'] || txn.firstValid || 0
        const lastValid = txn['last-valid'] || txn.lastValid || 0

        const txnMeta: TxnMetadata = {
          senderPubkey,
          firstValid,
          lastValid,
        }

        // Fast view tag check
        if (!checkViewTag(noteBytes, viewKeypair.privateKey, txnMeta)) {
          continue
        }

        // Full HPKE decrypt
        const decrypted = await decryptNote(noteBytes, viewKeypair.privateKey, txnMeta)
        if (!decrypted) continue

        // Verify commitment: recompute from decrypted values
        const recomputedCommitment = mimcHashTriple(
          decrypted.secret,
          decrypted.nullifier,
          decrypted.denomination,
        )

        const note: DepositNote = {
          secret: decrypted.secret,
          nullifier: decrypted.nullifier,
          commitment: recomputedCommitment,
          leafIndex: decrypted.leafIndex,
          denomination: decrypted.denomination,
          assetId: 0,
          timestamp: Date.now(),
          appId,
        }

        recovered.push(note)
        onProgress?.(lastRound, recovered.length)
      }

      nextToken = response['next-token'] || response.nextToken
      if (!nextToken) {
        hasMore = false
      }
    }
  }

  onProgress?.(lastRound, recovered.length)
  return recovered
}
