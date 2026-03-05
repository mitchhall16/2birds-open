import { Contract } from '@algorandfoundation/tealscript';

const TREE_DEPTH = 20;
const ROOT_HISTORY_SIZE = 100;

class ShieldedPool extends Contract {
  currentRoot = GlobalStateKey<bytes>({ key: 'root' });
  nextIndex = GlobalStateKey<uint64>({ key: 'next_idx' });
  assetId = GlobalStateKey<uint64>({ key: 'asset_id' });
  rootHistoryIndex = GlobalStateKey<uint64>({ key: 'rhi' });

  // Verifier state (dual-mode: LogicSig or app-based)
  verifierAppId = GlobalStateKey<uint64>({ key: 'vrf_app' });
  plonkVerifierAddr = GlobalStateKey<Address>({ key: 'pv_addr' });

  // Fixed denomination tier for this pool (0 = any amount, for backwards compat)
  denomination = GlobalStateKey<uint64>({ key: 'denom' });

  // Box storage
  treeFrontier = BoxMap<uint64, bytes>({ prefix: 'tree' });
  nullifiers = BoxMap<bytes, bytes>({ prefix: 'null' });
  rootHistory = BoxMap<uint64, bytes>({ prefix: 'root' });
  knownRoots = BoxMap<bytes, bytes>({ prefix: 'kr' });
  zeroHashes = BoxMap<uint64, bytes>({ prefix: 'zero' });

  createApplication(assetId: uint64, verifierAppId: uint64, denomination: uint64): void {
    this.assetId.value = assetId;
    this.verifierAppId.value = verifierAppId;
    this.denomination.value = denomination;
    this.nextIndex.value = 0;
    this.rootHistoryIndex.value = 0;
    this.currentRoot.value = bzero(32);
    this.plonkVerifierAddr.value = Address.zeroAddress;
  }

  /**
   * Initialize zero hashes for the Merkle tree (creator only, once).
   * zeroHash[0] = sha256(bzero(32) || bzero(32)), zeroHash[i] = sha256(zeroHash[i-1] || zeroHash[i-1])
   * Must be called before any deposits.
   */
  initZeroHashes(): void {
    assert(this.txn.sender === this.app.creator);
    assert(!this.zeroHashes(0).exists); // One-shot

    let h = bzero(32);
    for (let level = 0; level < TREE_DEPTH; level += 1) {
      const lvl = level as uint64;
      this.zeroHashes(lvl).value = h;
      h = rawBytes(sha256(concat(h, h)));
    }

    // Set initial root to the empty tree root
    this.currentRoot.value = h;
  }

  /**
   * Set PLONK LogicSig verifier address (creator only, one-shot).
   * Once set, the address is immutable.
   */
  setPlonkVerifier(addr: Address): void {
    assert(this.txn.sender === this.app.creator);
    assert(this.plonkVerifierAddr.value === Address.zeroAddress);
    this.plonkVerifierAddr.value = addr;
  }

  /**
   * Verify that the preceding transaction is a valid ZK proof verifier
   * AND that the proof's public signals match the expected values.
   * Supports LogicSig (PLONK) or app call (Groth16).
   *
   * Signal binding prevents proof replay / parameter substitution attacks.
   */
  private verifyProofWithSignals(expectedSignals: bytes): void {
    assert(this.txn.groupIndex > 0);
    const verifierTxn = this.txnGroup[this.txn.groupIndex - 1];

    let signals: bytes;

    if (this.plonkVerifierAddr.value !== Address.zeroAddress
        && verifierTxn.typeEnum === TransactionType.Payment
        && verifierTxn.sender === this.plonkVerifierAddr.value) {
      // PLONK LogicSig mode: proof verified by LogicSig, signals in Note
      assert(verifierTxn.amount === 0);
      signals = verifierTxn.note;
    } else {
      // App-based verifier mode (Groth16), signals in applicationArgs[1]
      assert(verifierTxn.typeEnum === TransactionType.ApplicationCall);
      assert(verifierTxn.applicationID === AppID.fromUint64(this.verifierAppId.value));
      signals = verifierTxn.applicationArgs[1];
    }

    // Verify all public signals match expected values
    assert(signals === expectedSignals);
  }

  /**
   * Shield — deposit funds, create a shielded UTXO note.
   */
  shield(commitment: bytes, amount: uint64): void {
    assert(len(commitment) === 32);

    // Enforce fixed denomination (prevents commitment-amount mismatch attack)
    assert(this.denomination.value > 0);
    assert(amount === this.denomination.value);

    const payTxn = this.txnGroup[this.txn.groupIndex - 1];
    if (this.assetId.value === 0) {
      verifyPayTxn(payTxn, {
        receiver: this.app.address,
        amount: amount,
      });
    } else {
      verifyAssetTransferTxn(payTxn, {
        assetReceiver: this.app.address,
        assetAmount: amount,
        xferAsset: AssetID.fromUint64(this.assetId.value),
      });
    }

    const idx = this.nextIndex.value;
    assert(idx < (1 << TREE_DEPTH));
    this.insertLeaf(commitment, idx);
    this.nextIndex.value = idx + 1;

    // Record root in history with O(1) lookup
    const histIdx = this.rootHistoryIndex.value;
    const rootSlot = histIdx % ROOT_HISTORY_SIZE;
    // Evict old root from knownRoots if slot is being reused
    // Guard: don't evict the current root (could still be referenced by other slots)
    if (this.rootHistory(rootSlot).exists) {
      const evictedRoot = this.rootHistory(rootSlot).value;
      if (evictedRoot !== this.currentRoot.value && this.knownRoots(evictedRoot).exists) {
        this.knownRoots(evictedRoot).delete();
      }
    }
    this.rootHistory(rootSlot).value = this.currentRoot.value;
    this.knownRoots(this.currentRoot.value).value = hex('01');
    this.rootHistoryIndex.value = histIdx + 1;

    log(concat(hex('736869656c64'), commitment));
  }

  /**
   * Transfer — consume input notes, create output notes (2-in/2-out).
   * ZK proof must be verified by a preceding verifier transaction.
   */
  transfer(
    nullifierHash1: bytes,
    nullifierHash2: bytes,
    outputCommitment1: bytes,
    outputCommitment2: bytes,
    proof_root: bytes,
    relayer: Address,
    fee: uint64,
  ): void {
    // Validate lengths
    assert(len(nullifierHash1) === 32);
    assert(len(nullifierHash2) === 32);
    assert(len(outputCommitment1) === 32);
    assert(len(outputCommitment2) === 32);
    assert(len(proof_root) === 32);
    assert(this.isKnownRoot(proof_root));
    assert(nullifierHash1 !== nullifierHash2);

    // Build expected signals and verify proof binds to them
    // Signals: root(32) + nullifierHash1(32) + nullifierHash2(32) + outputCommitment1(32) + outputCommitment2(32) + relayer(32) + fee(32)
    const expectedSignals = concat(
      concat(
        concat(concat(proof_root, nullifierHash1), nullifierHash2),
        concat(outputCommitment1, outputCommitment2),
      ),
      concat(rawBytes(relayer), concat(bzero(24), itob(fee))),
    );
    this.verifyProofWithSignals(expectedSignals);

    // Check and record nullifiers
    assert(!this.nullifiers(nullifierHash1).exists);
    this.nullifiers(nullifierHash1).value = hex('01');
    assert(!this.nullifiers(nullifierHash2).exists);
    this.nullifiers(nullifierHash2).value = hex('01');

    // Insert output commitments
    let idx = this.nextIndex.value;
    this.insertLeaf(outputCommitment1, idx);
    idx = idx + 1;
    this.insertLeaf(outputCommitment2, idx);
    idx = idx + 1;

    this.nextIndex.value = idx;

    // Record root in history with O(1) lookup
    const histIdx = this.rootHistoryIndex.value;
    const rootSlot = histIdx % ROOT_HISTORY_SIZE;
    if (this.rootHistory(rootSlot).exists) {
      const evictedRoot = this.rootHistory(rootSlot).value;
      if (evictedRoot !== this.currentRoot.value && this.knownRoots(evictedRoot).exists) {
        this.knownRoots(evictedRoot).delete();
      }
    }
    this.rootHistory(rootSlot).value = this.currentRoot.value;
    this.knownRoots(this.currentRoot.value).value = hex('01');
    this.rootHistoryIndex.value = histIdx + 1;

    log(hex('7472616e73666572'));
  }

  /**
   * Unshield — withdraw funds by consuming a shielded note.
   * ZK proof must be verified by a preceding verifier transaction.
   */
  unshield(
    nullifierHash: bytes,
    recipient: Address,
    amount: uint64,
    changeCommitment: bytes,
    proof_root: bytes,
  ): void {
    assert(len(nullifierHash) === 32);
    assert(len(proof_root) === 32);
    assert(this.isKnownRoot(proof_root));

    // changeCommitment must be exactly 32 bytes or empty (no change)
    assert(len(changeCommitment) === 32 || len(changeCommitment) === 0);

    // Build expected signals and verify proof binds to them
    // Signals: root(32) + nullifierHash(32) + recipient(32) + amount(32) + changeCommitment(32)
    const changeBytes = len(changeCommitment) === 32 ? changeCommitment : bzero(32);
    const expectedSignals = concat(
      concat(
        concat(proof_root, nullifierHash),
        concat(rawBytes(recipient), concat(bzero(24), itob(amount))),
      ),
      changeBytes,
    );
    this.verifyProofWithSignals(expectedSignals);

    assert(!this.nullifiers(nullifierHash).exists);
    this.nullifiers(nullifierHash).value = hex('01');

    // If there's a change note, add it back to the tree
    if (len(changeCommitment) === 32) {
      const idx = this.nextIndex.value;
      this.insertLeaf(changeCommitment, idx);
      this.nextIndex.value = idx + 1;

      const histIdx = this.rootHistoryIndex.value;
      const rootSlot = histIdx % ROOT_HISTORY_SIZE;
      if (this.rootHistory(rootSlot).exists) {
        const evictedRoot = this.rootHistory(rootSlot).value;
        if (evictedRoot !== this.currentRoot.value && this.knownRoots(evictedRoot).exists) {
          this.knownRoots(evictedRoot).delete();
        }
      }
      this.rootHistory(rootSlot).value = this.currentRoot.value;
      this.knownRoots(this.currentRoot.value).value = hex('01');
      this.rootHistoryIndex.value = histIdx + 1;
    }

    if (this.assetId.value === 0) {
      sendPayment({ receiver: recipient, amount: amount, fee: 0 });
    } else {
      sendAssetTransfer({
        assetReceiver: recipient,
        assetAmount: amount,
        xferAsset: AssetID.fromUint64(this.assetId.value),
        fee: 0,
      });
    }

    log(concat(hex('756e736869656c64'), nullifierHash));
  }

  /** O(1) root lookup using knownRoots BoxMap */
  private isKnownRoot(root: bytes): boolean {
    if (root === this.currentRoot.value) return true;
    return this.knownRoots(root).exists;
  }

  private insertLeaf(leaf: bytes, index: uint64): void {
    let currentHash = leaf;
    let currentIndex = index;

    for (let level = 0; level < TREE_DEPTH; level += 1) {
      const lvl = level as uint64;
      if (currentIndex % 2 === 0) {
        this.treeFrontier(lvl).value = currentHash;
        const zeroHash = this.zeroHashes(lvl).exists
          ? this.zeroHashes(lvl).value
          : bzero(32);
        currentHash = rawBytes(sha256(concat(currentHash, zeroHash)));
      } else {
        const leftSibling = this.treeFrontier(lvl).value;
        currentHash = rawBytes(sha256(concat(leftSibling, currentHash)));
      }
      currentIndex = currentIndex / 2;
    }

    this.currentRoot.value = currentHash;
  }

  optInToAsset(): void {
    assert(this.txn.sender === this.app.creator);
    assert(this.assetId.value !== 0);
    sendAssetTransfer({
      assetReceiver: this.app.address,
      assetAmount: 0,
      xferAsset: AssetID.fromUint64(this.assetId.value),
      fee: 0,
    });
  }

  updateApplication(): void {
    assert(false);
  }

  deleteApplication(): void {
    assert(false);
  }
}

export default ShieldedPool;
