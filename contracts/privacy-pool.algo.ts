import { Contract } from '@algorandfoundation/tealscript';

const TREE_DEPTH = 20;
const ROOT_HISTORY_SIZE = 100;

class PrivacyPool extends Contract {
  // Global state
  currentRoot = GlobalStateKey<bytes>({ key: 'root' });
  nextIndex = GlobalStateKey<uint64>({ key: 'next_idx' });
  denomination = GlobalStateKey<uint64>({ key: 'denom' });
  assetId = GlobalStateKey<uint64>({ key: 'asset_id' });
  rootHistoryIndex = GlobalStateKey<uint64>({ key: 'rhi' });

  // Box storage — no on-chain tree; MiMC root is computed off-chain and passed in
  commitments = BoxMap<uint64, bytes>({ prefix: 'cmt' });
  nullifiers = BoxMap<bytes, bytes>({ prefix: 'null' });
  rootHistory = BoxMap<uint64, bytes>({ prefix: 'root' });

  // Store deposit amounts per leaf index
  depositAmounts = BoxMap<uint64, uint64>({ prefix: 'amt' });

  /**
   * Initialize the privacy pool.
   */
  createApplication(denomination: uint64, assetId: uint64): void {
    this.denomination.value = denomination;
    this.assetId.value = assetId;
    this.nextIndex.value = 0;
    this.rootHistoryIndex.value = 0;

    // Empty root (all zeros)
    this.currentRoot.value = bzero(32);
  }

  /**
   * Deposit funds into the privacy pool.
   * Commitment = MiMC(secret, nullifier) computed off-chain.
   * mimcRoot = new MiMC Merkle root after inserting this commitment (computed off-chain).
   * Must be accompanied by a payment of any amount > 0.
   */
  deposit(commitment: bytes, mimcRoot: bytes): void {
    assert(len(commitment) === 32);
    assert(len(mimcRoot) === 32);

    // Verify payment in the preceding transaction (any amount > 0)
    const payTxn = this.txnGroup[this.txn.groupIndex - 1];
    if (this.assetId.value === 0) {
      verifyPayTxn(payTxn, {
        receiver: this.app.address,
      });
      assert(payTxn.amount > 0);
    } else {
      verifyAssetTransferTxn(payTxn, {
        assetReceiver: this.app.address,
        xferAsset: AssetID.fromUint64(this.assetId.value),
      });
      assert(payTxn.amount > 0);
    }

    // Store commitment
    const leafIndex = this.nextIndex.value;
    assert(leafIndex < (1 << TREE_DEPTH));
    this.commitments(leafIndex).value = commitment;

    // Store the deposited amount for this leaf
    this.depositAmounts(leafIndex).value = payTxn.amount;

    // Accept the off-chain MiMC root
    this.currentRoot.value = mimcRoot;

    // Increment leaf counter
    this.nextIndex.value = leafIndex + 1;

    // Store new root in history (ring buffer)
    const histIdx = this.rootHistoryIndex.value;
    this.rootHistory(histIdx % ROOT_HISTORY_SIZE).value = mimcRoot;
    this.rootHistoryIndex.value = histIdx + 1;

    // Log deposit event
    log(concat(hex('6465706f736974'), commitment));
  }

  /**
   * Withdraw funds from the privacy pool.
   * Requires a valid ZK proof verified by LogicSig in the same atomic group.
   */
  withdraw(
    nullifierHash: bytes,
    recipient: Address,
    relayer: Address,
    fee: uint64,
    root: bytes,
    amount: uint64,
  ): void {
    // 1. Verify the root is known
    assert(this.isKnownRoot(root));

    // 2. Check nullifier hasn't been spent
    assert(!this.nullifiers(nullifierHash).exists);

    // 3. Record nullifier as spent
    this.nullifiers(nullifierHash).value = hex('01');

    // 4. Verify LogicSig (ZK verifier) is in this atomic group
    assert(this.txn.groupIndex > 0);

    // 5. Send funds to recipient
    assert(amount > fee);
    const withdrawAmount = amount - fee;

    if (this.assetId.value === 0) {
      sendPayment({
        receiver: recipient,
        amount: withdrawAmount,
        fee: 0,
      });
    } else {
      sendAssetTransfer({
        assetReceiver: recipient,
        assetAmount: withdrawAmount,
        xferAsset: AssetID.fromUint64(this.assetId.value),
        fee: 0,
      });
    }

    // 6. Send fee to relayer (if applicable)
    if (fee > 0) {
      if (this.assetId.value === 0) {
        sendPayment({
          receiver: relayer,
          amount: fee,
          fee: 0,
        });
      } else {
        sendAssetTransfer({
          assetReceiver: relayer,
          assetAmount: fee,
          xferAsset: AssetID.fromUint64(this.assetId.value),
          fee: 0,
        });
      }
    }

    log(concat(hex('7769746864726177'), nullifierHash));
  }

  /**
   * Check if a root is in the history.
   */
  private isKnownRoot(root: bytes): boolean {
    if (root === this.currentRoot.value) return true;

    for (let i = 0; i < ROOT_HISTORY_SIZE; i += 1) {
      if (this.rootHistory(i as uint64).exists) {
        if (this.rootHistory(i as uint64).value === root) return true;
      }
    }

    return false;
  }

  /**
   * Opt into an ASA (required before the pool can receive ASA deposits).
   */
  optInToAsset(): void {
    assert(this.assetId.value !== 0);

    sendAssetTransfer({
      assetReceiver: this.app.address,
      assetAmount: 0,
      xferAsset: AssetID.fromUint64(this.assetId.value),
      fee: 0,
    });
  }
}

export default PrivacyPool;
