import { Contract } from '@algorandfoundation/tealscript';

const TREE_DEPTH = 16;
const ROOT_HISTORY_SIZE = 1000;

class PrivacyPool extends Contract {
  // Global state
  currentRoot = GlobalStateKey<bytes>({ key: 'root' });
  nextIndex = GlobalStateKey<uint64>({ key: 'next_idx' });
  denomination = GlobalStateKey<uint64>({ key: 'denom' });
  assetId = GlobalStateKey<uint64>({ key: 'asset_id' });
  rootHistoryIndex = GlobalStateKey<uint64>({ key: 'rhi' });
  verifierAppId = GlobalStateKey<uint64>({ key: 'vrf_app' });
  insertionVerifierAppId = GlobalStateKey<uint64>({ key: 'ins_vrf' });
  privateSendVerifierAppId = GlobalStateKey<uint64>({ key: 'ps_vrf' });

  // PLONK LogicSig verifier addresses (set to zero-address to use app-based verifier)
  plonkVerifierAddr = GlobalStateKey<Address>({ key: 'pv_addr' });
  plonkDepositVerifierAddr = GlobalStateKey<Address>({ key: 'pd_addr' });
  plonkPrivateSendVerifierAddr = GlobalStateKey<Address>({ key: 'pp_addr' });

  // Box storage — no on-chain tree; MiMC root is computed off-chain and passed in
  commitments = BoxMap<uint64, bytes>({ prefix: 'cmt' });
  nullifiers = BoxMap<bytes, bytes>({ prefix: 'null' });
  rootHistory = BoxMap<uint64, bytes>({ prefix: 'root' });
  knownRoots = BoxMap<bytes, bytes>({ prefix: 'kr' });


  /**
   * Initialize the privacy pool.
   */
  createApplication(denomination: uint64, assetId: uint64, verifierAppId: uint64, insertionVerifierAppId: uint64, privateSendVerifierAppId: uint64): void {
    this.denomination.value = denomination;
    this.assetId.value = assetId;
    this.verifierAppId.value = verifierAppId;
    this.insertionVerifierAppId.value = insertionVerifierAppId;
    this.privateSendVerifierAppId.value = privateSendVerifierAppId;
    this.nextIndex.value = 0;
    this.rootHistoryIndex.value = 0;

    // MiMC empty tree root for depth 16 (precomputed: all zero leaves)
    this.currentRoot.value = hex('1a781c1159b0f76ac76b5d8fe1ddf457f75d0033fef4d6f44f2c7787825c3229');

    // PLONK verifier addresses default to zero (use app-based verifier until set)
    this.plonkVerifierAddr.value = Address.zeroAddress;
    this.plonkDepositVerifierAddr.value = Address.zeroAddress;
    this.plonkPrivateSendVerifierAddr.value = Address.zeroAddress;
  }

  /**
   * Set PLONK LogicSig verifier addresses (creator only, one-time setup).
   * Once set, the contract will accept LogicSig-based verification instead of app calls.
   */
  setPlonkVerifiers(withdrawAddr: Address, depositAddr: Address, privateSendAddr: Address): void {
    assert(this.txn.sender === this.app.creator);
    assert(this.plonkVerifierAddr.value === Address.zeroAddress); // one-shot only
    this.plonkVerifierAddr.value = withdrawAddr;
    this.plonkDepositVerifierAddr.value = depositAddr;
    this.plonkPrivateSendVerifierAddr.value = privateSendAddr;
  }

  /**
   * Deposit funds into the privacy pool.
   * Commitment = MiMC(secret, nullifier) computed off-chain.
   * mimcRoot = new MiMC Merkle root after inserting this commitment (computed off-chain).
   * Must be accompanied by a payment of exactly the pool's denomination.
   */
  deposit(commitment: bytes, mimcRoot: bytes): void {
    assert(len(commitment) === 32);
    assert(len(mimcRoot) === 32);

    // Verify insertion proof in a preceding transaction.
    // Supports two modes:
    //   1. App-based verifier (Groth16): preceding txn is an app call to insertionVerifierAppId
    //   2. LogicSig verifier (PLONK): preceding txn is a payment signed by plonkDepositVerifierAddr
    assert(this.txn.groupIndex > 1);
    const verifierTxn = this.txnGroup[this.txn.groupIndex - 2];

    if (this.plonkDepositVerifierAddr.value !== Address.zeroAddress
        && verifierTxn.typeEnum === TransactionType.Payment
        && verifierTxn.sender === this.plonkDepositVerifierAddr.value) {
      // PLONK LogicSig mode: verifier ran as LogicSig, signals in Note field
    } else {
      // App-based verifier mode (Groth16)
      assert(verifierTxn.typeEnum === TransactionType.ApplicationCall);
      assert(verifierTxn.applicationID === AppID.fromUint64(this.insertionVerifierAppId.value));
      assert(verifierTxn.sender === this.txn.sender);
    }

    // Verify all 4 public signals match
    // Signals layout: 0-32 oldRoot, 32-64 newRoot, 64-96 commitment, 96-128 leafIndex
    // In app mode: signals are in applicationArgs[1]. In LogicSig mode: signals are in Note field.
    const signals = verifierTxn.typeEnum === TransactionType.Payment
      ? verifierTxn.note
      : verifierTxn.applicationArgs[1];
    assert(extract3(signals, 0, 32) === this.currentRoot.value);
    assert(extract3(signals, 32, 32) === mimcRoot);
    assert(extract3(signals, 64, 32) === commitment);
    const leafIndex = this.nextIndex.value;
    assert(extract3(signals, 96, 32) === concat(hex('000000000000000000000000000000000000000000000000'), itob(leafIndex)));

    // Verify payment in the preceding transaction — must match pool denomination exactly
    const payTxn = this.txnGroup[this.txn.groupIndex - 1];
    assert(payTxn.sender === this.txn.sender);
    if (this.assetId.value === 0) {
      verifyPayTxn(payTxn, {
        receiver: this.app.address,
      });
      assert(payTxn.amount === this.denomination.value);
    } else {
      verifyAssetTransferTxn(payTxn, {
        assetReceiver: this.app.address,
        xferAsset: AssetID.fromUint64(this.assetId.value),
      });
      assert(payTxn.amount === this.denomination.value);
    }

    // Store commitment
    assert(leafIndex < (1 << TREE_DEPTH));
    this.commitments(leafIndex).value = commitment;

    // Accept the verified MiMC root
    this.currentRoot.value = mimcRoot;

    // Increment leaf counter
    this.nextIndex.value = leafIndex + 1;

    // Store new root in history (ring buffer) and O(1) lookup map.
    // Evict the old root from knownRoots when the ring buffer slot is reused.
    const histIdx = this.rootHistoryIndex.value;
    const slot = histIdx % ROOT_HISTORY_SIZE;
    if (histIdx >= ROOT_HISTORY_SIZE && this.rootHistory(slot).exists) {
      const evictedRoot = this.rootHistory(slot).value;
      if (this.knownRoots(evictedRoot).exists) {
        this.knownRoots(evictedRoot).delete();
      }
    }
    this.rootHistory(slot).value = mimcRoot;
    this.knownRoots(mimcRoot).value = hex('01');
    this.rootHistoryIndex.value = histIdx + 1;

  }

  /**
   * Withdraw funds from the privacy pool.
   * Requires a valid ZK proof verified by LogicSig in the same atomic group.
   * Always sends the pool's denomination — no amount parameter.
   */
  withdraw(
    nullifierHash: bytes,
    recipient: Address,
    relayer: Address,
    fee: uint64,
    root: bytes,
    recipientSignal: bytes,
    relayerSignal: bytes,
  ): void {
    // 1. Verify the root is known
    assert(this.isKnownRoot(root));

    // 2. Check nullifier hasn't been spent
    assert(!this.nullifiers(nullifierHash).exists);

    // 3. Record nullifier as spent
    this.nullifiers(nullifierHash).value = hex('01');

    // 4. Verify ZK verifier is the preceding transaction in this group.
    // Supports two modes:
    //   1. App-based verifier (Groth16): app call to verifierAppId
    //   2. LogicSig verifier (PLONK): payment signed by plonkVerifierAddr
    assert(this.txn.groupIndex > 0);
    const prevTxn = this.txnGroup[this.txn.groupIndex - 1];

    if (this.plonkVerifierAddr.value !== Address.zeroAddress
        && prevTxn.typeEnum === TransactionType.Payment
        && prevTxn.sender === this.plonkVerifierAddr.value) {
      // PLONK LogicSig mode
    } else {
      // App-based verifier mode (Groth16)
      assert(prevTxn.typeEnum === TransactionType.ApplicationCall);
      assert(prevTxn.applicationID === AppID.fromUint64(this.verifierAppId.value));
      assert(prevTxn.sender === this.txn.sender);
    }

    // 5. Verify ALL public signals match (prevents front-running / proof replay attacks)
    // Signals layout: 0-32 root, 32-64 nullifierHash, 64-96 recipient, 96-128 relayer, 128-160 fee, 160-192 amount
    // In app mode: signals in applicationArgs[1]. In LogicSig mode: signals in Note field.
    const signals = prevTxn.typeEnum === TransactionType.Payment
      ? prevTxn.note
      : prevTxn.applicationArgs[1];
    assert(extract3(signals, 0, 32) === root);
    assert(extract3(signals, 32, 32) === nullifierHash);
    assert(extract3(signals, 64, 32) === recipientSignal);
    assert(extract3(signals, 96, 32) === relayerSignal);
    assert(extract3(signals, 128, 32) === concat(hex('000000000000000000000000000000000000000000000000'), itob(fee)));
    assert(extract3(signals, 160, 32) === concat(hex('000000000000000000000000000000000000000000000000'), itob(this.denomination.value)));

    // 6. Send denomination minus fee to recipient
    const amount = this.denomination.value;
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

    // 7. Send fee to relayer (if applicable)
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

  }

  /**
   * Combined deposit + withdraw in one atomic operation.
   * Uses a single combined ZK proof (privateSend circuit) instead of two.
   * Saves ~0.228 ALGO by eliminating one verifier call.
   */
  privateSend(
    commitment: bytes,
    mimcRoot: bytes,
    nullifierHash: bytes,
    recipient: Address,
    relayer: Address,
    fee: uint64,
    recipientSignal: bytes,
    relayerSignal: bytes,
  ): void {
    assert(len(commitment) === 32);
    assert(len(mimcRoot) === 32);
    assert(len(nullifierHash) === 32);

    // Verify combined privateSend verifier call at groupIndex - 2.
    // Supports app-based (Groth16) or LogicSig (PLONK) verification.
    assert(this.txn.groupIndex > 1);
    const verifierTxn = this.txnGroup[this.txn.groupIndex - 2];

    if (this.plonkPrivateSendVerifierAddr.value !== Address.zeroAddress
        && verifierTxn.typeEnum === TransactionType.Payment
        && verifierTxn.sender === this.plonkPrivateSendVerifierAddr.value) {
      // PLONK LogicSig mode
    } else {
      // App-based verifier mode (Groth16)
      assert(verifierTxn.typeEnum === TransactionType.ApplicationCall);
      assert(verifierTxn.applicationID === AppID.fromUint64(this.privateSendVerifierAppId.value));
      assert(verifierTxn.sender === this.txn.sender);
    }

    // Verify all 9 public signals match
    // Layout: 0-32 oldRoot, 32-64 newRoot, 64-96 commitment, 96-128 leafIndex,
    //         128-160 nullifierHash, 160-192 recipient, 192-224 relayer, 224-256 fee, 256-288 amount
    const signals = verifierTxn.typeEnum === TransactionType.Payment
      ? verifierTxn.note
      : verifierTxn.applicationArgs[1];
    assert(extract3(signals, 0, 32) === this.currentRoot.value);
    assert(extract3(signals, 32, 32) === mimcRoot);
    assert(extract3(signals, 64, 32) === commitment);
    const leafIndex = this.nextIndex.value;
    assert(extract3(signals, 96, 32) === concat(hex('000000000000000000000000000000000000000000000000'), itob(leafIndex)));
    assert(extract3(signals, 128, 32) === nullifierHash);
    assert(extract3(signals, 160, 32) === recipientSignal);
    assert(extract3(signals, 192, 32) === relayerSignal);
    assert(extract3(signals, 224, 32) === concat(hex('000000000000000000000000000000000000000000000000'), itob(fee)));
    assert(extract3(signals, 256, 32) === concat(hex('000000000000000000000000000000000000000000000000'), itob(this.denomination.value)));

    // Verify payment at groupIndex - 1
    const payTxn = this.txnGroup[this.txn.groupIndex - 1];
    assert(payTxn.sender === this.txn.sender);
    if (this.assetId.value === 0) {
      verifyPayTxn(payTxn, {
        receiver: this.app.address,
      });
      assert(payTxn.amount === this.denomination.value);
    } else {
      verifyAssetTransferTxn(payTxn, {
        assetReceiver: this.app.address,
        xferAsset: AssetID.fromUint64(this.assetId.value),
      });
      assert(payTxn.amount === this.denomination.value);
    }

    // Check nullifier hasn't been spent (checks before effects)
    assert(!this.nullifiers(nullifierHash).exists);
    this.nullifiers(nullifierHash).value = hex('01');

    // Store commitment and update tree
    assert(leafIndex < (1 << TREE_DEPTH));
    this.commitments(leafIndex).value = commitment;
    this.currentRoot.value = mimcRoot;
    this.nextIndex.value = leafIndex + 1;

    // Store new root in history (ring buffer) and O(1) lookup map.
    // Evict the old root from knownRoots when the ring buffer slot is reused.
    const histIdx = this.rootHistoryIndex.value;
    const slot = histIdx % ROOT_HISTORY_SIZE;
    if (histIdx >= ROOT_HISTORY_SIZE && this.rootHistory(slot).exists) {
      const evictedRoot = this.rootHistory(slot).value;
      if (this.knownRoots(evictedRoot).exists) {
        this.knownRoots(evictedRoot).delete();
      }
    }
    this.rootHistory(slot).value = mimcRoot;
    this.knownRoots(mimcRoot).value = hex('01');
    this.rootHistoryIndex.value = histIdx + 1;

    // Send denomination minus fee to recipient
    const amount = this.denomination.value;
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

  }

  /**
   * Check if a root is known — O(1) box existence check.
   */
  private isKnownRoot(root: bytes): boolean {
    if (root === this.currentRoot.value) return true;
    return this.knownRoots(root).exists;
  }

  /**
   * Opt into an ASA (required before the pool can receive ASA deposits).
   */
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

  /**
   * Block contract updates — contract is immutable after deployment.
   */
  updateApplication(): void {
    assert(false);
  }

  /**
   * Block contract deletion — pool funds must remain accessible.
   */
  deleteApplication(): void {
    assert(false);
  }
}

export default PrivacyPool;
