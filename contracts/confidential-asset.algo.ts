import { Contract } from '@algorandfoundation/tealscript';

class ConfidentialAsset extends Contract {
  assetId = GlobalStateKey<uint64>({ key: 'asset_id' });
  totalDeposited = GlobalStateKey<uint64>({ key: 'total_dep' });
  totalWithdrawn = GlobalStateKey<uint64>({ key: 'total_wd' });

  // Range proof verifier (LogicSig address or app ID)
  rangeProofVerifierAddr = GlobalStateKey<Address>({ key: 'rp_addr' });
  rangeProofVerifierAppId = GlobalStateKey<uint64>({ key: 'rp_app' });

  // Box storage: balance commitments (BN254 G1 points, 64 bytes each)
  balances = BoxMap<Address, bytes>({ prefix: 'bal' });

  createApplication(assetId: uint64, rangeProofVerifierAppId: uint64): void {
    this.assetId.value = assetId;
    this.totalDeposited.value = 0;
    this.totalWithdrawn.value = 0;
    this.rangeProofVerifierAddr.value = Address.zeroAddress;
    this.rangeProofVerifierAppId.value = rangeProofVerifierAppId;
  }

  /**
   * Set range proof LogicSig verifier address (creator only, one-shot).
   * Once set, the address is immutable.
   */
  setRangeProofVerifier(addr: Address): void {
    assert(this.txn.sender === this.app.creator);
    assert(this.rangeProofVerifierAddr.value === Address.zeroAddress);
    this.rangeProofVerifierAddr.value = addr;
  }

  /**
   * Verify that the preceding transaction is a valid range proof verifier
   * AND that the proof's public signals match the expected values.
   * Supports LogicSig (PLONK) or app call (Groth16).
   *
   * Signal binding prevents proof replay / parameter substitution attacks.
   */
  private verifyRangeProofWithSignals(expectedSignals: bytes): void {
    assert(this.txn.groupIndex > 0);
    const verifierTxn = this.txnGroup[this.txn.groupIndex - 1];

    let signals: bytes;

    if (this.rangeProofVerifierAddr.value !== Address.zeroAddress
        && verifierTxn.typeEnum === TransactionType.Payment
        && verifierTxn.sender === this.rangeProofVerifierAddr.value) {
      // PLONK LogicSig mode: range proof verified by LogicSig, signals in Note
      assert(verifierTxn.amount === 0);
      signals = verifierTxn.note;
    } else {
      // App-based verifier mode (Groth16), signals in applicationArgs[1]
      assert(verifierTxn.typeEnum === TransactionType.ApplicationCall);
      assert(verifierTxn.applicationID === AppID.fromUint64(this.rangeProofVerifierAppId.value));
      signals = verifierTxn.applicationArgs[1];
    }

    // Verify all public signals match expected values
    assert(signals === expectedSignals);
  }

  /**
   * Shield — deposit public funds, create a Pedersen commitment.
   * Commitment = amount * G + blinding * H (64-byte BN254 G1 point)
   */
  shield(commitment: bytes, amount: uint64): void {
    assert(len(commitment) === 64);

    // Verify range proof binds commitment to deposited amount
    // Signals: commitment(64) + amount(8)
    const shieldSignals = concat(commitment, itob(amount));
    this.verifyRangeProofWithSignals(shieldSignals);

    // Payment must be 2 txns before (verifier is groupIndex-1, payment is groupIndex-2)
    assert(this.txn.groupIndex > 1);
    const payTxn = this.txnGroup[this.txn.groupIndex - 2];
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

    if (this.balances(this.txn.sender).exists) {
      // Add to existing: C_new = C_old + C_deposit via BN254 ec_add
      const existing = this.balances(this.txn.sender).value;
      const newCommitment = ecAdd('BN254g1', existing, commitment);
      this.balances(this.txn.sender).value = newCommitment;
    } else {
      this.balances(this.txn.sender).value = commitment;
    }

    this.totalDeposited.value = this.totalDeposited.value + amount;
    log(concat(hex('736869656c64'), commitment));
  }

  /**
   * Confidential transfer — transfer between shielded balances with hidden amount.
   * Range proof must be verified by a preceding verifier transaction.
   */
  confidentialTransfer(
    recipient: Address,
    senderNewCommitment: bytes,
    recipientNewCommitment: bytes,
    transferCommitment: bytes,
  ): void {
    assert(len(senderNewCommitment) === 64);
    assert(len(recipientNewCommitment) === 64);
    assert(len(transferCommitment) === 64);

    // Verify sender has a balance
    assert(this.balances(this.txn.sender).exists);

    // On-chain commitment arithmetic:
    // senderOld = senderNew + transferCommitment
    const senderOld = this.balances(this.txn.sender).value;
    const computedSenderOld = ecAdd('BN254g1', senderNewCommitment, transferCommitment);
    assert(senderOld === computedSenderOld);

    // recipientNew = recipientOld + transferCommitment
    if (this.balances(recipient).exists) {
      const recipientOld = this.balances(recipient).value;
      const computedRecipientNew = ecAdd('BN254g1', recipientOld, transferCommitment);
      assert(recipientNewCommitment === computedRecipientNew);
    } else {
      // New recipient: their commitment must equal the transfer commitment
      assert(recipientNewCommitment === transferCommitment);
    }

    // Verify range proof with signal binding
    // Signals: senderNewCommitment(64) + recipientNewCommitment(64) + transferCommitment(64) + recipient(32)
    const expectedSignals = concat(
      concat(senderNewCommitment, recipientNewCommitment),
      concat(transferCommitment, rawBytes(recipient)),
    );
    this.verifyRangeProofWithSignals(expectedSignals);

    this.balances(this.txn.sender).value = senderNewCommitment;
    this.balances(recipient).value = recipientNewCommitment;

    log(hex('7472616e73666572'));
  }

  /**
   * Unshield — withdraw from shielded balance to public.
   * Requires a range proof verifier in the preceding transaction to prove
   * that newCommitment = oldCommitment - amount*G (i.e., amount is valid).
   */
  unshield(amount: uint64, newCommitment: bytes): void {
    assert(len(newCommitment) === 64);
    assert(this.balances(this.txn.sender).exists);

    // Verify range proof with signal binding
    // Signals: oldCommitment(64) + newCommitment(64) + amount(8)
    const oldCommitment = this.balances(this.txn.sender).value;
    const expectedSignals = concat(
      concat(oldCommitment, newCommitment),
      itob(amount),
    );
    this.verifyRangeProofWithSignals(expectedSignals);

    // Update or delete balance
    if (newCommitment === rawBytes(bzero(64))) {
      this.balances(this.txn.sender).delete();
    } else {
      this.balances(this.txn.sender).value = newCommitment;
    }

    if (this.assetId.value === 0) {
      sendPayment({ receiver: this.txn.sender, amount: amount, fee: 0 });
    } else {
      sendAssetTransfer({
        assetReceiver: this.txn.sender,
        assetAmount: amount,
        xferAsset: AssetID.fromUint64(this.assetId.value),
        fee: 0,
      });
    }

    this.totalWithdrawn.value = this.totalWithdrawn.value + amount;
    log(concat(hex('756e736869656c64'), itob(amount)));
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

export default ConfidentialAsset;
