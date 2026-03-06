/**
 * @2birds/stealth — Stealth Address Registry
 *
 * Manages the on-chain announcement registry where senders publish
 * ephemeral public keys for recipients to scan.
 *
 * The registry is an Algorand smart contract using box storage.
 * Each announcement is stored in a box keyed by round + index.
 */

import algosdk from 'algosdk';
import {
  type BN254Point,
  type StealthAnnouncement,
  type StealthMetaAddress,
  type NetworkConfig,
  type AlgorandAddress,
  encodePoint,
  decodePoint,
  bigintToBytes32,
  bytes32ToBigint,
  createAlgodClient,
} from '@2birds/core';
import { generateStealthAddress, stealthPubKeyToAddress } from './keys.js';

/** Registry contract application ID (set after deployment) */
export interface RegistryConfig {
  appId: bigint;
  network: NetworkConfig;
}

/**
 * StealthRegistry — client for the on-chain stealth address announcement registry.
 */
export class StealthRegistry {
  private algod: algosdk.Algodv2;
  private appId: bigint;

  constructor(config: RegistryConfig) {
    this.algod = createAlgodClient(config.network);
    this.appId = config.appId;
  }

  /**
   * Register a meta-address on-chain (associates it with a name or address).
   * This allows senders to look up a recipient's meta-address.
   */
  async registerMetaAddress(
    sender: algosdk.Account,
    metaAddress: StealthMetaAddress,
    label: string, // e.g., "alice.algo" or an Algorand address
  ): Promise<string> {
    const spendBytes = encodePoint(metaAddress.spendingPubKey);
    const viewBytes = encodePoint(metaAddress.viewingPubKey);
    const metaBytes = new Uint8Array(128);
    metaBytes.set(spendBytes, 0);
    metaBytes.set(viewBytes, 64);

    const params = await this.algod.getTransactionParams().do();

    const txn = algosdk.makeApplicationCallTxnFromObject({
      sender: sender.addr,
      appIndex: Number(this.appId),
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        new TextEncoder().encode('register'),
        new TextEncoder().encode(label),
        metaBytes,
      ],
      boxes: [
        { appIndex: Number(this.appId), name: new TextEncoder().encode(`meta:${label}`) },
      ],
      suggestedParams: params,
    });

    const signed = txn.signTxn(sender.sk);
    const resp = await this.algod.sendRawTransaction(signed).do();
    const txId = resp.txid;
    await algosdk.waitForConfirmation(this.algod, txId, 4);
    return txId;
  }

  /**
   * Resolve a label to its meta-address.
   */
  async resolve(label: string): Promise<StealthMetaAddress | null> {
    try {
      const boxName = new TextEncoder().encode(`meta:${label}`);
      const box = await this.algod.getApplicationBoxByName(Number(this.appId), boxName).do();
      const data = box.value;
      if (data.length !== 128) return null;

      return {
        spendingPubKey: decodePoint(data.slice(0, 64)),
        viewingPubKey: decodePoint(data.slice(64, 128)),
      };
    } catch {
      return null;
    }
  }

  /**
   * Publish a stealth payment announcement.
   * Called by the sender after sending funds to the stealth address.
   */
  async announce(
    sender: algosdk.Account,
    ephemeralPubKey: BN254Point,
    stealthAddress: AlgorandAddress,
    viewTag: number,
    metadata: Uint8Array = new Uint8Array(0),
  ): Promise<string> {
    const ephBytes = encodePoint(ephemeralPubKey);
    const addrBytes = algosdk.decodeAddress(stealthAddress).publicKey;
    const viewTagBytes = new Uint8Array([viewTag]);

    // Announcement data: ephemeral_pub (64) + stealth_addr (32) + view_tag (1) + metadata
    const announcementData = new Uint8Array(97 + metadata.length);
    announcementData.set(ephBytes, 0);
    announcementData.set(addrBytes, 64);
    announcementData.set(viewTagBytes, 96);
    if (metadata.length > 0) {
      announcementData.set(metadata, 97);
    }

    const params = await this.algod.getTransactionParams().do();
    const roundBytes = bigintToBytes32(BigInt(params.firstValid));
    const boxName = new Uint8Array(40); // "ann:" + round(32) + counter(4)
    const prefix = new TextEncoder().encode('ann:');
    boxName.set(prefix, 0);
    boxName.set(roundBytes.slice(24, 32), 4); // last 8 bytes of round
    // Counter would be managed by the contract

    const txn = algosdk.makeApplicationCallTxnFromObject({
      sender: sender.addr,
      appIndex: Number(this.appId),
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        new TextEncoder().encode('announce'),
        announcementData,
      ],
      boxes: [
        { appIndex: Number(this.appId), name: boxName },
      ],
      suggestedParams: params,
    });

    const signed = txn.signTxn(sender.sk);
    const resp = await this.algod.sendRawTransaction(signed).do();
    const txId = resp.txid;
    await algosdk.waitForConfirmation(this.algod, txId, 4);
    return txId;
  }

  /**
   * Fetch announcements from a range of rounds.
   * Used by the scanner to find payments addressed to a recipient.
   */
  async getAnnouncements(fromRound: bigint, toRound: bigint): Promise<StealthAnnouncement[]> {
    const announcements: StealthAnnouncement[] = [];

    // In production, this would use the indexer to efficiently query
    // box operations within the round range. For now, we scan boxes.
    try {
      const boxes = await this.algod.getApplicationBoxes(Number(this.appId)).do();
      for (const boxDesc of boxes.boxes) {
        const name = boxDesc.name;
        // Filter for announcement boxes (prefix "ann:")
        const nameStr = new TextDecoder().decode(name);
        if (!nameStr.startsWith('ann:')) continue;

        const box = await this.algod.getApplicationBoxByName(Number(this.appId), name).do();
        const data = box.value;
        if (data.length < 97) continue;

        const ephemeralPubKey = decodePoint(data.slice(0, 64));
        const addrBytes = data.slice(64, 96);
        const stealthAddress = algosdk.encodeAddress(addrBytes);
        const viewTag = data[96];
        const metadata = data.length > 97 ? data.slice(97) : new Uint8Array(0);

        announcements.push({
          ephemeralPubKey,
          stealthAddress,
          viewTag,
          metadata,
          txnId: '', // Would be populated from indexer
          round: 0n, // Would be populated from indexer
        });
      }
    } catch {
      // No boxes yet
    }

    return announcements;
  }

  /**
   * High-level: send to a stealth address.
   * Generates the stealth address, sends the payment, and publishes the announcement.
   */
  async stealthSend(
    sender: algosdk.Account,
    recipientMeta: StealthMetaAddress,
    amount: bigint,
    assetId: number = 0,
  ): Promise<{ txId: string; stealthAddress: AlgorandAddress }> {
    // Generate stealth address
    const { stealthPubKey, ephemeralPubKey, viewTag } = await generateStealthAddress(recipientMeta);

    // BN254→Ed25519 bridge: derive deterministic Algorand address from stealth public key
    const stealthAddress = await stealthPubKeyToAddress(stealthPubKey);

    const params = await this.algod.getTransactionParams().do();

    // Create payment transaction
    let payTxn: algosdk.Transaction;
    if (assetId === 0) {
      payTxn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender: sender.addr,
        receiver: stealthAddress,
        amount: Number(amount),
        suggestedParams: params,
      });
    } else {
      payTxn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
        sender: sender.addr,
        receiver: stealthAddress,
        amount: Number(amount),
        assetIndex: assetId,
        suggestedParams: params,
      });
    }

    // Create announcement transaction
    const announceTxn = algosdk.makeApplicationCallTxnFromObject({
      sender: sender.addr,
      appIndex: Number(this.appId),
      onComplete: algosdk.OnApplicationComplete.NoOpOC,
      appArgs: [
        new TextEncoder().encode('announce'),
        encodePoint(ephemeralPubKey),
      ],
      suggestedParams: params,
    });

    // Group the transactions atomically
    const grouped = algosdk.assignGroupID([payTxn, announceTxn]);
    const signedPay = grouped[0].signTxn(sender.sk);
    const signedAnnounce = grouped[1].signTxn(sender.sk);

    const resp = await this.algod.sendRawTransaction([signedPay, signedAnnounce]).do();
    const txId = resp.txid;
    await algosdk.waitForConfirmation(this.algod, txId, 4);

    return { txId, stealthAddress };
  }
}
