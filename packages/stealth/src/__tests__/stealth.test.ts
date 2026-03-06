import { describe, it, expect } from 'vitest';
import {
  generateStealthKeys,
  generateStealthAddress,
  checkStealthAddress,
  stealthPubKeyToAddress,
  stealthKeyToAlgorandAccount,
  encodeMetaAddress,
  decodeMetaAddress,
} from '../index.js';
import { derivePubKey, isOnCurve } from '@2birds/core';

describe('Stealth address protocol', () => {
  describe('Key generation', () => {
    it('generates valid spending and viewing keys', () => {
      const keys = generateStealthKeys();
      expect(keys.spendingKey).not.toBe(0n);
      expect(keys.viewingKey).not.toBe(0n);
      expect(keys.spendingKey).not.toBe(keys.viewingKey);
    });

    it('generates valid meta-address with on-curve points', () => {
      const keys = generateStealthKeys();
      expect(isOnCurve(keys.metaAddress.spendingPubKey)).toBe(true);
      expect(isOnCurve(keys.metaAddress.viewingPubKey)).toBe(true);
    });
  });

  describe('Meta-address encoding', () => {
    it('round-trips a meta-address', () => {
      const keys = generateStealthKeys();
      const encoded = encodeMetaAddress(keys.metaAddress);
      expect(encoded.startsWith('st:algo:')).toBe(true);
      const decoded = decodeMetaAddress(encoded);
      expect(decoded.spendingPubKey.x).toBe(keys.metaAddress.spendingPubKey.x);
      expect(decoded.spendingPubKey.y).toBe(keys.metaAddress.spendingPubKey.y);
      expect(decoded.viewingPubKey.x).toBe(keys.metaAddress.viewingPubKey.x);
      expect(decoded.viewingPubKey.y).toBe(keys.metaAddress.viewingPubKey.y);
    });
  });

  describe('Stealth address generation + checking', () => {
    it('sender generates a valid stealth address', async () => {
      const recipient = generateStealthKeys();
      const { stealthPubKey, ephemeralPubKey, viewTag } = await generateStealthAddress(recipient.metaAddress);
      expect(isOnCurve(stealthPubKey)).toBe(true);
      expect(isOnCurve(ephemeralPubKey)).toBe(true);
      expect(viewTag).toBeGreaterThanOrEqual(0);
      expect(viewTag).toBeLessThanOrEqual(255);
    });

    it('recipient correctly identifies their stealth payment', async () => {
      const recipient = generateStealthKeys();
      const { stealthPubKey, ephemeralPubKey, viewTag } = await generateStealthAddress(recipient.metaAddress);

      const result = await checkStealthAddress(
        ephemeralPubKey,
        stealthPubKey,
        recipient.viewingKey,
        recipient.spendingKey,
        viewTag,
      );

      expect(result.isOwner).toBe(true);
      expect(result.stealthPrivKey).toBeDefined();
    });

    it('non-recipient does not match', async () => {
      const recipient = generateStealthKeys();
      const other = generateStealthKeys();
      const { stealthPubKey, ephemeralPubKey, viewTag } = await generateStealthAddress(recipient.metaAddress);

      const result = await checkStealthAddress(
        ephemeralPubKey,
        stealthPubKey,
        other.viewingKey,
        other.spendingKey,
      );

      expect(result.isOwner).toBe(false);
    });

    it('stealth private key corresponds to stealth public key', async () => {
      const recipient = generateStealthKeys();
      const { stealthPubKey, ephemeralPubKey, viewTag } = await generateStealthAddress(recipient.metaAddress);

      const result = await checkStealthAddress(
        ephemeralPubKey,
        stealthPubKey,
        recipient.viewingKey,
        recipient.spendingKey,
      );

      expect(result.stealthPrivKey).toBeDefined();
      const derivedPub = derivePubKey(result.stealthPrivKey!);
      expect(derivedPub.x).toBe(stealthPubKey.x);
      expect(derivedPub.y).toBe(stealthPubKey.y);
    });
  });

  describe('BN254 → Ed25519 bridge', () => {
    it('sender and recipient derive the same Algorand address', async () => {
      const recipient = generateStealthKeys();
      const { stealthPubKey, ephemeralPubKey } = await generateStealthAddress(recipient.metaAddress);

      // Sender derives address from stealth PUBLIC key
      const senderAddress = await stealthPubKeyToAddress(stealthPubKey);

      // Recipient derives stealth private key, then Algorand account
      const check = await checkStealthAddress(
        ephemeralPubKey,
        stealthPubKey,
        recipient.viewingKey,
        recipient.spendingKey,
      );
      const recipientAccount = await stealthKeyToAlgorandAccount(check.stealthPrivKey!);

      // Both must agree on the same address
      expect(recipientAccount.address).toBe(senderAddress);
    });

    it('Algorand account has a valid 58-char address', async () => {
      const recipient = generateStealthKeys();
      const { stealthPubKey, ephemeralPubKey } = await generateStealthAddress(recipient.metaAddress);

      const check = await checkStealthAddress(
        ephemeralPubKey,
        stealthPubKey,
        recipient.viewingKey,
        recipient.spendingKey,
      );
      const account = await stealthKeyToAlgorandAccount(check.stealthPrivKey!);

      expect(account.address).toHaveLength(58);
      expect(account.sk).toHaveLength(64);
    });

    it('different stealth payments produce different addresses', async () => {
      const recipient = generateStealthKeys();
      const result1 = await generateStealthAddress(recipient.metaAddress);
      const result2 = await generateStealthAddress(recipient.metaAddress);

      const addr1 = await stealthPubKeyToAddress(result1.stealthPubKey);
      const addr2 = await stealthPubKeyToAddress(result2.stealthPubKey);

      expect(addr1).not.toBe(addr2);
    });
  });
});
