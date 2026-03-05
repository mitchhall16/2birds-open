import { Contract } from '@algorandfoundation/tealscript';

class StealthRegistry extends Contract {
  announcementCount = GlobalStateKey<uint64>({ key: 'count' });

  // Box storage
  metaAddresses = BoxMap<bytes, bytes>({ prefix: 'meta' });
  announcements = BoxMap<uint64, bytes>({ prefix: 'ann' });

  createApplication(): void {
    this.announcementCount.value = 0;
  }

  /**
   * Register a stealth meta-address (spending pub 64B + viewing pub 64B = 128B).
   * Keyed by sender + label to prevent other users from overwriting.
   */
  register(label: bytes, metaAddress: bytes): void {
    assert(len(metaAddress) === 128);
    assert(len(label) > 0);
    const key = concat(this.txn.sender, label);
    this.metaAddresses(key).value = metaAddress;
  }

  /**
   * Publish a stealth payment announcement.
   * Data: ephemeral_pub (64B) + stealth_addr (32B) + view_tag (1B) + metadata
   */
  announce(announcementData: bytes): void {
    assert(len(announcementData) >= 97);

    const count = this.announcementCount.value;
    this.announcements(count).value = announcementData;
    this.announcementCount.value = count + 1;

    log(concat(hex('616e6e6f756e6365'), itob(count)));
  }

  /**
   * Remove a meta-address registration. Reclaims box MBR.
   * Only the original registrant can deregister.
   */
  deregister(label: bytes): void {
    const key = concat(this.txn.sender, label);
    assert(this.metaAddresses(key).exists);
    this.metaAddresses(key).delete();
  }

  updateApplication(): void {
    assert(false);
  }

  deleteApplication(): void {
    assert(false);
  }
}

export default StealthRegistry;
