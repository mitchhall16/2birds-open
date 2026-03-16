/**
 * JavaScript wrapper for Algorand's Deterministic Falcon-1024 WASM.
 * Drop-in replacement for falcon-crypto, but produces signatures
 * compatible with AVM's falcon_verify opcode.
 */

let _module = null
let _initPromise = null

async function getModule() {
  if (_module) return _module
  if (_initPromise) return _initPromise

  _initPromise = (async () => {
    const { default: FalconDetModule } = await import('./dist/falcon-det.mjs')
    _module = await FalconDetModule()
    return _module
  })()

  return _initPromise
}

/**
 * Get public key size (1793 bytes for Falcon-1024).
 */
export async function publicKeyBytes() {
  const mod = await getModule()
  return mod._falcon_det_pubkey_size()
}

/**
 * Get private key size.
 */
export async function privateKeyBytes() {
  const mod = await getModule()
  return mod._falcon_det_privkey_size()
}

/**
 * Get max signature size.
 */
export async function signatureMaxBytes() {
  const mod = await getModule()
  return mod._falcon_det_sig_maxsize()
}

/**
 * Generate a deterministic Falcon-1024 keypair from a seed.
 * @param {Uint8Array} [seed] - Optional seed bytes. If omitted, uses zero-length seed.
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>}
 */
export async function keyPairFromSeed(seed) {
  const mod = await getModule()
  const pkSize = mod._falcon_det_pubkey_size()
  const skSize = mod._falcon_det_privkey_size()

  const pkPtr = mod._malloc(pkSize)
  const skPtr = mod._malloc(skSize)
  let seedPtr = 0
  const seedLen = seed ? seed.length : 0

  try {
    if (seed && seed.length > 0) {
      seedPtr = mod._malloc(seed.length)
      mod.HEAPU8.set(seed, seedPtr)
    }

    const ret = mod._falcon_det_keygen(seedPtr, seedLen, pkPtr, skPtr)
    if (ret !== 0) throw new Error(`Falcon keygen failed: ${ret}`)

    return {
      publicKey: new Uint8Array(mod.HEAPU8.buffer.slice(pkPtr, pkPtr + pkSize)),
      privateKey: new Uint8Array(mod.HEAPU8.buffer.slice(skPtr, skPtr + skSize)),
    }
  } finally {
    if (seedPtr) mod._free(seedPtr)
    mod._free(pkPtr)
    mod._free(skPtr)
  }
}

/**
 * Generate a keypair with a random seed.
 * Uses crypto.getRandomValues for the seed.
 * @returns {Promise<{publicKey: Uint8Array, privateKey: Uint8Array}>}
 */
export async function keyPair() {
  const seed = new Uint8Array(48)
  crypto.getRandomValues(seed)
  return keyPairFromSeed(seed)
}

/**
 * Sign a message with deterministic Falcon-1024 (compressed format).
 * Returns only the raw signature (variable length).
 * @param {Uint8Array} message - The message to sign
 * @param {Uint8Array} privateKey - The private key
 * @returns {Promise<Uint8Array>} The signature
 */
export async function signDetached(message, privateKey) {
  const mod = await getModule()
  const maxSigSize = mod._falcon_det_sig_maxsize()
  const skSize = mod._falcon_det_privkey_size()

  const sigPtr = mod._malloc(maxSigSize)
  const sigLenPtr = mod._malloc(8) // size_t
  const skPtr = mod._malloc(skSize)
  let msgPtr = 0

  try {
    mod.HEAPU8.set(privateKey, skPtr)
    if (message && message.length > 0) {
      msgPtr = mod._malloc(message.length)
      mod.HEAPU8.set(message, msgPtr)
    }

    // Write 0 to sigLen
    mod.setValue(sigLenPtr, 0, 'i64')

    const ret = mod._falcon_det_sign(sigPtr, sigLenPtr, skPtr, msgPtr, message ? message.length : 0)
    if (ret !== 0) throw new Error(`Falcon sign failed: ${ret}`)

    // Read actual signature length (size_t = 4 bytes in wasm32)
    const sigLen = mod.getValue(sigLenPtr, 'i32')
    return new Uint8Array(mod.HEAPU8.buffer.slice(sigPtr, sigPtr + sigLen))
  } finally {
    if (msgPtr) mod._free(msgPtr)
    mod._free(sigPtr)
    mod._free(sigLenPtr)
    mod._free(skPtr)
  }
}

/**
 * Verify a deterministic Falcon-1024 signature.
 * @param {Uint8Array} signature - The signature
 * @param {Uint8Array} message - The message
 * @param {Uint8Array} publicKey - The public key
 * @returns {Promise<boolean>} True if valid
 */
export async function verifyDetached(signature, message, publicKey) {
  const mod = await getModule()
  const pkSize = mod._falcon_det_pubkey_size()

  const sigPtr = mod._malloc(signature.length)
  const pkPtr = mod._malloc(pkSize)
  let msgPtr = 0

  try {
    mod.HEAPU8.set(signature, sigPtr)
    mod.HEAPU8.set(publicKey, pkPtr)
    if (message && message.length > 0) {
      msgPtr = mod._malloc(message.length)
      mod.HEAPU8.set(message, msgPtr)
    }

    const ret = mod._falcon_det_verify(sigPtr, signature.length, pkPtr, msgPtr, message ? message.length : 0)
    return ret === 0
  } finally {
    if (msgPtr) mod._free(msgPtr)
    mod._free(sigPtr)
    mod._free(pkPtr)
  }
}

// Default export matching falcon-crypto's interface
export default {
  keyPair,
  keyPairFromSeed,
  signDetached,
  verifyDetached,
  publicKeyBytes: publicKeyBytes(),
  privateKeyBytes: privateKeyBytes(),
  bytes: signatureMaxBytes(),
}
