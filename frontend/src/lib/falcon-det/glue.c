/**
 * Emscripten glue for Algorand's Deterministic Falcon-1024.
 * Exposes keygen, sign, verify to JavaScript via WASM.
 */
#include "c-src/deterministic.h"
#include "c-src/falcon.h"
#include <string.h>

/* Re-export size constants */
int falcon_det_pubkey_size(void) {
    return FALCON_DET1024_PUBKEY_SIZE;
}

int falcon_det_privkey_size(void) {
    return FALCON_DET1024_PRIVKEY_SIZE;
}

int falcon_det_sig_maxsize(void) {
    return FALCON_DET1024_SIG_COMPRESSED_MAXSIZE;
}

/**
 * Generate a Falcon-1024 keypair from a seed.
 * seed: pointer to seed bytes
 * seed_len: length of seed (0 = system random)
 * pubkey: output buffer (FALCON_DET1024_PUBKEY_SIZE bytes)
 * privkey: output buffer (FALCON_DET1024_PRIVKEY_SIZE bytes)
 * Returns 0 on success.
 */
int falcon_det_keygen(
    const uint8_t *seed, size_t seed_len,
    uint8_t *pubkey, uint8_t *privkey
) {
    shake256_context rng;

    if (seed == NULL || seed_len == 0) {
        shake256_init_prng_from_seed(&rng, NULL, 0);
    } else {
        shake256_init_prng_from_seed(&rng, seed, seed_len);
    }

    return falcon_det1024_keygen(&rng, privkey, pubkey);
}

/**
 * Sign a message with deterministic Falcon-1024.
 * sig: output buffer (at least FALCON_DET1024_SIG_COMPRESSED_MAXSIZE bytes)
 * sig_len: output, actual signature length
 * privkey: private key (FALCON_DET1024_PRIVKEY_SIZE bytes)
 * msg: message to sign
 * msg_len: message length
 * Returns 0 on success.
 */
int falcon_det_sign(
    uint8_t *sig, size_t *sig_len,
    const uint8_t *privkey,
    const uint8_t *msg, size_t msg_len
) {
    if (msg == NULL || msg_len == 0) {
        return falcon_det1024_sign_compressed(sig, sig_len, privkey, NULL, 0);
    }
    return falcon_det1024_sign_compressed(sig, sig_len, privkey, msg, msg_len);
}

/**
 * Verify a deterministic Falcon-1024 signature.
 * sig: signature bytes
 * sig_len: signature length
 * pubkey: public key (FALCON_DET1024_PUBKEY_SIZE bytes)
 * msg: message
 * msg_len: message length
 * Returns 0 if valid.
 */
int falcon_det_verify(
    const uint8_t *sig, size_t sig_len,
    const uint8_t *pubkey,
    const uint8_t *msg, size_t msg_len
) {
    if (sig == NULL || sig_len == 0) {
        return -1;
    }
    if (msg == NULL || msg_len == 0) {
        return falcon_det1024_verify_compressed(sig, sig_len, pubkey, NULL, 0);
    }
    return falcon_det1024_verify_compressed(sig, sig_len, pubkey, msg, msg_len);
}
