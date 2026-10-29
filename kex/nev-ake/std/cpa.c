#include "api.h"
#include "params.h"
#include "owpke.h"
#include "symmetrics/hashkdf.h"
#include "randombytes.h"

void kem_cpa_keygen(uint8_t *pk, uint8_t *sk) {
    ow_pke_keypair(pk, sk);
}

void kem_cpa_enc(uint8_t *c, uint8_t *ss, const uint8_t *pk) {
    uint8_t buf[SEED_BYTES];
    randombytes(buf, SEED_BYTES);
    Hash(ss, buf, SEED_BYTES);
    ow_pke_enc(c, buf, pk);
}

void kem_cpa_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t buf[SEED_BYTES];
    ow_pke_dec(buf, ct, sk);
    Hash(ss, buf, SEED_BYTES);
}

void pke_cpa_keygen(uint8_t *pk, uint8_t *sk) {
    ow_pke_keypair(pk, sk);
}

void pke_cpa_enc(uint8_t *ct, const uint8_t *m, const uint8_t *pk) {
    uint8_t k[SEED_BYTES];
    kem_cpa_enc(ct, k, pk);
    for (int i = 0; i < SEED_BYTES; ++i) {
        ct[PKE_OW_CT_BYTES + i] = m[i] ^ k[i];
    }
}

void pke_cpa_dec(uint8_t *m, const uint8_t *ct, const uint8_t *sk) {
    uint8_t k[SEED_BYTES];
    kem_cpa_dec(k,ct,sk);
    for (int i = 0; i < SEED_BYTES; ++i) {
        m[i] = ct[PKE_OW_CT_BYTES + i] ^ k[i];
    }
}