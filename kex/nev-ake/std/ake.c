#include "ake.h"

#include <stddef.h>
#include <string.h>

#include "api.h"
#include "owkem.h"
#include "owpke.h"
#include "randombytes.h"
#include "verify.h"

#define AKE_G_INPUT_BYTES (1 + AKE_MSG_BYTES)
#define AKE_H_INPUT_BYTES (1 + 5 * AKE_MSG_BYTES + AKE_M1_BYTES + AKE_M2_BYTES)
#define AKE_H_REJECT_INPUT_BYTES (1 + 5 * AKE_MSG_BYTES + PKE_OW_CT_BYTES + AKE_M1_BYTES + AKE_M2_BYTES)

static void append(uint8_t *buf, size_t *off, const uint8_t *src, size_t len) {
    memcpy(buf + *off, src, len);
    *off += len;
}

void ake_hash_g(uint8_t *rho, const uint8_t *m) {
    uint8_t buf[AKE_G_INPUT_BYTES];
    size_t off = 0;
    buf[off++] = AKE_DOMAIN_G;
    append(buf, &off, m, AKE_MSG_BYTES);
    KDF(rho, AKE_MSG_BYTES, buf, (int)off);
}

void ake_hash_h(uint8_t *key,
                const uint8_t *mi,
                const uint8_t *mj,
                const uint8_t *kt,
                const uint8_t *idi,
                const uint8_t *idj,
                const uint8_t *M,
                const uint8_t *M_prime) {
    uint8_t buf[AKE_H_INPUT_BYTES];
    size_t off = 0;
    buf[off++] = AKE_DOMAIN_H;
    append(buf, &off, mi, AKE_MSG_BYTES);
    append(buf, &off, mj, AKE_MSG_BYTES);
    append(buf, &off, kt, AKE_MSG_BYTES);
    append(buf, &off, idi, AKE_MSG_BYTES);
    append(buf, &off, idj, AKE_MSG_BYTES);
    append(buf, &off, M, AKE_M1_BYTES);
    append(buf, &off, M_prime, AKE_M2_BYTES);
    KDF(key, AKE_KEY_BYTES, buf, (int)off);
}

void ake_hash_hi(uint8_t *key,
                 const uint8_t *si,
                 const uint8_t *ci,
                 const uint8_t *mj,
                 const uint8_t *kt,
                 const uint8_t *idi,
                 const uint8_t *idj,
                 const uint8_t *M,
                 const uint8_t *M_prime) {
    uint8_t buf[AKE_H_REJECT_INPUT_BYTES];
    size_t off = 0;
    buf[off++] = AKE_DOMAIN_HI;
    append(buf, &off, si, AKE_MSG_BYTES);
    append(buf, &off, ci, PKE_OW_CT_BYTES);
    append(buf, &off, mj, AKE_MSG_BYTES);
    append(buf, &off, kt, AKE_MSG_BYTES);
    append(buf, &off, idi, AKE_MSG_BYTES);
    append(buf, &off, idj, AKE_MSG_BYTES);
    append(buf, &off, M, AKE_M1_BYTES);
    append(buf, &off, M_prime, AKE_M2_BYTES);
    KDF(key, AKE_KEY_BYTES, buf, (int)off);
}

void ake_hash_hr(uint8_t *key,
                 const uint8_t *sj,
                 const uint8_t *mi,
                 const uint8_t *cj,
                 const uint8_t *kt,
                 const uint8_t *idi,
                 const uint8_t *idj,
                 const uint8_t *M,
                 const uint8_t *M_prime) {
    uint8_t buf[AKE_H_REJECT_INPUT_BYTES];
    size_t off = 0;
    buf[off++] = AKE_DOMAIN_HR;
    append(buf, &off, sj, AKE_MSG_BYTES);
    append(buf, &off, mi, AKE_MSG_BYTES);
    append(buf, &off, cj, PKE_OW_CT_BYTES);
    append(buf, &off, kt, AKE_MSG_BYTES);
    append(buf, &off, idi, AKE_MSG_BYTES);
    append(buf, &off, idj, AKE_MSG_BYTES);
    append(buf, &off, M, AKE_M1_BYTES);
    append(buf, &off, M_prime, AKE_M2_BYTES);
    KDF(key, AKE_KEY_BYTES, buf, (int)off);
}

static int ake_pke_decrypt_verify(uint8_t *m,
                                  const uint8_t *c,
                                  const uint8_t *sk,
                                  const uint8_t *pk) {
    uint8_t rho[AKE_MSG_BYTES];
    uint8_t cmp[PKE_OW_CT_BYTES];

    ow_pke_dec(m, c, sk);
    ake_hash_g(rho, m);
    ow_pke_enc_interal(cmp, m, pk, rho);
    return verify(c, cmp, PKE_OW_CT_BYTES);
}

int ake_party_keygen(uint8_t *pk, uint8_t *sk) {
    ow_pke_keypair(pk, sk + AKE_SK_PKE_OFFSET);
    memcpy(sk + AKE_SK_PK_OFFSET, pk, PKE_OW_PK_BYTES);
    randombytes(sk + AKE_SK_S_OFFSET, AKE_MSG_BYTES);
    return 0;
}

void ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj) {
    ake_party_keygen(pki, ski);
    ake_party_keygen(pkj, skj);
}

void ake_init(uint8_t *M, uint8_t *st, const uint8_t *ski, const uint8_t *pkj) {
    uint8_t rho[AKE_MSG_BYTES];
    uint8_t *pk_tilde = st + AKE_ST_PK_T_OFFSET;
    uint8_t *sk_tilde = st + AKE_ST_SK_T_OFFSET;
    uint8_t *mj = st + AKE_ST_MJ_OFFSET;
    uint8_t *cj = st + AKE_ST_CJ_OFFSET;

    (void)ski;

    randombytes(mj, AKE_MSG_BYTES);
    ake_hash_g(rho, mj);
    ow_pke_enc_interal(M, mj, pkj, rho);
    memcpy(cj, M, PKE_OW_CT_BYTES);

    ow_kem_keygen(pk_tilde, sk_tilde);
    memcpy(M + PKE_OW_CT_BYTES, pk_tilde, KEM_OW_PK_BYTES);
}

void ake_der_response(uint8_t *M_prime,
                      uint8_t *K_prime,
                      const uint8_t *idi,
                      const uint8_t *idj,
                      const uint8_t *skj,
                      const uint8_t *pki,
                      const uint8_t *M) {
    const uint8_t *cj = M;
    const uint8_t *pk_tilde = M + PKE_OW_CT_BYTES;
    const uint8_t *skj_pke = skj + AKE_SK_PKE_OFFSET;
    const uint8_t *pkj = skj + AKE_SK_PK_OFFSET;
    const uint8_t *sj = skj + AKE_SK_S_OFFSET;
    uint8_t *ci = M_prime;
    uint8_t *ct_tilde = M_prime + PKE_OW_CT_BYTES;
    uint8_t mi[AKE_MSG_BYTES];
    uint8_t mj_prime[AKE_MSG_BYTES];
    uint8_t rho[AKE_MSG_BYTES];
    uint8_t kt[AKE_MSG_BYTES];
    uint8_t rt[AKE_MSG_BYTES];
    uint8_t k_good[AKE_KEY_BYTES];
    uint8_t k_bad[AKE_KEY_BYTES];
    int fail_j;

    randombytes(mi, AKE_MSG_BYTES);
    ake_hash_g(rho, mi);
    ow_pke_enc_interal(ci, mi, pki, rho);

    randombytes(rt, AKE_MSG_BYTES);
    ow_kem_enc_internal(kt, ct_tilde, pk_tilde, rt);

    fail_j = ake_pke_decrypt_verify(mj_prime, cj, skj_pke, pkj);

    ake_hash_h(k_good, mi, mj_prime, kt, idi, idj, M, M_prime);
    ake_hash_hr(k_bad, sj, mi, cj, kt, idi, idj, M, M_prime);
    memcpy(K_prime, k_good, AKE_KEY_BYTES);
    cmov(K_prime, k_bad, AKE_KEY_BYTES, (uint8_t)fail_j);
}

void ake_der_init(uint8_t *K,
                  const uint8_t *idi,
                  const uint8_t *idj,
                  const uint8_t *ski,
                  const uint8_t *pkj,
                  const uint8_t *st,
                  const uint8_t *M_prime) {
    const uint8_t *pk_tilde = st + AKE_ST_PK_T_OFFSET;
    const uint8_t *sk_tilde = st + AKE_ST_SK_T_OFFSET;
    const uint8_t *mj = st + AKE_ST_MJ_OFFSET;
    const uint8_t *cj = st + AKE_ST_CJ_OFFSET;
    const uint8_t *ci = M_prime;
    const uint8_t *ct_tilde = M_prime + PKE_OW_CT_BYTES;
    const uint8_t *ski_pke = ski + AKE_SK_PKE_OFFSET;
    const uint8_t *pki = ski + AKE_SK_PK_OFFSET;
    const uint8_t *si = ski + AKE_SK_S_OFFSET;
    uint8_t M[AKE_M1_BYTES];
    uint8_t mi_prime[AKE_MSG_BYTES];
    uint8_t kt[AKE_MSG_BYTES];
    uint8_t k_good[AKE_KEY_BYTES];
    uint8_t k_bad[AKE_KEY_BYTES];
    int fail_i;

    (void)pkj;

    memcpy(M, cj, PKE_OW_CT_BYTES);
    memcpy(M + PKE_OW_CT_BYTES, pk_tilde, KEM_OW_PK_BYTES);

    fail_i = ake_pke_decrypt_verify(mi_prime, ci, ski_pke, pki);
    ow_kem_dec(kt, (uint8_t *)ct_tilde, (uint8_t *)sk_tilde);

    ake_hash_h(k_good, mi_prime, mj, kt, idi, idj, M, M_prime);
    ake_hash_hi(k_bad, si, ci, mj, kt, idi, idj, M, M_prime);
    memcpy(K, k_good, AKE_KEY_BYTES);
    cmov(K, k_bad, AKE_KEY_BYTES, (uint8_t)fail_i);
}
