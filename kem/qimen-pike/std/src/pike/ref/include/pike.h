#include <ec.h>
#include <encoded_sizes.h>

#ifndef PIKE_SHARED_SECRET_BYTES
#define PIKE_SHARED_SECRET_BYTES 32
#endif

#define PIKE_SCALAR_BYTES (NWORDS_ORDER * RADIX / 8)
#define PIKE_SEC_TWOPOW_BYTES ((POWER_OF_2 + 5) / 8)
#define PIKE_SEC_TORSION_D_BYTES ((P_COFACTOR_FOR_TPLS_BITLENGTH - POWER_OF_2 + 7) / 8)
#define PIKE_PK_ENCODED_BYTES (5 * FP2_ENCODED_BYTES + 1)
#define PIKE_SK_ENCODED_BYTES (3 * PIKE_SEC_TWOPOW_BYTES + PIKE_SEC_TORSION_D_BYTES)
#define PIKE_CT_ENCODED_BYTES (6 * FP2_ENCODED_BYTES + PIKE_SHARED_SECRET_BYTES)

/** @brief PIKE secret key
 *
 * @typedef pike_sk_t
 *
 * @struct pike_sk_t
 *
 */
typedef struct pike_sk_t {
    digit_t deg[NWORDS_ORDER];
    digit_t alpha[NWORDS_ORDER];
    digit_t beta[NWORDS_ORDER];
    digit_t iota[NWORDS_ORDER];
} pike_sk_t;

/** @brief PIKE public key
 *
 * @typedef pike_pk_t
 *
 * @struct pike_pk_t
 *
 */
typedef struct pike_pk_t {
    fp2_t xPpls;
    fp2_t xQpls;
    fp2_t xPmin;
    fp2_t xQmin;
    fp2_t xPQmin;
    bool label_pls;
} pike_pk_t;

/** @brief PIKE ciphertext
 *
 * @typedef pike_ct_t
 *
 * @struct pike_ct_t
 *
 */
typedef struct pike_ct_t {
    fp2_t EB_cof;
    fp2_t EAB_cof;
    fp2_t xPpls_B;
    fp2_t xQpls_B;
    fp2_t xPpls_AB;
    fp2_t xQpls_AB;
    uint8_t ct[PIKE_SHARED_SECRET_BYTES];
} pike_ct_t;

int decaps(unsigned char *key, pike_ct_t *ct, const pike_pk_t *pk, const pike_sk_t *sk, unsigned char *dummy_m);
int encaps(unsigned char *key, pike_ct_t *ct, const pike_pk_t *pk);
int ct_encode(unsigned char *encoded_ct, pike_ct_t *ct);
int ct_decode(pike_ct_t *ct, const unsigned char *encoded_ct);
int pk_encode(unsigned char *out, pike_pk_t *pk);
int pk_decode(pike_pk_t *pk, const unsigned char *in);
int sk_encode(unsigned char *out, const pike_sk_t *sk);
int sk_decode(pike_sk_t *sk, const unsigned char *in);
int keygen(pike_sk_t *sk, pike_pk_t *pk);
int encrypt(pike_ct_t *ct, const pike_pk_t *pk, const unsigned char *m, const size_t m_len, const unsigned char *seed, const size_t seed_len);
int decrypt(unsigned char *m, size_t *m_len, const pike_ct_t *ct, const pike_sk_t *sk);
