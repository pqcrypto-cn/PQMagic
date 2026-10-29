#ifndef PIKE_COMPRESSED_H
#define PIKE_COMPRESSED_H

#include <ec.h>
#include <encoded_sizes.h>

#define P_COFACTOR_FOR_TPLS_LEN ((BITS - P_COFACTOR_FOR_TPLS_BITLENGTH + RADIX - 1) / RADIX)
#define P_COFACTOR_FOR_TMIN_LEN ((BITS - P_COFACTOR_FOR_TMIN_BITLENGTH + RADIX - 1) / RADIX)
#define P_COFACTOR_FOR_TWOPOW_LEN ((POWER_OF_2 + RADIX - 1) / RADIX)
#define SECRET_FOR_TWOPOW_LEN ((POWER_OF_2 + RADIX - 3) / RADIX)
#define SECRET_FOR_TORSION_D_LEN ((P_COFACTOR_FOR_TPLS_BITLENGTH - POWER_OF_2 + RADIX - 1) / RADIX)

#define PIKE_COMPRESSED_TPLS_BYTES ((BITS - P_COFACTOR_FOR_TPLS_BITLENGTH + 7) / 8)
#define PIKE_COMPRESSED_TMIN_BYTES ((BITS - P_COFACTOR_FOR_TMIN_BITLENGTH + 7) / 8)
#define PIKE_COMPRESSED_TWOPOW_BYTES ((POWER_OF_2 + 7) / 8)
#define PIKE_COMPRESSED_SEC_TWOPOW_BYTES ((POWER_OF_2 + 5) / 8)
#define PIKE_COMPRESSED_SEC_TORSION_D_BYTES ((P_COFACTOR_FOR_TPLS_BITLENGTH - POWER_OF_2 + 7) / 8)

#ifndef PIKE_COMPRESSED_SHARED_SECRET_BYTES
#define PIKE_COMPRESSED_SHARED_SECRET_BYTES 32
#endif

// ct_encode: 4 fp2 (EB_cof, EAB_cof, xQpls_B, xPpls_AB)
//          + 2 scalars (scl2_B, scl2_AB)
//          + 4 ints (hint_B, hint_AB)
#define PIKE_COMPRESSED_CT_CORE_ENCODED_BYTES \
    (4 * FP2_ENCODED_BYTES + 2 * PIKE_COMPRESSED_TWOPOW_BYTES + 4 * sizeof(int))

// full ciphertext encoding: compressed core + encrypted message payload
#define PIKE_COMPRESSED_CT_ENCODED_BYTES \
    (PIKE_COMPRESSED_CT_CORE_ENCODED_BYTES + PIKE_COMPRESSED_SHARED_SECRET_BYTES)

// pk_encode: 2 fp2 (EA_cof, xPpls)
//          + 5 scalars (sclTpls, scl2, sclmin1, sclmin2, sclmin3)
//          + 2 bools (sclpls_label, sclmin_label)
//          + 5 ints (sclTpls_label, hint_pls, hintmin)
#define PIKE_COMPRESSED_PK_ENCODED_BYTES \
    (2 * FP2_ENCODED_BYTES + PIKE_COMPRESSED_TPLS_BYTES + PIKE_COMPRESSED_TWOPOW_BYTES + \
     3 * PIKE_COMPRESSED_TMIN_BYTES + 2 + 5 * sizeof(int))

// sk_encode: 4 scalars (deg, alpha, beta, iota)
#define PIKE_COMPRESSED_SK_ENCODED_BYTES \
    (3 * PIKE_COMPRESSED_SEC_TWOPOW_BYTES + PIKE_COMPRESSED_SEC_TORSION_D_BYTES)
/** @brief PIKE compressed secret key */
typedef struct pike_sk_t
{
    digit_t deg[SECRET_FOR_TWOPOW_LEN];
    digit_t alpha[SECRET_FOR_TWOPOW_LEN];
    digit_t beta[SECRET_FOR_TWOPOW_LEN];
    digit_t iota[SECRET_FOR_TORSION_D_LEN];
} pike_sk_t;

/** @brief PIKE compressed public key */
typedef struct pike_pk_t
{
    fp2_t EA_cof;
    fp2_t xPpls;
    digit_t sclTpls[P_COFACTOR_FOR_TPLS_LEN]; // log(TORSION_ODD_PLUS) bits
    digit_t scl2[P_COFACTOR_FOR_TWOPOW_LEN];  // TORSION_PLUS_EVEN_POWER bits
    digit_t sclmin1[P_COFACTOR_FOR_TMIN_LEN]; // log(TORSION_ODD_MINUS) bits
    digit_t sclmin2[P_COFACTOR_FOR_TMIN_LEN]; // log(TORSION_ODD_MINUS) bits
    digit_t sclmin3[P_COFACTOR_FOR_TMIN_LEN]; // log(TORSION_ODD_MINUS) bits
    int sclTpls_label;
    int hintpls[2];
    int hintmin[2];
    bool sclpls_label;
    bool sclmin_label;
} pike_pk_t;

/** @brief PIKE compressed ciphertext */
typedef struct pike_ct_t
{
    fp2_t EB_cof;
    fp2_t EAB_cof;
    fp2_t xQpls_B;
    fp2_t xPpls_AB;
    digit_t scl2_B[P_COFACTOR_FOR_TWOPOW_LEN];  // TORSION_PLUS_EVEN_POWER bits
    digit_t scl2_AB[P_COFACTOR_FOR_TWOPOW_LEN]; // TORSION_PLUS_EVEN_POWER bits
    int hint_B[2];
    int hint_AB[2];
    uint8_t ct[PIKE_COMPRESSED_SHARED_SECRET_BYTES];
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
int pike_encrypt(pike_ct_t *ct, const pike_pk_t *pk, const unsigned char *m, const size_t m_len, const unsigned char *seed, const size_t seed_len);
int decrypt(unsigned char *m, size_t *m_len, const pike_ct_t *ct, const pike_sk_t *sk);

#endif
