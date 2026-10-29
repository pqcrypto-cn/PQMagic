/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include "KEM_AlgorithmInstance.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pike_compressed.h>
#include <encoded_sizes.h>
#include <pike_hash.h>

int randombytes(unsigned char *output, unsigned long long output_bytes);

#define NGCC_KEM_SUCCESS 0
#define NGCC_KEM_DECAPS_FAIL -1
#define NGCC_KEM_ERROR -2

#define PIKE_SS_BYTES ((unsigned long long)PIKE_COMPRESSED_SHARED_SECRET_BYTES)
#define PIKE_FP2_BYTES ((size_t)(FP_ENCODED_BYTES * 2))
#define PIKE_POINT_BYTES ((size_t)(PIKE_FP2_BYTES * 2))
#define PIKE_BASIS_BYTES ((size_t)(PIKE_POINT_BYTES * 3))
#define PIKE_CURVE_BYTES ((size_t)(PIKE_FP2_BYTES * 2))
#define PIKE_SCALAR_BYTES ((size_t)(NWORDS_ORDER * RADIX / 8))
#define PIKE_PK_BYTES ((unsigned long long)PIKE_COMPRESSED_PK_ENCODED_BYTES)
#define PIKE_SK_CORE_BYTES ((unsigned long long)PIKE_COMPRESSED_SK_ENCODED_BYTES)
#define PIKE_SK_BYTES (PIKE_SK_CORE_BYTES + PIKE_PK_BYTES)
#define PIKE_CT_ENCODE_BYTES_SZ ((size_t)PIKE_COMPRESSED_CT_ENCODED_BYTES)
#define PIKE_CT_BYTES ((unsigned long long)PIKE_COMPRESSED_CT_ENCODED_BYTES)

static int serialize_pk(unsigned char *pk_bytes, const pike_pk_t *pk_obj);
static int deserialize_pk(pike_pk_t *pk_obj, const unsigned char *pk_bytes);
static int serialize_sk(unsigned char *sk_bytes, const pike_sk_t *sk_obj, const unsigned char *pk_bytes);
static int deserialize_sk(pike_sk_t *sk_obj, pike_pk_t *pk_obj, const unsigned char *sk_bytes);
static int serialize_ct(unsigned char *ct_bytes, const pike_ct_t *ct_obj);
static int deserialize_ct(pike_ct_t *ct_obj, const unsigned char *ct_bytes);
static int encode_point(unsigned char *out, const ec_point_t *point);
static int decode_point(ec_point_t *point, const unsigned char *in);
static int encode_basis(unsigned char *out, const ec_basis_t *basis);
static int decode_basis(ec_basis_t *basis, const unsigned char *in);
static int encode_curve(unsigned char *out, const ec_curve_t *curve);
static int decode_curve(ec_curve_t *curve, const unsigned char *in);
static int encode_digit_array_le(unsigned char *out, const digit_t *digits, size_t words);
static int decode_digit_array_le(digit_t *digits, const unsigned char *in, size_t words);
static int derive_dummy_m(unsigned char *dummy_m, const unsigned char *sk, unsigned long long sk_len_bytes, const unsigned char *ct, unsigned long long ct_len_bytes);
static int derive_gm(unsigned char *gm, const unsigned char *m);
static int encode_ct_for_kdf(unsigned char *encoded_ct, const pike_ct_t *ct_obj);
static int derive_ss_from_m_and_ct(unsigned char *ss, const unsigned char *m, const pike_ct_t *ct_obj);
static int compare_ct_for_kdf(const pike_ct_t *lhs, const pike_ct_t *rhs, int *is_equal);

unsigned long long kem_get_pk_len_bytes()
{
    return PIKE_PK_BYTES;
}

unsigned long long kem_get_sk_len_bytes()
{
    return PIKE_SK_BYTES;
}

unsigned long long kem_get_ss_len_bytes()
{
    return PIKE_SS_BYTES;
}

unsigned long long kem_get_ct_len_bytes()
{
    return PIKE_CT_BYTES;
}

int kem_keygen(
    unsigned char *pk, unsigned long long *pk_len_bytes,
    unsigned char *sk, unsigned long long *sk_len_bytes)
{
    pike_sk_t sk_obj;
    pike_pk_t pk_obj;

    if (NULL == pk || NULL == pk_len_bytes || NULL == sk || NULL == sk_len_bytes)
    {
        return NGCC_KEM_ERROR;
    }

    memset(&sk_obj, 0, sizeof(sk_obj));
    memset(&pk_obj, 0, sizeof(pk_obj));

    if (1 != keygen(&sk_obj, &pk_obj))
    {
        return NGCC_KEM_ERROR;
    }

    if (0 != serialize_pk(pk, &pk_obj))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != serialize_sk(sk, &sk_obj, pk))
    {
        return NGCC_KEM_ERROR;
    }

    *pk_len_bytes = PIKE_PK_BYTES;
    *sk_len_bytes = PIKE_SK_BYTES;

    return NGCC_KEM_SUCCESS;
}

int kem_enc(
    unsigned char *pk, unsigned long long pk_len_bytes,
    unsigned char *ss, unsigned long long *ss_len_bytes,
    unsigned char *ct, unsigned long long *ct_len_bytes)
{
    pike_pk_t pk_obj;
    pike_ct_t ct_obj;
    unsigned char m[PIKE_SS_BYTES];
    unsigned char gm[PIKE_SS_BYTES];

    if (NULL == pk || NULL == ss || NULL == ss_len_bytes || NULL == ct || NULL == ct_len_bytes)
    {
        return NGCC_KEM_ERROR;
    }
    if (pk_len_bytes != PIKE_PK_BYTES)
    {
        return NGCC_KEM_ERROR;
    }

    memset(&pk_obj, 0, sizeof(pk_obj));
    memset(&ct_obj, 0, sizeof(ct_obj));
    memset(m, 0, sizeof(m));
    memset(gm, 0, sizeof(gm));

    if (0 != deserialize_pk(&pk_obj, pk))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != randombytes(m, PIKE_SS_BYTES))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != derive_gm(gm, m))
    {
        return NGCC_KEM_ERROR;
    }
    if (1 != pike_encrypt(&ct_obj, &pk_obj, m, PIKE_SS_BYTES, gm, PIKE_SS_BYTES))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != derive_ss_from_m_and_ct(ss, m, &ct_obj))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != serialize_ct(ct, &ct_obj))
    {
        return NGCC_KEM_ERROR;
    }

    *ss_len_bytes = PIKE_SS_BYTES;
    *ct_len_bytes = PIKE_CT_BYTES;
    return NGCC_KEM_SUCCESS;
}

int kem_dec(
    unsigned char *sk, unsigned long long sk_len_bytes,
    unsigned char *ct, unsigned long long ct_len_bytes,
    unsigned char *ss, unsigned long long *ss_len_bytes)
{
    pike_sk_t sk_obj;
    pike_pk_t pk_obj;
    pike_ct_t ct_obj;
    pike_ct_t ct_ref;
    unsigned char dummy_m[PIKE_SS_BYTES];
    unsigned char m[PIKE_SS_BYTES];
    unsigned char gm[PIKE_SS_BYTES];
    size_t m_len;
    int is_valid;

    if (NULL == sk || NULL == ct || NULL == ss || NULL == ss_len_bytes)
    {
        return NGCC_KEM_ERROR;
    }
    if (sk_len_bytes != PIKE_SK_BYTES || ct_len_bytes != PIKE_CT_BYTES)
    {
        return NGCC_KEM_ERROR;
    }

    memset(&sk_obj, 0, sizeof(sk_obj));
    memset(&pk_obj, 0, sizeof(pk_obj));
    memset(&ct_obj, 0, sizeof(ct_obj));
    memset(&ct_ref, 0, sizeof(ct_ref));
    memset(dummy_m, 0, sizeof(dummy_m));
    memset(m, 0, sizeof(m));
    memset(gm, 0, sizeof(gm));
    m_len = 0;
    is_valid = 0;

    if (0 != deserialize_sk(&sk_obj, &pk_obj, sk))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != deserialize_ct(&ct_obj, ct))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != derive_dummy_m(dummy_m, sk, sk_len_bytes, ct, ct_len_bytes))
    {
        return NGCC_KEM_ERROR;
    }

    if (1 != decrypt(m, &m_len, &ct_obj, &sk_obj) || m_len != PIKE_SS_BYTES)
    {
        if (0 != derive_ss_from_m_and_ct(ss, dummy_m, &ct_obj))
        {
            return NGCC_KEM_ERROR;
        }
        *ss_len_bytes = PIKE_SS_BYTES;
        return NGCC_KEM_DECAPS_FAIL;
    }

    if (0 != derive_gm(gm, m))
    {
        return NGCC_KEM_ERROR;
    }
    if (1 != pike_encrypt(&ct_ref, &pk_obj, m, m_len, gm, PIKE_SS_BYTES))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != compare_ct_for_kdf(&ct_obj, &ct_ref, &is_valid))
    {
        return NGCC_KEM_ERROR;
    }

    if (is_valid)
    {
        if (0 != derive_ss_from_m_and_ct(ss, m, &ct_obj))
        {
            return NGCC_KEM_ERROR;
        }
        *ss_len_bytes = PIKE_SS_BYTES;
        return NGCC_KEM_SUCCESS;
    }

    if (0 != derive_ss_from_m_and_ct(ss, dummy_m, &ct_obj))
    {
        return NGCC_KEM_ERROR;
    }
    *ss_len_bytes = PIKE_SS_BYTES;
    return NGCC_KEM_DECAPS_FAIL;
}

static int serialize_pk(unsigned char *pk_bytes, const pike_pk_t *pk_obj)
{
    pike_pk_t pk_copy;

    if (NULL == pk_bytes || NULL == pk_obj)
    {
        return NGCC_KEM_ERROR;
    }

    memcpy(&pk_copy, pk_obj, sizeof(pk_copy));
    return (1 == pk_encode(pk_bytes, &pk_copy)) ? NGCC_KEM_SUCCESS : NGCC_KEM_ERROR;
}

static int deserialize_pk(pike_pk_t *pk_obj, const unsigned char *pk_bytes)
{
    if (NULL == pk_obj || NULL == pk_bytes)
    {
        return NGCC_KEM_ERROR;
    }

    return (1 == pk_decode(pk_obj, pk_bytes)) ? NGCC_KEM_SUCCESS : NGCC_KEM_ERROR;
}

static int serialize_sk(unsigned char *sk_bytes, const pike_sk_t *sk_obj, const unsigned char *pk_bytes)
{
    size_t offset;

    if (NULL == sk_bytes || NULL == sk_obj || NULL == pk_bytes)
    {
        return NGCC_KEM_ERROR;
    }

    offset = 0;
    if (1 != sk_encode(sk_bytes + offset, sk_obj))
    {
        return NGCC_KEM_ERROR;
    }
    offset += (size_t)PIKE_SK_CORE_BYTES;
    memcpy(sk_bytes + offset, pk_bytes, (size_t)PIKE_PK_BYTES);

    return NGCC_KEM_SUCCESS;
}

static int deserialize_sk(pike_sk_t *sk_obj, pike_pk_t *pk_obj, const unsigned char *sk_bytes)
{
    size_t offset;

    if (NULL == sk_obj || NULL == pk_obj || NULL == sk_bytes)
    {
        return NGCC_KEM_ERROR;
    }

    memset(sk_obj, 0, sizeof(*sk_obj));
    offset = 0;
    if (1 != sk_decode(sk_obj, sk_bytes + offset))
    {
        return NGCC_KEM_ERROR;
    }
    offset += (size_t)PIKE_SK_CORE_BYTES;
    if (0 != deserialize_pk(pk_obj, sk_bytes + offset))
    {
        return NGCC_KEM_ERROR;
    }

    return NGCC_KEM_SUCCESS;
}

static int serialize_ct(unsigned char *ct_bytes, const pike_ct_t *ct_obj)
{
    pike_ct_t ct_copy;

    if (NULL == ct_bytes || NULL == ct_obj)
    {
        return NGCC_KEM_ERROR;
    }

    memcpy(&ct_copy, ct_obj, sizeof(ct_copy));
    return (1 == ct_encode(ct_bytes, &ct_copy)) ? NGCC_KEM_SUCCESS : NGCC_KEM_ERROR;
}

static int deserialize_ct(pike_ct_t *ct_obj, const unsigned char *ct_bytes)
{
    if (NULL == ct_obj || NULL == ct_bytes)
    {
        return NGCC_KEM_ERROR;
    }

    return (1 == ct_decode(ct_obj, ct_bytes)) ? NGCC_KEM_SUCCESS : NGCC_KEM_ERROR;
}

static int encode_point(unsigned char *out, const ec_point_t *point)
{
    if (NULL == out || NULL == point)
    {
        return NGCC_KEM_ERROR;
    }

    fp2_encode(out, &point->x);
    fp2_encode(out + PIKE_FP2_BYTES, &point->z);
    return NGCC_KEM_SUCCESS;
}

static int decode_point(ec_point_t *point, const unsigned char *in)
{
    if (NULL == point || NULL == in)
    {
        return NGCC_KEM_ERROR;
    }

    fp2_decode(&point->x, in);
    fp2_decode(&point->z, in + PIKE_FP2_BYTES);
    return NGCC_KEM_SUCCESS;
}

static int encode_basis(unsigned char *out, const ec_basis_t *basis)
{
    if (NULL == out || NULL == basis)
    {
        return NGCC_KEM_ERROR;
    }

    if (0 != encode_point(out, &basis->P))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != encode_point(out + PIKE_POINT_BYTES, &basis->Q))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != encode_point(out + (2 * PIKE_POINT_BYTES), &basis->PmQ))
    {
        return NGCC_KEM_ERROR;
    }

    return NGCC_KEM_SUCCESS;
}

static int decode_basis(ec_basis_t *basis, const unsigned char *in)
{
    if (NULL == basis || NULL == in)
    {
        return NGCC_KEM_ERROR;
    }

    if (0 != decode_point(&basis->P, in))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != decode_point(&basis->Q, in + PIKE_POINT_BYTES))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != decode_point(&basis->PmQ, in + (2 * PIKE_POINT_BYTES)))
    {
        return NGCC_KEM_ERROR;
    }

    return NGCC_KEM_SUCCESS;
}

static int encode_curve(unsigned char *out, const ec_curve_t *curve)
{
    if (NULL == out || NULL == curve)
    {
        return NGCC_KEM_ERROR;
    }

    fp2_encode(out, &curve->A);
    fp2_encode(out + PIKE_FP2_BYTES, &curve->C);
    return NGCC_KEM_SUCCESS;
}

static int decode_curve(ec_curve_t *curve, const unsigned char *in)
{
    if (NULL == curve || NULL == in)
    {
        return NGCC_KEM_ERROR;
    }

    fp2_decode(&curve->A, in);
    fp2_decode(&curve->C, in + PIKE_FP2_BYTES);
    fp2_set_zero(&curve->A24.x);
    fp2_set_zero(&curve->A24.z);
    curve->is_A24_computed_and_normalized = false;
    return NGCC_KEM_SUCCESS;
}

static int encode_digit_array_le(unsigned char *out, const digit_t *digits, size_t words)
{
    size_t i;
    size_t j;

    if (NULL == out || NULL == digits)
    {
        return NGCC_KEM_ERROR;
    }

#if RADIX == 64
    for (i = 0; i < words; i++)
    {
        uint64_t v;
        v = (uint64_t)digits[i];
        for (j = 0; j < 8; j++)
        {
            out[i * 8 + j] = (unsigned char)(v >> (8 * j));
        }
    }
#elif RADIX == 32
    for (i = 0; i < words; i++)
    {
        uint32_t v;
        v = (uint32_t)digits[i];
        for (j = 0; j < 4; j++)
        {
            out[i * 4 + j] = (unsigned char)(v >> (8 * j));
        }
    }
#else
#error "Unsupported RADIX for stable serialization"
#endif

    return NGCC_KEM_SUCCESS;
}

static int decode_digit_array_le(digit_t *digits, const unsigned char *in, size_t words)
{
    size_t i;
    size_t j;

    if (NULL == digits || NULL == in)
    {
        return NGCC_KEM_ERROR;
    }

#if RADIX == 64
    for (i = 0; i < words; i++)
    {
        uint64_t v;
        v = 0;
        for (j = 0; j < 8; j++)
        {
            v |= ((uint64_t)in[i * 8 + j]) << (8 * j);
        }
        digits[i] = (digit_t)v;
    }
#elif RADIX == 32
    for (i = 0; i < words; i++)
    {
        uint32_t v;
        v = 0;
        for (j = 0; j < 4; j++)
        {
            v |= ((uint32_t)in[i * 4 + j]) << (8 * j);
        }
        digits[i] = (digit_t)v;
    }
#else
#error "Unsupported RADIX for stable serialization"
#endif

    return NGCC_KEM_SUCCESS;
}

static int derive_dummy_m(unsigned char *dummy_m, const unsigned char *sk, unsigned long long sk_len_bytes, const unsigned char *ct, unsigned long long ct_len_bytes)
{
    unsigned char *material;
    unsigned long long material_len_bytes;

    if (NULL == dummy_m || NULL == sk || NULL == ct)
    {
        return NGCC_KEM_ERROR;
    }
    if (sk_len_bytes > ULLONG_MAX - ct_len_bytes)
    {
        return NGCC_KEM_ERROR;
    }

    material_len_bytes = sk_len_bytes + ct_len_bytes;
    material = (unsigned char *)malloc((size_t)material_len_bytes);
    if (NULL == material)
    {
        return NGCC_KEM_ERROR;
    }

    memcpy(material, sk, (size_t)sk_len_bytes);
    memcpy(material + sk_len_bytes, ct, (size_t)ct_len_bytes);

    if (0 != pike_xof(dummy_m, (size_t)PIKE_SS_BYTES, material, (size_t)material_len_bytes))
    {
        free(material);
        return NGCC_KEM_ERROR;
    }

    free(material);
    return NGCC_KEM_SUCCESS;
}

static int derive_gm(unsigned char *gm, const unsigned char *m)
{
    if (NULL == gm || NULL == m)
    {
        return NGCC_KEM_ERROR;
    }

    return (0 == pike_xof(gm, (size_t)PIKE_SS_BYTES, m, (size_t)PIKE_SS_BYTES)) ? NGCC_KEM_SUCCESS : NGCC_KEM_ERROR;
}

static int encode_ct_for_kdf(unsigned char *encoded_ct, const pike_ct_t *ct_obj)
{
    pike_ct_t ct_copy;

    if (NULL == encoded_ct || NULL == ct_obj)
    {
        return NGCC_KEM_ERROR;
    }

    memcpy(&ct_copy, ct_obj, sizeof(ct_copy));
    return (1 == ct_encode(encoded_ct, &ct_copy)) ? NGCC_KEM_SUCCESS : NGCC_KEM_ERROR;
}

static int derive_ss_from_m_and_ct(unsigned char *ss, const unsigned char *m, const pike_ct_t *ct_obj)
{
    unsigned char material[PIKE_SS_BYTES + PIKE_CT_ENCODE_BYTES_SZ];

    if (NULL == ss || NULL == m || NULL == ct_obj)
    {
        return NGCC_KEM_ERROR;
    }

    memset(material, 0, sizeof(material));
    memcpy(material, m, PIKE_SS_BYTES);
    if (0 != encode_ct_for_kdf(material + PIKE_SS_BYTES, ct_obj))
    {
        return NGCC_KEM_ERROR;
    }

    if (0 != pike_xof(ss, (size_t)PIKE_SS_BYTES, material, sizeof(material)))
    {
        return NGCC_KEM_ERROR;
    }

    return NGCC_KEM_SUCCESS;
}

static int compare_ct_for_kdf(const pike_ct_t *lhs, const pike_ct_t *rhs, int *is_equal)
{
    unsigned char lhs_enc[PIKE_CT_ENCODE_BYTES_SZ];
    unsigned char rhs_enc[PIKE_CT_ENCODE_BYTES_SZ];

    if (NULL == lhs || NULL == rhs || NULL == is_equal)
    {
        return NGCC_KEM_ERROR;
    }

    memset(lhs_enc, 0, sizeof(lhs_enc));
    memset(rhs_enc, 0, sizeof(rhs_enc));
    if (0 != encode_ct_for_kdf(lhs_enc, lhs))
    {
        return NGCC_KEM_ERROR;
    }
    if (0 != encode_ct_for_kdf(rhs_enc, rhs))
    {
        return NGCC_KEM_ERROR;
    }

    *is_equal = (0 == memcmp(lhs_enc, rhs_enc, sizeof(lhs_enc))) ? 1 : 0;
    return NGCC_KEM_SUCCESS;
}
