#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include <pqmagic_api.h>

#include <stdlib.h>
#include <string.h>

#define PQMAGIC_PROV_NAME "PQMagicProvider"
#define PQMAGIC_PROV_VERSION "0.1.0"
#define PQMAGIC_PROV_BUILDINFO "PQMagic OpenSSL 3 provider (ML-KEM-512 + ML-DSA-65)"

#define PQMAGIC_KEY_MLKEM512 1
#define PQMAGIC_KEY_MLDSA65  2

typedef struct {
    const OSSL_CORE_HANDLE *handle;
} PQMAGIC_PROV_CTX;

typedef struct {
    int type;
    unsigned char *pub;
    size_t publen;
    unsigned char *priv;
    size_t privlen;
} PQMAGIC_KEYDATA;

typedef struct {
    int type;
} PQMAGIC_GEN_CTX;

typedef struct {
    int type;
    PQMAGIC_KEYDATA *key;
} PQMAGIC_KEM_CTX;

typedef struct {
    int type;
    PQMAGIC_KEYDATA *key;
} PQMAGIC_SIG_CTX;

static size_t pqmagic_pub_len(int type)
{
    switch (type) {
    case PQMAGIC_KEY_MLKEM512:
        return ML_KEM_512_PUBLICKEYBYTES;
    case PQMAGIC_KEY_MLDSA65:
        return ML_DSA_65_PUBLICKEYBYTES;
    default:
        return 0;
    }
}

static size_t pqmagic_priv_len(int type)
{
    switch (type) {
    case PQMAGIC_KEY_MLKEM512:
        return ML_KEM_512_SECRETKEYBYTES;
    case PQMAGIC_KEY_MLDSA65:
        return ML_DSA_65_SECRETKEYBYTES;
    default:
        return 0;
    }
}

static PQMAGIC_KEYDATA *pqmagic_key_new_typed(int type)
{
    PQMAGIC_KEYDATA *k = (PQMAGIC_KEYDATA *)calloc(1, sizeof(*k));
    if (k == NULL)
        return NULL;
    k->type = type;
    return k;
}

static void pqmagic_secure_free(unsigned char *buf, size_t len)
{
    if (buf != NULL && len > 0)
        OPENSSL_cleanse(buf, len);
    free(buf);
}

static int pqmagic_set_key_component(unsigned char **dst, size_t *dst_len,
                                     const void *src, size_t src_len,
                                     size_t expected_len)
{
    unsigned char *tmp;

    if (src == NULL || src_len != expected_len)
        return 0;

    tmp = (unsigned char *)malloc(src_len);
    if (tmp == NULL)
        return 0;

    memcpy(tmp, src, src_len);
    pqmagic_secure_free(*dst, *dst_len);
    *dst = tmp;
    *dst_len = src_len;
    return 1;
}

/* ---------------- Provider ---------------- */

static void pqmagic_provider_teardown(void *vprovctx)
{
    free(vprovctx);
}

static const OSSL_PARAM *pqmagic_provider_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_BUILDINFO, NULL, 0),
        OSSL_PARAM_END
    };
    (void)provctx;
    return table;
}

static int pqmagic_provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PQMAGIC_PROV_NAME))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PQMAGIC_PROV_VERSION))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, PQMAGIC_PROV_BUILDINFO))
        return 0;

    return 1;
}

/* ---------------- KEYMGMT common ---------------- */

static void *pqmagic_keymgmt_new_common(int type)
{
    return pqmagic_key_new_typed(type);
}

static void pqmagic_keymgmt_free_common(void *vkey)
{
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    if (key == NULL)
        return;
    pqmagic_secure_free(key->pub, key->publen);
    pqmagic_secure_free(key->priv, key->privlen);
    free(key);
}

static int pqmagic_keymgmt_has(const void *vkey, int selection)
{
    const PQMAGIC_KEYDATA *key = (const PQMAGIC_KEYDATA *)vkey;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && (key->pub == NULL || key->publen == 0))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (key->priv == NULL || key->privlen == 0))
        return 0;

    return 1;
}

static int pqmagic_keymgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    const PQMAGIC_KEYDATA *a = (const PQMAGIC_KEYDATA *)vkey1;
    const PQMAGIC_KEYDATA *b = (const PQMAGIC_KEYDATA *)vkey2;

    if (a == NULL || b == NULL || a->type != b->type)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (a->publen != b->publen || a->pub == NULL || b->pub == NULL
            || memcmp(a->pub, b->pub, a->publen) != 0)
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (a->privlen != b->privlen || a->priv == NULL || b->priv == NULL
            || memcmp(a->priv, b->priv, a->privlen) != 0)
            return 0;
    }

    return 1;
}

static int pqmagic_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    const OSSL_PARAM *p;
    size_t expected_pub, expected_priv;

    if (key == NULL)
        return 0;

    expected_pub = pqmagic_pub_len(key->type);
    expected_priv = pqmagic_priv_len(key->type);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p == NULL || !pqmagic_set_key_component(&key->pub, &key->publen,
                                                    p->data, p->data_size,
                                                    expected_pub))
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p == NULL || !pqmagic_set_key_component(&key->priv, &key->privlen,
                                                    p->data, p->data_size,
                                                    expected_priv))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *pqmagic_keymgmt_import_types(int selection)
{
    static const OSSL_PARAM pub_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    static const OSSL_PARAM priv_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    static const OSSL_PARAM keypair_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        return keypair_types;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return priv_types;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return pub_types;
    return NULL;
}

static int pqmagic_keymgmt_export(void *vkey, int selection,
                                  OSSL_CALLBACK *param_cb, void *cbarg)
{
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    OSSL_PARAM params[3];
    size_t i = 0;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->pub != NULL) {
        params[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                         key->pub, key->publen);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->priv != NULL) {
        params[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                         key->priv, key->privlen);
    }

    params[i] = OSSL_PARAM_construct_end();
    return param_cb(params, cbarg);
}

static const OSSL_PARAM *pqmagic_keymgmt_export_types(int selection)
{
    return pqmagic_keymgmt_import_types(selection);
}

static const OSSL_PARAM *pqmagic_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    (void)provctx;
    return gettable;
}

static int pqmagic_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    OSSL_PARAM *p;
    int bits = 0, secbits = 0, max_size = 0;

    if (key == NULL)
        return 0;

    if (key->type == PQMAGIC_KEY_MLKEM512) {
        bits = ML_KEM_512_SSBYTES * 8;
        secbits = 128;
        max_size = ML_KEM_512_CIPHERTEXTBYTES;
    } else if (key->type == PQMAGIC_KEY_MLDSA65) {
        bits = 192;
        secbits = 192;
        max_size = ML_DSA_65_SIGBYTES;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, bits))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, secbits))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_int(p, max_size))
        return 0;

    return 1;
}

static void *pqmagic_keymgmt_dup(const void *vkey, int selection)
{
    const PQMAGIC_KEYDATA *src = (const PQMAGIC_KEYDATA *)vkey;
    PQMAGIC_KEYDATA *dst;

    if (src == NULL)
        return NULL;

    dst = pqmagic_key_new_typed(src->type);
    if (dst == NULL)
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && src->pub != NULL) {
        if (!pqmagic_set_key_component(&dst->pub, &dst->publen,
                                       src->pub, src->publen, src->publen)) {
            pqmagic_keymgmt_free_common(dst);
            return NULL;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && src->priv != NULL) {
        if (!pqmagic_set_key_component(&dst->priv, &dst->privlen,
                                       src->priv, src->privlen, src->privlen)) {
            pqmagic_keymgmt_free_common(dst);
            return NULL;
        }
    }

    return dst;
}

static int pqmagic_keygen_fill(PQMAGIC_KEYDATA *key)
{
    unsigned char *pk = NULL, *sk = NULL;
    size_t pklen, sklen;
    int rc;

    if (key == NULL)
        return 0;

    pklen = pqmagic_pub_len(key->type);
    sklen = pqmagic_priv_len(key->type);
    pk = (unsigned char *)malloc(pklen);
    sk = (unsigned char *)malloc(sklen);
    if (pk == NULL || sk == NULL) {
        free(pk);
        free(sk);
        return 0;
    }

    if (key->type == PQMAGIC_KEY_MLKEM512) {
        rc = pqmagic_ml_kem_512_std_keypair(pk, sk);
    } else if (key->type == PQMAGIC_KEY_MLDSA65) {
        rc = pqmagic_ml_dsa_65_std_keypair(pk, sk);
    } else {
        rc = -1;
    }

    if (rc != 0) {
        OPENSSL_cleanse(pk, pklen);
        OPENSSL_cleanse(sk, sklen);
        free(pk);
        free(sk);
        return 0;
    }

    pqmagic_secure_free(key->pub, key->publen);
    pqmagic_secure_free(key->priv, key->privlen);
    key->pub = pk;
    key->publen = pklen;
    key->priv = sk;
    key->privlen = sklen;
    return 1;
}

static void *pqmagic_keymgmt_gen_init_common(int type, int selection)
{
    PQMAGIC_GEN_CTX *g;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    g = (PQMAGIC_GEN_CTX *)calloc(1, sizeof(*g));
    if (g == NULL)
        return NULL;
    g->type = type;
    return g;
}

static int pqmagic_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void)genctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *pqmagic_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    (void)genctx;
    (void)provctx;
    return NULL;
}

static void *pqmagic_keymgmt_gen_common(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    PQMAGIC_GEN_CTX *g = (PQMAGIC_GEN_CTX *)genctx;
    PQMAGIC_KEYDATA *key;
    (void)cb;
    (void)cbarg;

    if (g == NULL)
        return NULL;

    key = pqmagic_key_new_typed(g->type);
    if (key == NULL)
        return NULL;

    if (!pqmagic_keygen_fill(key)) {
        pqmagic_keymgmt_free_common(key);
        return NULL;
    }

    return key;
}

static void pqmagic_keymgmt_gen_cleanup(void *genctx)
{
    free(genctx);
}

/* ---------------- ML-KEM-512 KEYMGMT ---------------- */

static void *mlkem512_keymgmt_new(void *provctx)
{
    (void)provctx;
    return pqmagic_keymgmt_new_common(PQMAGIC_KEY_MLKEM512);
}

static void *mlkem512_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)provctx;
    (void)params;
    return pqmagic_keymgmt_gen_init_common(PQMAGIC_KEY_MLKEM512, selection);
}

static const OSSL_DISPATCH mlkem512_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mlkem512_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pqmagic_keymgmt_free_common },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pqmagic_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pqmagic_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pqmagic_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pqmagic_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pqmagic_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pqmagic_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pqmagic_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pqmagic_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))pqmagic_keymgmt_dup },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mlkem512_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))pqmagic_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))pqmagic_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pqmagic_keymgmt_gen_common },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))pqmagic_keymgmt_gen_cleanup },
    { 0, NULL }
};

/* ---------------- ML-DSA-65 KEYMGMT ---------------- */

static void *mldsa65_keymgmt_new(void *provctx)
{
    (void)provctx;
    return pqmagic_keymgmt_new_common(PQMAGIC_KEY_MLDSA65);
}

static void *mldsa65_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)provctx;
    (void)params;
    return pqmagic_keymgmt_gen_init_common(PQMAGIC_KEY_MLDSA65, selection);
}

static const OSSL_DISPATCH mldsa65_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mldsa65_keymgmt_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))pqmagic_keymgmt_free_common },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))pqmagic_keymgmt_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))pqmagic_keymgmt_match },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))pqmagic_keymgmt_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))pqmagic_keymgmt_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))pqmagic_keymgmt_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))pqmagic_keymgmt_export_types },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))pqmagic_keymgmt_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))pqmagic_keymgmt_gettable_params },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))pqmagic_keymgmt_dup },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mldsa65_keymgmt_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))pqmagic_keymgmt_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))pqmagic_keymgmt_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))pqmagic_keymgmt_gen_common },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))pqmagic_keymgmt_gen_cleanup },
    { 0, NULL }
};

/* ---------------- KEM (ML-KEM-512) ---------------- */

static void *mlkem512_kem_newctx(void *provctx)
{
    PQMAGIC_KEM_CTX *ctx = (PQMAGIC_KEM_CTX *)calloc(1, sizeof(*ctx));
    (void)provctx;
    if (ctx == NULL)
        return NULL;
    ctx->type = PQMAGIC_KEY_MLKEM512;
    return ctx;
}

static int mlkem512_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQMAGIC_KEM_CTX *ctx = (PQMAGIC_KEM_CTX *)vctx;
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    (void)params;

    if (ctx == NULL || key == NULL || key->type != PQMAGIC_KEY_MLKEM512 || key->pub == NULL)
        return 0;
    ctx->key = key;
    return 1;
}

static int mlkem512_kem_encapsulate(void *vctx,
                                    unsigned char *out, size_t *outlen,
                                    unsigned char *secret, size_t *secretlen)
{
    PQMAGIC_KEM_CTX *ctx = (PQMAGIC_KEM_CTX *)vctx;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub == NULL)
        return 0;

    if (outlen != NULL)
        *outlen = ML_KEM_512_CIPHERTEXTBYTES;
    if (secretlen != NULL)
        *secretlen = ML_KEM_512_SSBYTES;

    if (out == NULL || secret == NULL)
        return 1;

    return pqmagic_ml_kem_512_std_enc(out, secret, ctx->key->pub) == 0;
}

static int mlkem512_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQMAGIC_KEM_CTX *ctx = (PQMAGIC_KEM_CTX *)vctx;
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    (void)params;

    if (ctx == NULL || key == NULL || key->type != PQMAGIC_KEY_MLKEM512 || key->priv == NULL)
        return 0;
    ctx->key = key;
    return 1;
}

static int mlkem512_kem_decapsulate(void *vctx,
                                    unsigned char *out, size_t *outlen,
                                    const unsigned char *in, size_t inlen)
{
    PQMAGIC_KEM_CTX *ctx = (PQMAGIC_KEM_CTX *)vctx;

    if (ctx == NULL || ctx->key == NULL || ctx->key->priv == NULL)
        return 0;

    if (outlen != NULL)
        *outlen = ML_KEM_512_SSBYTES;

    if (out == NULL)
        return 1;

    if (in == NULL || inlen != ML_KEM_512_CIPHERTEXTBYTES)
        return 0;

    return pqmagic_ml_kem_512_std_dec(out, in, ctx->key->priv) == 0;
}

static void mlkem512_kem_freectx(void *vctx)
{
    free(vctx);
}

static void *mlkem512_kem_dupctx(void *vctx)
{
    PQMAGIC_KEM_CTX *src = (PQMAGIC_KEM_CTX *)vctx;
    PQMAGIC_KEM_CTX *dst = (PQMAGIC_KEM_CTX *)calloc(1, sizeof(*dst));
    if (dst == NULL)
        return NULL;
    *dst = *src;
    return dst;
}

static const OSSL_DISPATCH mlkem512_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))mlkem512_kem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))mlkem512_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))mlkem512_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))mlkem512_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))mlkem512_kem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))mlkem512_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))mlkem512_kem_dupctx },
    { 0, NULL }
};

/* ---------------- SIGNATURE (ML-DSA-65) ---------------- */

static void *mldsa65_sig_newctx(void *provctx, const char *propq)
{
    PQMAGIC_SIG_CTX *ctx = (PQMAGIC_SIG_CTX *)calloc(1, sizeof(*ctx));
    (void)provctx;
    (void)propq;
    if (ctx == NULL)
        return NULL;
    ctx->type = PQMAGIC_KEY_MLDSA65;
    return ctx;
}

static int mldsa65_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQMAGIC_SIG_CTX *ctx = (PQMAGIC_SIG_CTX *)vctx;
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    (void)params;

    if (ctx == NULL || key == NULL || key->type != PQMAGIC_KEY_MLDSA65 || key->priv == NULL)
        return 0;
    ctx->key = key;
    return 1;
}

static int mldsa65_sig_sign(void *vctx,
                            unsigned char *sig, size_t *siglen, size_t sigsize,
                            const unsigned char *tbs, size_t tbslen)
{
    PQMAGIC_SIG_CTX *ctx = (PQMAGIC_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->key == NULL || ctx->key->priv == NULL || siglen == NULL)
        return 0;

    if (sig == NULL) {
        *siglen = ML_DSA_65_SIGBYTES;
        return 1;
    }

    if (sigsize < ML_DSA_65_SIGBYTES)
        return 0;

    return pqmagic_ml_dsa_65_std_signature(sig, siglen,
                                           tbs, tbslen,
                                           NULL, 0,
                                           ctx->key->priv) == 0;
}

static int mldsa65_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PQMAGIC_SIG_CTX *ctx = (PQMAGIC_SIG_CTX *)vctx;
    PQMAGIC_KEYDATA *key = (PQMAGIC_KEYDATA *)vkey;
    (void)params;

    if (ctx == NULL || key == NULL || key->type != PQMAGIC_KEY_MLDSA65 || key->pub == NULL)
        return 0;
    ctx->key = key;
    return 1;
}

static int mldsa65_sig_verify(void *vctx,
                              const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen)
{
    PQMAGIC_SIG_CTX *ctx = (PQMAGIC_SIG_CTX *)vctx;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub == NULL || sig == NULL)
        return 0;

    return pqmagic_ml_dsa_65_std_verify(sig, siglen,
                                        tbs, tbslen,
                                        NULL, 0,
                                        ctx->key->pub) == 0;
}

static void mldsa65_sig_freectx(void *vctx)
{
    free(vctx);
}

static void *mldsa65_sig_dupctx(void *vctx)
{
    PQMAGIC_SIG_CTX *src = (PQMAGIC_SIG_CTX *)vctx;
    PQMAGIC_SIG_CTX *dst = (PQMAGIC_SIG_CTX *)calloc(1, sizeof(*dst));
    if (dst == NULL)
        return NULL;
    *dst = *src;
    return dst;
}

static const OSSL_DISPATCH mldsa65_sig_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))mldsa65_sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))mldsa65_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))mldsa65_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))mldsa65_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))mldsa65_sig_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))mldsa65_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))mldsa65_sig_dupctx },
    { 0, NULL }
};

/* ---------------- Algorithms ---------------- */

static const OSSL_ALGORITHM pqmagic_keymgmt_algorithms[] = {
    { "MLKEM512:ML-KEM-512", "provider=pqmagic", mlkem512_keymgmt_functions,
      "PQMagic ML-KEM-512 key management" },
    { "MLDSA65:ML-DSA-65", "provider=pqmagic", mldsa65_keymgmt_functions,
      "PQMagic ML-DSA-65 key management" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqmagic_kem_algorithms[] = {
    { "MLKEM512:ML-KEM-512", "provider=pqmagic", mlkem512_kem_functions,
      "PQMagic ML-KEM-512 KEM" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM pqmagic_signature_algorithms[] = {
    { "MLDSA65:ML-DSA-65", "provider=pqmagic", mldsa65_sig_functions,
      "PQMagic ML-DSA-65 signature" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *pqmagic_provider_query_operation(void *provctx,
                                                               int operation_id,
                                                               int *no_cache)
{
    (void)provctx;
    if (no_cache != NULL)
        *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return pqmagic_keymgmt_algorithms;
    case OSSL_OP_KEM:
        return pqmagic_kem_algorithms;
    case OSSL_OP_SIGNATURE:
        return pqmagic_signature_algorithms;
    default:
        return NULL;
    }
}

static const OSSL_DISPATCH pqmagic_provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))pqmagic_provider_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))pqmagic_provider_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))pqmagic_provider_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))pqmagic_provider_query_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    PQMAGIC_PROV_CTX *ctx = (PQMAGIC_PROV_CTX *)calloc(1, sizeof(*ctx));
    (void)in;
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    *provctx = ctx;
    *out = pqmagic_provider_functions;
    return 1;
}
