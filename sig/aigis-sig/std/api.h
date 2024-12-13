#ifndef API_H
#define API_H

#include "params.h"

#define SIG_SECRETKEYBYTES SK_SIZE_PACKED
#define SIG_PUBLICKEYBYTES PK_SIZE_PACKED
#define SIG_BYTES SIG_SIZE_PACKED

#define crypto_sign_keypair_internal AIGIS_SIG_NAMESPACE(keypair_internal)
int crypto_sign_keypair_internal(unsigned char *pk, 
                                 unsigned char *sk,
                                 const unsigned char *coins);

// return 0 if success, or return error code (neg number).
#define crypto_sign_keypair AIGIS_SIG_NAMESPACE(keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign_signature_internal AIGIS_SIG_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(unsigned char *sig, unsigned long long *siglen,
                          const unsigned char *m, unsigned long long mlen,
                          const unsigned char *sk);

// return 0 if success, or return error code (neg number).
#define crypto_sign_signature AIGIS_SIG_NAMESPACE(signature)
int crypto_sign_signature(unsigned char *sig, unsigned long long *siglen,
                          const unsigned char *m, unsigned long long mlen,
                          const unsigned char *ctx, unsigned long long ctx_len,
                          const unsigned char *sk);

#define crypto_sign AIGIS_SIG_NAMESPACETOP
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen,
                const unsigned char *ctx, unsigned long long ctx_len,
                const unsigned char *sk);

#define crypto_sign_verify_internal AIGIS_SIG_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const unsigned char *sig,
                       unsigned long long siglen,
                       const unsigned char *m,
                       unsigned long long mlen,
                       const unsigned char *pk);

// return 0 if verification success, or return error code (neg number).
#define crypto_sign_verify AIGIS_SIG_NAMESPACE(verify)
int crypto_sign_verify(const unsigned char *sig, unsigned long long siglen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *ctx, unsigned long long ctx_len,
                       const unsigned char *pk);

#define crypto_sign_open AIGIS_SIG_NAMESPACE(open)
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *ctx, unsigned long long ctx_len,
                     const unsigned char *pk);

#endif
