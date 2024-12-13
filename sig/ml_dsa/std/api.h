#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"


#define SIG_SECRETKEYBYTES CRYPTO_SECRETKEYBYTES
#define SIG_PUBLICKEYBYTES CRYPTO_PUBLICKEYBYTES
#define SIG_BYTES CRYPTO_BYTES

#define crypto_sign_keypair_internal ML_DSA_NAMESPACE(keypair_internal)
int crypto_sign_keypair_internal(uint8_t *pk, 
                                 uint8_t *sk,
                                 const uint8_t *coins);
// return 0 if success, or return error code (neg number).
#define crypto_sign_keypair ML_DSA_NAMESPACE(keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

#define crypto_sign_signature_internal ML_DSA_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *coins,
                          const uint8_t *sk);
// return 0 if success, or return error code (neg number).
#define crypto_sign_signature ML_DSA_NAMESPACE(signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ctx, size_t ctx_len,
                          const uint8_t *sk);

#define crypto_sign ML_DSA_NAMESPACETOP
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *ctx, size_t ctx_len,
                const uint8_t *sk);

#define crypto_sign_verify_internal ML_DSA_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk);
// return 0/1 if verification failed/success, or return error code (neg number).
#define crypto_sign_verify ML_DSA_NAMESPACE(verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *pk);

#define crypto_sign_open ML_DSA_NAMESPACE(open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *ctx, size_t ctx_len,
                     const uint8_t *pk);

#endif
