#ifndef API_H
#define API_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"


#define SIG_SECRETKEYBYTES CRYPTO_SECRETKEYBYTES
#define SIG_PUBLICKEYBYTES CRYPTO_PUBLICKEYBYTES
#define SIG_BYTES CRYPTO_BYTES

// return 0 if success, or return error code (neg number).
#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

// return 0 if success, or return error code (neg number).
#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(unsigned char *sig, size_t *siglen, 
                          const unsigned char *m, size_t mlen, 
                          const unsigned char *sk);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(unsigned char *sm, size_t *smlen,
                const unsigned char *m, size_t mlen,
                const unsigned char *sk);

// return 0 if verification success, or return error code (neg number).
#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const unsigned char *sig, size_t siglen,
                       const unsigned char *m, size_t mlen,
                       const unsigned char *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen,
                     const unsigned char *pk);

#endif
