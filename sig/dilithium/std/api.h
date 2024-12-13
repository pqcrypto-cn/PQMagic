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
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

// return 0 if success, or return error code (neg number).
#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(uint8_t *sm, size_t *smlen, 
                          const uint8_t *m, size_t mlen, 
                          const uint8_t *sk);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

// return 0/1 if verification failed/success, or return error code (neg number).
#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(const uint8_t *sm, size_t smlen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#endif
