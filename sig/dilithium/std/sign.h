#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

#define challenge DILITHIUM_NAMESPACE(challenge)
void challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define crypto_sign_keypair_internal DILITHIUM_NAMESPACE(keypair_internal)
int crypto_sign_keypair_internal(
    unsigned char *pk, 
    unsigned char *sk,
    const unsigned char *coins);

#define crypto_sign_keypair DILITHIUM_NAMESPACE(keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign_signature_internal DILITHIUM_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *coins,
    const unsigned char *sk);

#define crypto_sign_signature DILITHIUM_NAMESPACE(signature)
int crypto_sign_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

#define crypto_sign DILITHIUM_NAMESPACETOP
int crypto_sign(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

#define crypto_sign_verify DILITHIUM_NAMESPACE(verify)
int crypto_sign_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *pk);

#define crypto_sign_open DILITHIUM_NAMESPACE(open)
int crypto_sign_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *pk);

#endif
