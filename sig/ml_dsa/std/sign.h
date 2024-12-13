#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"

#define challenge ML_DSA_NAMESPACE(challenge)
void challenge(poly *c, const uint8_t seed[SEEDBYTES]);

#define crypto_sign_keypair_internal ML_DSA_NAMESPACE(keypair_internal)
int crypto_sign_keypair_internal(
    unsigned char *pk, 
    unsigned char *sk,
    const unsigned char *coins);

#define crypto_sign_keypair ML_DSA_NAMESPACE(keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign_signature_internal ML_DSA_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *coins,
    const unsigned char *sk);

#define crypto_sign_signature ML_DSA_NAMESPACE(signature)
int crypto_sign_signature(
    unsigned char *sig, size_t *siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

#define crypto_sign ML_DSA_NAMESPACETOP
int crypto_sign(
    unsigned char *sm, size_t *smlen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *sk);

#define crypto_sign_verify_internal ML_DSA_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(
    const unsigned char *sig,
    size_t siglen,
    const unsigned char *m,
    size_t mlen,
    const unsigned char *pk);

#define crypto_sign_verify ML_DSA_NAMESPACE(verify)
int crypto_sign_verify(
    const unsigned char *sig, size_t siglen,
    const unsigned char *m, size_t mlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

#define crypto_sign_open ML_DSA_NAMESPACE(open)
int crypto_sign_open(
    unsigned char *m, size_t *mlen,
    const unsigned char *sm, size_t smlen,
    const unsigned char *ctx, size_t ctx_len,
    const unsigned char *pk);

#endif
