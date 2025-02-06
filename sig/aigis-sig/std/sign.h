#ifndef SIGN_H
#define SIGN_H

#include "params.h"
#include "poly.h"
#include "polyvec.h"

#define expand_mat AIGIS_SIG_NAMESPACE(expand_mat)
void expand_mat(polyvecl mat[PARAM_K], const unsigned char rho[SEEDBYTES]);

#define challenge AIGIS_SIG_NAMESPACE(challenge)
void challenge(poly *c, const unsigned char mu[CRHBYTES],
               const polyveck *w1);


#define crypto_sign_keypair_internal AIGIS_SIG_NAMESPACE(keypair_internal)
int crypto_sign_keypair_internal(unsigned char *pk, 
                                 unsigned char *sk,
                                 const unsigned char *coins);

// return 0 if success, or return error code (neg number).
#define crypto_sign_keypair AIGIS_SIG_NAMESPACE(keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign_signature_internal AIGIS_SIG_NAMESPACE(signature_internal)
int crypto_sign_signature_internal(unsigned char *sig, size_t *siglen,
                          const unsigned char *m, size_t mlen,
                          const unsigned char *sk);

// return 0 if success, or return error code (neg number).
#define crypto_sign_signature AIGIS_SIG_NAMESPACE(signature)
int crypto_sign_signature(unsigned char *sig, size_t *siglen,
                          const unsigned char *m, size_t mlen,
                          const unsigned char *ctx, size_t ctx_len,
                          const unsigned char *sk);

#define crypto_sign AIGIS_SIG_NAMESPACETOP
int crypto_sign(unsigned char *sm, size_t *smlen,
                const unsigned char *m, size_t mlen,
                const unsigned char *ctx, size_t ctx_len,
                const unsigned char *sk);

#define crypto_sign_verify_internal AIGIS_SIG_NAMESPACE(verify_internal)
int crypto_sign_verify_internal(const unsigned char *sig,
                       size_t siglen,
                       const unsigned char *m,
                       size_t mlen,
                       const unsigned char *pk);

// return 0 if verification success, or return error code (neg number).
#define crypto_sign_verify AIGIS_SIG_NAMESPACE(verify)
int crypto_sign_verify(const unsigned char *sig, size_t siglen,
                       const unsigned char *m, size_t mlen,
                       const unsigned char *ctx, size_t ctx_len,
                       const unsigned char *pk);

#define crypto_sign_open AIGIS_SIG_NAMESPACE(open)
int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen,
                     const unsigned char *ctx, size_t ctx_len,
                     const unsigned char *pk);

#endif
