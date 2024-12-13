#ifndef KEM_H
#define KEM_H

#include "params.h"

#define crypto_kem_keypair_internal ML_KEM_NAMESPACE(_keypair_internal)
int crypto_kem_keypair_internal(unsigned char *pk, 
                                unsigned char *sk,
                                const unsigned char *coins);

#define crypto_kem_keypair ML_KEM_NAMESPACE(_keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc_internal ML_KEM_NAMESPACE(_enc_internal)
int crypto_kem_enc_internal(unsigned char *ct,
                            unsigned char *ss,
                            const unsigned char *pk,
                            const unsigned char *coins);

#define crypto_kem_enc ML_KEM_NAMESPACE(_enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

#define crypto_kem_dec ML_KEM_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
