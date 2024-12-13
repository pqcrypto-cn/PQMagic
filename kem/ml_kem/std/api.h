#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  ML_KEM_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  ML_KEM_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES ML_KEM_CIPHERTEXTBYTES
#define CRYPTO_BYTES           ML_KEM_SSBYTES

#if   (ML_KEM_MODE == 512)
#define CRYPTO_ALGNAME "ML-KEM-512"
#elif (ML_KEM_MODE == 768)
#define CRYPTO_ALGNAME "ML-KEM-768"
#elif (ML_KEM_MODE == 1024)
#define CRYPTO_ALGNAME "ML-KEM-1024"
#else
#error "ML_KEM_MODE must be in {512,768,1024}"
#endif

#define crypto_kem_keypair ML_KEM_NAMESPACE(_keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc ML_KEM_NAMESPACE(_enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

#define crypto_kem_dec ML_KEM_NAMESPACE(_dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif
