#ifndef API_H
#define API_H

#include "params.h"

#define CRYPTO_SECRETKEYBYTES  KEM_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KEM_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KEM_CIPHERTEXTBYTES
#define CRYPTO_BYTES           KEM_SSBYTES

#define crypto_kem_keypair_internal AIGIS_ENC_NAMESPACE(keypair_internal)
int crypto_kem_keypair_internal(
    unsigned char *pk, 
    unsigned char *sk,
    const unsigned char *coins);

#define crypto_kem_keypair AIGIS_ENC_NAMESPACE(keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc_internal AIGIS_ENC_NAMESPACE(enc_internal)
int crypto_kem_enc_internal(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk,
    const unsigned char *coins);

#define crypto_kem_enc AIGIS_ENC_NAMESPACE(enc)
int crypto_kem_enc(
    unsigned char *ct, 
    unsigned char *ss, 
    const unsigned char *pk);

#define crypto_kem_dec AIGIS_ENC_NAMESPACE(dec)
int crypto_kem_dec(
    unsigned char *ss, 
    const unsigned char *ct, 
    const unsigned char *sk);
#endif
