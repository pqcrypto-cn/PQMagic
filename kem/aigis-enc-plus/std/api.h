#ifndef API_H
#define API_H

#include "params.h"
#include "hashkdf.h"

#if SEED_BYTES == 16
#define Hash hash128
#define Hash2 hash256
#define KDF kdf128
#define KDF_ABSORB kdf128_absorb
#define KDF_SQUEEZEBLOCK kdf128_squeezeblocks
#define KDF_RATE KDF128RATE
#elif SEED_BYTES == 32
#define Hash hash256
#define Hash2 hash512
#define KDF kdf256
#define KDF_ABSORB kdf256_absorb
#define KDF_SQUEEZEBLOCK kdf256_squeezeblocks
#define KDF_RATE KDF256RATE
#elif SEED_BYTES == 64
#define Hash hash512
#define Hash2 hash1024
#define KDF kdf512
#define KDF_ABSORB kdf512_absorb
#define KDF_SQUEEZEBLOCK kdf512_squeezeblocks
#define KDF_RATE KDF512RATE
#else
#error "kem.c/owcpa.c/alg.c only supports SEED_BYTES in {16,32,64}"
#endif


#define KEM_SECRETKEYBYTES  SK_BYTES
#define KEM_PUBLICKEYBYTES  PK_BYTES
#define KEM_BYTES           SEED_BYTES
#define KEM_CIPHERTEXTBYTES CT_BYTES

#define CRYPTO_SECRETKEYBYTES  SK_BYTES
#define CRYPTO_PUBLICKEYBYTES  PK_BYTES
#define CRYPTO_BYTES           SEED_BYTES
#define CRYPTO_CIPHERTEXTBYTES CT_BYTES



int mkem_keygen( uint8_t *pk, uint8_t *sk);
int mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct);
int mdkem_enc(uint8_t *pk, uint8_t *rnd, uint8_t *ss, uint8_t *ct);
int mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss);
#endif
