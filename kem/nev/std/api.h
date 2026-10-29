#ifndef API_H
#define API_H
#include <stdint.h>
#include "params.h"
#include "symmetrics/hashkdf.h"


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
#endif


#define KEM_SECRETKEYBYTES  KEM_CCA_SK_BYTES
#define KEM_PUBLICKEYBYTES  KEM_CCA_PK_BYTES
#define KEM_BYTES           SEED_BYTES
#define KEM_CIPHERTEXTBYTES KEM_CCA_CT_BYTES

#define CRYPTO_SECRETKEYBYTES  KEM_CCA_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES  KEM_CCA_PK_BYTES
#define CRYPTO_BYTES           SEED_BYTES
#define CRYPTO_CIPHERTEXTBYTES KEM_CCA_CT_BYTES

#define KEM_ALGNAME "NEV"

#endif
