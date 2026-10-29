#ifndef API_H
#define API_H

#include "params.h"


#if SEEDBYTES == 16
#define Hash hash128
#define Hash2 hash256
#define KDF kdf128
#define KDF_ABSORB kdf128_absorb
#define KDF_SQUEEZEBLOCK kdf128_squeezeblocks
#define KDF_RATE KDF128RATE
#elif SEEDBYTES == 32
#define Hash hash256
#define Hash2 hash512
#define KDF kdf256
#define KDF_ABSORB kdf256_absorb
#define KDF_SQUEEZEBLOCK kdf256_squeezeblocks
#define KDF_RATE KDF256RATE
#elif SEEDBYTES == 64
#define Hash hash512
#define Hash2 hash1024
#define KDF kdf512
#define KDF_ABSORB kdf512_absorb
#define KDF_SQUEEZEBLOCK kdf512_squeezeblocks
#define KDF_RATE KDF512RATE
#endif




#define SIG_SECRETKEYBYTES SK_SIZE_PACKED
#define SIG_PUBLICKEYBYTES PK_SIZE_PACKED
#define SIG_BYTES SIG_MAX_SIZE_PACKED

#define SIG_ALGNAME "Aigis-sig"
 
int msig_keygen(unsigned char *pk, unsigned char *sk);
                   
int msig_sign(unsigned char *sk, 
                   unsigned char *m, unsigned long long mlen, 
                   unsigned char *sm, unsigned long long *smlen);                     

int msig_verf(unsigned char *pk,
                   unsigned char *sm, unsigned long long smlen,
                   unsigned char *m, unsigned long long mlen);
#endif
