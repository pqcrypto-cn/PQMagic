#ifndef hashkdf_h
#define hashkdf_h
#include "fips202.h"
#include "sm3kdf.h"
#include "kat_test/drng.h"

//#define USE_SM3
//#define KDF_AVX
//#define USE_AES
// #define USE_SHA3
//#define USE_NICCS_API

//#define BLAKE

#ifdef USE_SM3
#define KDF128RATE SM3_KDF_RATE
#define KDF256RATE SM3_KDF_RATE
#define KDF512RATE SM3_KDF_RATE
#define kdfstate sm3kdf_ctx
#elif  defined(USE_SHA3)
#define KDF128RATE SHAKE128_RATE
#define KDF256RATE SHAKE256_RATE
#define KDF512RATE SHAKE512_RATE
typedef uint64_t kdfstate[25];
#elif defined(USE_AES)
#define KDF128RATE 32
#define KDF256RATE 32
#define KDF512RATE 32
#define kdfstate aes256ctr_ctx
#elif defined(USE_NICCS_API)
#define KDF128RATE 32
#define KDF256RATE 32
#define KDF512RATE 32
#define kdfstate DRNG_ctx

void kdf_init(kdfstate* state, const uint8_t* input, int inlen);
void kdf_squeezeblocks(uint8_t* output, int nblocks, kdfstate* state);
#endif



void kdf128(uint8_t *out, int outlen, uint8_t *in, int inlen);
void kdf256(uint8_t *out, int outlen, uint8_t *in, int inlen);
void kdf512(uint8_t* out, int outlen, uint8_t* in, int inlen);
void hash128(uint8_t* out, uint8_t* in, int inlen);
void hash256(uint8_t *out, uint8_t *in, int inlen);
void hash512(uint8_t *out, uint8_t *in, int inlen);
void hash1024(uint8_t* out, uint8_t* in, int inlen);

void kdf128_absorb(kdfstate* state, const uint8_t* input, int inputByteLen);
void kdf128_squeezeblocks(uint8_t* output, int nblocks, kdfstate* state);

void kdf256_absorb(kdfstate * state, const uint8_t *input, int inputByteLen);
void kdf256_squeezeblocks(uint8_t *output, int nblocks, kdfstate * state);

void kdf512_absorb(kdfstate* state, const uint8_t* input, int inputByteLen);
void kdf512_squeezeblocks(uint8_t* output, int nblocks, kdfstate* state);

#endif
