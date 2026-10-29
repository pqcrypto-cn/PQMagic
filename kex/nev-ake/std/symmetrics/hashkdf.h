#ifndef hashkdf_h
#define hashkdf_h
#include <stddef.h>
#include <stdint.h>
#include "fips202.h"
#include "auxfunc.h"

#ifdef USE_SHA3
#define KDF128RATE SHAKE128_RATE
#define KDF256RATE SHAKE256_RATE
#define KDF512RATE SHAKE512_RATE
typedef uint64_t kdfstate[25];
#elif defined(USE_ICCS)
#define KDF128RATE 32
#define KDF256RATE 32
#define KDF512RATE 32

#define ICCS_KDF_MAX_INPUT_BYTES 65

typedef struct {
    uint8_t input[ICCS_KDF_MAX_INPUT_BYTES];
    size_t input_len;
    uint32_t counter;
} kdfstate;
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
