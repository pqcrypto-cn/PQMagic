#ifndef _SM3_KDF_H_
#define _SM3_KDF_H_

#include <stdint.h>
#include "params.h"
#include "include/sm3_extended.h"

#define SM3_KDF_RATE	32

typedef struct {
	uint8_t buf[512];
	unsigned int len;
	unsigned int cnt;
} sm3kdf_ctx;

#define sm3kdf_absorb AIGIS_ENC_NAMESPACE(sm3kdf_absorb)
void sm3kdf_absorb(sm3kdf_ctx* state, const uint8_t* input, unsigned long long inlen);

#define sm3kdf_squeezeblocks AIGIS_ENC_NAMESPACE(sm3kdf_squeezeblocks)
void sm3kdf_squeezeblocks(uint8_t* out, unsigned long long nblocks, sm3kdf_ctx* state);

// void sm3kdf(uint8_t* output, unsigned long long outlen, const uint8_t* input, unsigned long long inlen);
#define sm3kdf sm3_extended

#endif // !_SM3_KDF_H_
