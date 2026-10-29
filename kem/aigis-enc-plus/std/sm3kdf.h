#ifndef _SM3_KDF_H_
#define _SM3_KDF_H_

#include <stdint.h>

#define SM3_KDF_RATE	32

typedef struct {
	uint8_t buf[512];
	unsigned int pos;
	unsigned int cnt;
} sm3kdf_ctx;

void sm3kdf_init(sm3kdf_ctx* state, const uint8_t* key, unsigned long long klen, uint16_t nonce);

void sm3kdf_absorb(sm3kdf_ctx* state, const uint8_t* input, unsigned long long inlen);

void sm3kdf_squeezeblocks(uint8_t* out, unsigned long long nblocks, sm3kdf_ctx* state);

void sm3kdf(uint8_t* output, unsigned long long outlen, const uint8_t* input, unsigned long long inlen);

#endif // !_SM3_KDF_H_
