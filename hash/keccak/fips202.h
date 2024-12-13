#ifndef FIPS202_H
#define FIPS202_H

#include <stdio.h>
#include <stdint.h>
#include "include/pqmagic_config.h"

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_128_RATE 168
#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE  72

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

#define shake128_init GLOBAL_NAMESPACE(shake128_init)
void shake128_init(keccak_state *state);
#define shake128_absorb GLOBAL_NAMESPACE(shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_finalize GLOBAL_NAMESPACE(shake128_finalize)
void shake128_finalize(keccak_state *state);
#define shake128_squeeze GLOBAL_NAMESPACE(shake128_squeeze)
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake128_absorb_once GLOBAL_NAMESPACE(shake128_absorb_once)
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_squeezeblocks GLOBAL_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *state);

#define shake128 GLOBAL_NAMESPACE(shake128)
void shake128(uint8_t *output, size_t outlen, const uint8_t *input,  size_t inlen);

#define shake256_init GLOBAL_NAMESPACE(shake256_init)
void shake256_init(keccak_state *state);
#define shake256_absorb GLOBAL_NAMESPACE(shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_finalize GLOBAL_NAMESPACE(shake256_finalize)
void shake256_finalize(keccak_state *state);
#define shake256_squeeze GLOBAL_NAMESPACE(shake256_squeeze)
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake256_absorb_once GLOBAL_NAMESPACE(shake256_absorb_once)
void shake256_absorb_once(keccak_state *state, const uint8_t *input, size_t inlen);
#define shake256_squeezeblocks GLOBAL_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, keccak_state *state);

#define shake256 GLOBAL_NAMESPACE(shake256)
void shake256(uint8_t *output, size_t outlen, const uint8_t *input,  size_t inlen);

#define shake256_inc_init GLOBAL_NAMESPACE(shake256_inc_init)
void shake256_inc_init(uint64_t *s_inc);
#define shake256_inc_absorb GLOBAL_NAMESPACE(shake256_inc_absorb)
void shake256_inc_absorb(uint64_t *s_inc, const uint8_t *input, size_t inlen);
#define shake256_inc_finalize GLOBAL_NAMESPACE(shake256_inc_finalize)
void shake256_inc_finalize(uint64_t *s_inc);
#define shake256_inc_squeeze GLOBAL_NAMESPACE(shake256_inc_squeeze)
void shake256_inc_squeeze(uint8_t *output, size_t outlen, uint64_t *s_inc);

#define sha3_128 GLOBAL_NAMESPACE(sha3_128)
void sha3_128(uint8_t *output, const uint8_t *input,  size_t inlen);
#define sha3_256 GLOBAL_NAMESPACE(sha3_256)
void sha3_256(uint8_t *output, const uint8_t *input,  size_t inlen);
#define sha3_384 GLOBAL_NAMESPACE(sha3_384)
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen);
#define sha3_512 GLOBAL_NAMESPACE(sha3_512)
void sha3_512(uint8_t *output, const uint8_t *input,  size_t inlen);
#define sha3_1024 GLOBAL_NAMESPACE(sha3_1024)
void sha3_1024(uint8_t *output, const uint8_t *input,  size_t inlen);
#endif
