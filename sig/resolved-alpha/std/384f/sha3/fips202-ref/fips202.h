#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define SHAKE384_RATE 104
#define SHAKE512_RATE 72

#define FIPS202_NAMESPACE(s) resolved_alpha_fips202_ref_##s

typedef struct {
  uint64_t s[25];
  unsigned int pos;
} keccak_state;

#define KeccakF_RoundConstants FIPS202_NAMESPACE(KeccakF_RoundConstants)
extern const uint64_t KeccakF_RoundConstants[];

#define shake128_init FIPS202_NAMESPACE(shake128_init)
void shake128_init(keccak_state *state);
#define shake128_absorb FIPS202_NAMESPACE(shake128_absorb)
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_finalize FIPS202_NAMESPACE(shake128_finalize)
void shake128_finalize(keccak_state *state);
#define shake128_squeeze FIPS202_NAMESPACE(shake128_squeeze)
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake128_absorb_once FIPS202_NAMESPACE(shake128_absorb_once)
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake128_squeezeblocks FIPS202_NAMESPACE(shake128_squeezeblocks)
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);

#define shake256_init FIPS202_NAMESPACE(shake256_init)
void shake256_init(keccak_state *state);
#define shake256_absorb FIPS202_NAMESPACE(shake256_absorb)
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_finalize FIPS202_NAMESPACE(shake256_finalize)
void shake256_finalize(keccak_state *state);
#define shake256_squeeze FIPS202_NAMESPACE(shake256_squeeze)
void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake256_absorb_once FIPS202_NAMESPACE(shake256_absorb_once)
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake256_squeezeblocks FIPS202_NAMESPACE(shake256_squeezeblocks)
void shake256_squeezeblocks(uint8_t *out, size_t nblocks,  keccak_state *state);

#define shake128 FIPS202_NAMESPACE(shake128)
void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define shake256 FIPS202_NAMESPACE(shake256)
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
#define sha3_256 FIPS202_NAMESPACE(sha3_256)
void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sha3_512 FIPS202_NAMESPACE(sha3_512)
void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen);


#define shake384_init FIPS202_NAMESPACE(shake384_init)
void shake384_init(keccak_state *state);
#define shake384_absorb FIPS202_NAMESPACE(shake384_absorb)
void shake384_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake384_finalize FIPS202_NAMESPACE(shake384_finalize)
void shake384_finalize(keccak_state *state);
#define shake384_squeeze FIPS202_NAMESPACE(shake384_squeeze)
void shake384_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake384_absorb_once FIPS202_NAMESPACE(shake384_absorb_once)
void shake384_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake384_squeezeblocks FIPS202_NAMESPACE(shake384_squeezeblocks)
void shake384_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
#define shake384 FIPS202_NAMESPACE(shake384)
void shake384(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);


#define shake512_init FIPS202_NAMESPACE(shake512_init)
void shake512_init(keccak_state *state);
#define shake512_absorb FIPS202_NAMESPACE(shake512_absorb)
void shake512_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake512_finalize FIPS202_NAMESPACE(shake512_finalize)
void shake512_finalize(keccak_state *state);
#define shake512_squeeze FIPS202_NAMESPACE(shake512_squeeze)
void shake512_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
#define shake512_absorb_once FIPS202_NAMESPACE(shake512_absorb_once)
void shake512_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
#define shake512_squeezeblocks FIPS202_NAMESPACE(shake512_squeezeblocks)
void shake512_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
#define shake512 FIPS202_NAMESPACE(shake512)
void shake512(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

#endif
