#ifndef HASHKDF_H
#define HASHKDF_H
#include "sm3kdf.h"
#include "params.h"

#ifdef USE_SHAKE
#include "hash/keccak/fips202.h"
#define KDF128RATE SHAKE128_RATE
#define KDF256RATE SHAKE256_RATE
#define kdfstate keccak_state
#else
#define KDF128RATE SM3_KDF_RATE
#define KDF256RATE SM3_KDF_RATE
#define kdfstate sm3kdf_ctx
#endif

#define kdf128 AIGIS_ENC_NAMESPACE(kdf128)
void kdf128(uint8_t *out, int outlen, const uint8_t *in, int inlen);
#define kdf256 AIGIS_ENC_NAMESPACE(kdf256)
void kdf256(uint8_t *out, int outlen, const uint8_t *in, int inlen);
#define hash256 AIGIS_ENC_NAMESPACE(hash256)
void hash256(uint8_t *out, const uint8_t *in, int inlen);
#define hash512 AIGIS_ENC_NAMESPACE(hash512)
void hash512(uint8_t *out, const uint8_t *in, int inlen);
#define hash1024 AIGIS_ENC_NAMESPACE(hash1024)
void hash1024(uint8_t *out, const uint8_t *in, int inlen);

#define kdf128_absorb AIGIS_ENC_NAMESPACE(kdf128_absorb)
void kdf128_absorb(kdfstate * state, const uint8_t *input, int inputByteLen);
#define kdf128_squeezeblocks AIGIS_ENC_NAMESPACE(kdf128_squeezeblocks)
void kdf128_squeezeblocks(uint8_t *output, int nblocks, kdfstate * state);

#if SEED_BYTES == 32
#define Hash hash256
#define Hash2 hash512
#elif SEED_BYTES == 64
#define Hash hash512
#define Hash2 hash1024
#else
#error "kem.c/owcpa.c/alg.c only supports SEED_BYTES in {32,64}"
#endif

#endif
