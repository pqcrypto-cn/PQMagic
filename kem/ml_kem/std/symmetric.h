#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define XOF_BLOCKBYTES SHAKE128_RATE

#ifdef USE_SHAKE

#include "hash/keccak/fips202.h"

typedef keccak_state xof_state;

#define shake128_absorb_extend ML_KEM_NAMESPACE(_shake128_absorb_extend)
void shake128_absorb_extend(keccak_state *s,
                           const uint8_t seed[ML_KEM_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

#define shake256_prf ML_KEM_NAMESPACE(_shake256_prf)
void shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[ML_KEM_SYMBYTES], uint8_t nonce);

#define shake256_rkprf ML_KEM_NAMESPACE(_shake256_rkprf)
void shake256_rkprf(uint8_t out[ML_KEM_SSBYTES], const uint8_t key[ML_KEM_SYMBYTES], const uint8_t ct[ML_KEM_CIPHERTEXTBYTES]);

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) shake128_absorb_extend(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) shake256_rkprf(OUT, KEY, INPUT)

#else

#include "sm3_hash.h"
#include "sm3_extended.h"

#define sm3_prf ML_KEM_NAMESPACE(_sm3_prf)
void sm3_prf(uint8_t *out,
             size_t outlen,
             const uint8_t key[ML_KEM_SYMBYTES],
             uint8_t nonce);

#define sm3_rkprf ML_KEM_NAMESPACE(sm3_rkprf)
void sm3_rkprf(uint8_t out[ML_KEM_SSBYTES], const uint8_t key[ML_KEM_SYMBYTES], const uint8_t ct[ML_KEM_CIPHERTEXTBYTES]);

#define hash_h(OUT, IN, INBYTES) sm3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sm3_512(OUT, IN, INBYTES)
#define prf(OUT, OUTBYTES, KEY, NONCE) \
        sm3_prf(OUT, OUTBYTES, KEY, NONCE)
#define rkprf(OUT, KEY, INPUT) sm3_rkprf(OUT, KEY, INPUT)
// #define kdf(OUT, IN, INBYTES) sm3_extended(OUT, ML_KEM_SSBYTES, IN, INBYTES)
#define xof_sm3(OUT, OUTLEN, EXTSEED, LEN) sm3_extended(OUT, OUTLEN, EXTSEED, LEN)

#endif /* USE_SHAKE */

#endif /* SYMMETRIC_H */
