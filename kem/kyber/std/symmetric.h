#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#define XOF_BLOCKBYTES SHAKE128_RATE

#ifdef USE_SHAKE

#include "hash/keccak/fips202.h"

typedef keccak_state xof_state;

#define shake128_absorb_extend KYBER_NAMESPACE(_shake128_absorb_extend)
void shake128_absorb_extend(keccak_state *s,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

#define shake256_prf KYBER_NAMESPACE(_shake256_prf)
void shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) shake128_absorb_extend(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)

#else

#include "sm3_hash.h"
#include "sm3_extended.h"

#define sm3_prf KYBER_NAMESPACE(_sm3_prf)
void sm3_prf(uint8_t *out,
             size_t outlen,
             const uint8_t key[KYBER_SYMBYTES],
             uint8_t nonce);

#define hash_h(OUT, IN, INBYTES) sm3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sm3_512(OUT, IN, INBYTES)
#define prf(OUT, OUTBYTES, KEY, NONCE) \
        sm3_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) sm3_extended(OUT, KYBER_SSBYTES, IN, INBYTES)
#define xof_sm3(OUT, OUTLEN, EXTSEED, LEN) sm3_extended(OUT, OUTLEN, EXTSEED, LEN)

#endif /* USE_SHAKE */

#endif /* SYMMETRIC_H */
