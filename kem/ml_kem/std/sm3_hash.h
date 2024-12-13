#ifndef SM3_HASH_H
#define SM3_HASH_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "sm3_extended.h"

#define FIPS202_NAMESPACE(s) ML_KEM_NAMESPACE(_fips202##s)

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

#define sm3_256 FIPS202_NAMESPACE(_sm3_256)
void sm3_256(uint8_t h[32], const uint8_t *in, size_t inlen);
#define sm3_512 FIPS202_NAMESPACE(_sm3_512)
void sm3_512(uint8_t *h, const uint8_t *in, size_t inlen);

#endif
