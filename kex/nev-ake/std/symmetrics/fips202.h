#ifndef FIPS202_H
#define FIPS202_H

#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHAKE512_RATE 72
#define SHA3_128_RATE 168
#define SHA3_256_RATE 136
#define SHA3_384_RATE 104
#define SHA3_512_RATE  72

void shake128_absorb(uint64_t *s, const unsigned char *input, unsigned long long inputByteLen);
void shake128_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void shake256_absorb(uint64_t *s, const unsigned char *input, unsigned long long inputByteLen);
void shake256_squeezeblocks(unsigned char *output, unsigned long long nblocks, uint64_t *s);
void shake512_absorb(uint64_t* s, const unsigned char* input, unsigned long long inputByteLen);
void shake512_squeezeblocks(unsigned char* output, unsigned long long nblocks, uint64_t* s);

void shake128(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
void shake256(unsigned char *output, unsigned long long outlen, const unsigned char *input,  unsigned long long inlen);
void shake512(unsigned char* output, unsigned long long outlen, const unsigned char* input, unsigned long long inlen);

void sha3_128(unsigned char *output, const unsigned char *input,  unsigned long long inlen);
void sha3_256(unsigned char *output, const unsigned char *input,  unsigned long long inlen);
void sha3_384(unsigned char *output, const unsigned char *input, unsigned long long inlen);
void sha3_512(unsigned char *output, const unsigned char *input,  unsigned long long inlen);
void sha3_1024(unsigned char *output, const unsigned char *input,  unsigned long long inlen);
#endif
