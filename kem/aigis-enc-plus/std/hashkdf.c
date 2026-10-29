#include "hashkdf.h"
#include "sm3kdf.h"
#include "kat_test/auxfunc.h"



void kdf128(uint8_t *out, int outlen, uint8_t *in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, outlen, in, inlen);
#elif defined(USE_NICCS_API)
	pseudoXOF(outlen * 8, in, inlen * 8, out);
#elif defined(USE_SHA3)
	shake128(out, outlen, in, inlen);
#endif
}

void kdf256(uint8_t *out, int outlen, uint8_t *in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, outlen, in, inlen);
#elif defined(USE_NICCS_API)
	pseudoXOF(outlen * 8, in, inlen * 8, out);
#elif defined(USE_SHA3)
	shake256(out, outlen, in, inlen);
#else
	//uint8_t nounce[12] = { 0 };
	//nounce[0] = in[32];
	aes256ctr_prf(out, outlen, in, in[32]);
#endif
}

void kdf512(uint8_t* out, int outlen, uint8_t* in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, outlen, in, inlen);
#elif defined(USE_NICCS_API)
	pseudoXOF(outlen * 8, in, inlen * 8, out);
#elif defined(USE_SHA3)
	shake512(out, outlen, in, inlen);
#else
	aes256ctr_prf(out, outlen, in, in[32]);
#endif
}

void hash128(uint8_t* out, uint8_t* in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, 16, in, inlen);
#elif defined(USE_NICCS_API)
	pseudoXOF(128, in, inlen * 8, out);
#else
	sha3_128(out, in, inlen);
#endif
}

void hash256(uint8_t *out, uint8_t *in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, 32, in, inlen);
#elif defined(USE_NICCS_API)
	sm3hash(256, in, inlen * 8, out);
#else
	sha3_256(out, in, inlen);
#endif
}

void hash512(uint8_t *out, uint8_t *in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, 64, in, inlen);
#elif defined(USE_NICCS_API)
	pseudohash(512, in, inlen * 8, out);
#else
	sha3_512(out, in, inlen);
#endif
}

void hash1024(uint8_t* out, uint8_t* in, int inlen)
{
#ifdef USE_SM3
	sm3kdf(out, 128, in, inlen);
#elif defined(USE_NICCS_API)
	pseudohash(1024, in, inlen * 8, out);
#else
	sha3_1024(out, in, inlen);
#endif
}

#ifdef USE_NICCS_API
void kdf_init(kdfstate* state, const uint8_t* input, int inlen) {
	init_random_number(state, input, inlen);
}

void kdf_squeezeblocks(uint8_t* output, int nblocks, kdfstate* state)
{
	get_random_number(state, output, nblocks * 256);
}
#endif

void kdf128_absorb(kdfstate* state, const uint8_t* input, int inlen)
{
#ifdef USE_SM3
	sm3kdf_absorb(state, input, inlen);
#elif  defined(USE_SHA3)
	shake128_absorb(*state, input, inlen);
#endif
}

void kdf128_squeezeblocks(uint8_t* output, int nblocks, kdfstate* state)
{
#ifdef USE_SM3
	sm3kdf_squeezeblocks(output, nblocks, state);
#elif  defined(USE_SHA3)
	shake128_squeezeblocks(output, nblocks, *state); 
#endif
}

void kdf256_absorb(kdfstate * state, const uint8_t *input, int inlen)
{
#ifdef USE_SM3
	sm3kdf_absorb(state, input, inlen);
#elif  defined(USE_SHA3)
	shake256_absorb(*state, input, inlen);
#endif
}
void kdf256_squeezeblocks(uint8_t *output, int nblocks, kdfstate * state)
{
#ifdef USE_SM3
	sm3kdf_squeezeblocks(output, nblocks, state);
#elif  defined(USE_SHA3)
	shake256_squeezeblocks(output, nblocks, *state);
#endif
}

void kdf512_absorb(kdfstate* state, const uint8_t* input, int inlen)
{
#ifdef USE_SM3
	sm3kdf_absorb(state, input, inlen);
#elif  defined(USE_SHA3)
	shake512_absorb(*state, input, inlen);
#endif
}
void kdf512_squeezeblocks(uint8_t* output, int nblocks, kdfstate* state)
{
#ifdef USE_SM3
	sm3kdf_squeezeblocks(output, nblocks, state);
#elif  defined(USE_SHA3)
	shake512_squeezeblocks(output, nblocks, *state);
#endif
}