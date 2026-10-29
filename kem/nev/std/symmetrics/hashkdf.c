#include "hashkdf.h"

#include <stddef.h>
#include <string.h>


#ifdef USE_ICCS

static void store32_be(uint8_t out[4], uint32_t x)
{
	out[0] = (uint8_t)(x >> 24);
	out[1] = (uint8_t)(x >> 16);
	out[2] = (uint8_t)(x >> 8);
	out[3] = (uint8_t)x;
}

static void iccs_kdf_absorb(kdfstate *state,
							const uint8_t *input,
							size_t input_len)
{

	memcpy(state->input, input, input_len);
	state->input_len = input_len;

	state->counter = 1;
}

static void iccs_kdf_squeezeblocks(uint8_t *output,
								   size_t nblocks,
								   kdfstate *state)
{
	uint8_t input_with_counter[ICCS_KDF_MAX_INPUT_BYTES + 4];


	memcpy(input_with_counter,
		   state->input,
		   state->input_len);

	for (size_t i = 0; i < nblocks; ++i) {
		store32_be(input_with_counter + state->input_len,
				   state->counter);


		sm3hash(
			256,
			input_with_counter,
			8ULL * (state->input_len + 4),
			output + 32 * i
		);


		state->counter++;
	}
}

#endif

void kdf128(uint8_t *out, int outlen, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	pseudoXOF(outlen * 8, in, inlen * 8, out);
#elif defined(USE_SHA3)
	shake128(out, outlen, in, inlen);
#endif
}

void kdf256(uint8_t *out, int outlen, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	pseudoXOF(outlen * 8, in, inlen * 8, out);
#elif defined(USE_SHA3)
	shake256(out, outlen, in, inlen);
#endif
}

void kdf512(uint8_t *out, int outlen, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	pseudoXOF(outlen * 8, in, inlen * 8, out);
#elif defined(USE_SHA3)
	shake512(out, outlen, in, inlen);
#endif
}

void hash128(uint8_t *out, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	pseudoXOF(128, in, inlen * 8, out);
#elif defined(USE_SHA3)
	sha3_128(out, in, inlen);
#endif
}

void hash256(uint8_t *out, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	sm3hash(256, in, inlen * 8, out);
#elif defined(USE_SHA3)
	sha3_256(out, in, inlen);
#endif
}

void hash512(uint8_t *out, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	pseudohash(512, in, inlen * 8, out);
#elif defined(USE_SHA3)
	sha3_512(out, in, inlen);
#endif
}

void hash1024(uint8_t *out, uint8_t *in, int inlen)
{
#ifdef USE_ICCS
	pseudohash(1024, in, inlen * 8, out);
#elif defined(USE_SHA3)
	sha3_1024(out, in, inlen);
#endif
}

void kdf128_absorb(kdfstate *state,
				   const uint8_t *input,
				   int inlen)
{
#ifdef USE_SHA3
	shake128_absorb(*state, input, inlen);
#elif defined(USE_ICCS)
	iccs_kdf_absorb(state, input, (size_t)inlen);
#endif
}

void kdf128_squeezeblocks(uint8_t *output,
						  int nblocks,
						  kdfstate *state)
{
#ifdef USE_SHA3
	shake128_squeezeblocks(output, nblocks, *state);
#elif defined(USE_ICCS)
	iccs_kdf_squeezeblocks(output, (size_t)nblocks, state);
#endif
}

void kdf256_absorb(kdfstate *state,
				   const uint8_t *input,
				   int inlen)
{
#ifdef USE_SHA3
	shake256_absorb(*state, input, inlen);
#elif defined(USE_ICCS)
	iccs_kdf_absorb(state, input, (size_t)inlen);
#endif
}

void kdf256_squeezeblocks(uint8_t *output,
						  int nblocks,
						  kdfstate *state)
{
#ifdef USE_SHA3
	shake256_squeezeblocks(output, nblocks, *state);
#elif defined(USE_ICCS)
	iccs_kdf_squeezeblocks(output, (size_t)nblocks, state);
#endif
}

void kdf512_absorb(kdfstate *state,
				   const uint8_t *input,
				   int inlen)
{
#ifdef USE_SHA3
	shake512_absorb(*state, input, inlen);
#elif defined(USE_ICCS)
	iccs_kdf_absorb(state, input, (size_t)inlen);
#endif
}

void kdf512_squeezeblocks(uint8_t *output,
						  int nblocks,
						  kdfstate *state)
{
#ifdef USE_SHA3
	shake512_squeezeblocks(output, nblocks, *state);
#elif defined(USE_ICCS)
	iccs_kdf_squeezeblocks(output, (size_t)nblocks, state);
#endif
}