#include "sm3kdf.h"
#include "hash/sm3/x86-64/include/sm3.h"
#include <stdlib.h>
#include <memory.h>

// Only absorb once.
void sm3kdf_absorb(sm3kdf_ctx* state, const uint8_t* input, unsigned long long inlen)
{
	// First 4 bytes are used for nonce
	memcpy(state->buf + 4, input, (unsigned int)inlen);
	state->len = (unsigned int)inlen;
	state->cnt = 0; // Nonce starts from zero.
}

void sm3kdf_squeezeblocks(uint8_t* out, unsigned long long nblocks, sm3kdf_ctx* state)
{
	uint8_t *cCnt;
	unsigned int nCnt;
	unsigned int i;

	nCnt = state->cnt;
	// First 4 bytes in buf are prserved for nonce.
	cCnt = state->buf;
	for (i = 0; i < nblocks; i++)
	{
		cCnt[0] = (nCnt >> 24) & 0xFF;
		cCnt[1] = (nCnt >> 16) & 0xFF;
		cCnt[2] = (nCnt >> 8) & 0xFF;
		cCnt[3] = (nCnt) & 0xFF;

		sm3(state->buf, state->len + 4, out);
		out += SM3_KDF_RATE;
		nCnt++;
	}
	state->cnt = nCnt;
}

