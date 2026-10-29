#include "sm3kdf.h"
#include "./ippcpsm3/ippcp.h"
#include <stdlib.h>
#include <memory.h>

void sm3kdf(uint8_t* output, unsigned long long outlen, const uint8_t* input, unsigned long long inlen)
{
	uint8_t* pData = NULL;
	uint8_t cdgst[32]; //摘要
	uint8_t *cCnt; //计数器的内存表示值
	int nCnt = 1;  //计数器
	int nDgst = 32; //摘要长度
	int nTimes; //需要计算的次数
	int i = 0;

	if (NULL == (pData = (uint8_t*)malloc(inlen + 4)))
		return;
	memcpy(pData, input, inlen);
	cCnt = pData + inlen;

	nTimes = ((int)outlen + 31) / 32;
	nDgst = 32; nCnt = 1;
	for (i = 0; i < nTimes; i++)
	{
		//cCnt
		{
			cCnt[0] = (nCnt >> 24) & 0xFF;
			cCnt[1] = (nCnt >> 16) & 0xFF;
			cCnt[2] = (nCnt >> 8) & 0xFF;
			cCnt[3] = (nCnt) & 0xFF;
		}
		ippsSM3MessageDigest(pData, (int)inlen + 4, cdgst);

		if (i == nTimes - 1) //最后一次计算，根据keylen/32是否整除，截取摘要的值
		{
			if (outlen % 32 != 0)
			{
				nDgst = outlen % 32;
			}
		}
		memcpy(output, cdgst, nDgst);
		output += nDgst;
		nCnt++;
	}

	free(pData);
}

void sm3kdf_init(sm3kdf_ctx* state, const uint8_t* key, unsigned long long klen, uint16_t nonce)
{
	memcpy(state->buf, key, (unsigned int)klen);
	state->pos = (unsigned int)klen;
	state->buf[state->pos++] = (uint8_t)(nonce & 0xFF);
	state->buf[state->pos++] = (uint8_t)(nonce >> 8);
	state->cnt = 1;
}

void sm3kdf_absorb(sm3kdf_ctx* state, const uint8_t* input, unsigned long long inlen)
{
	memcpy(state->buf, input, (unsigned int)inlen);
	state->pos = (unsigned int)inlen;
	state->cnt = 1;
}

void sm3kdf_squeezeblocks(uint8_t* out, unsigned long long nblocks, sm3kdf_ctx* state)
{
	uint8_t *cCnt;
	unsigned int nCnt;
	unsigned int i;

	nCnt = state->cnt;
	cCnt = state->buf + state->pos;
	for (i = 0; i < nblocks; i++)
	{
		cCnt[0] = (nCnt >> 24) & 0xFF;
		cCnt[1] = (nCnt >> 16) & 0xFF;
		cCnt[2] = (nCnt >> 8) & 0xFF;
		cCnt[3] = (nCnt) & 0xFF;

		ippsSM3MessageDigest(state->buf, state->pos + 4, out);
		out += SM3_KDF_RATE;
		nCnt++;
	}
	state->cnt = nCnt;
}
