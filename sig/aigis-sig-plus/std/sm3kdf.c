#include "sm3kdf.h"
#include <stdlib.h>
#include <memory.h>

void sm3kdf(unsigned char* output, unsigned long long outlen, const unsigned char* input, unsigned long long inlen)
{
	unsigned char* pData = NULL;
	unsigned char cdgst[32]; //ժҪ
	unsigned char *cCnt; //���������ڴ��ʾֵ
	int nCnt = 1;  //������
	int nDgst = 32; //ժҪ����
	int nTimes; //��Ҫ����Ĵ���
	int i = 0;

	if (NULL == (pData = (unsigned char*)malloc(inlen + 4)))
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

		if (i == nTimes - 1) //���һ�μ��㣬����keylen/32�Ƿ���������ȡժҪ��ֵ
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

void sm3kdf_init(sm3kdf_ctx* state, const unsigned char* key, unsigned long long klen, uint16_t nonce)
{
	memcpy(state->buf, key, (unsigned int)klen);
	state->pos = (unsigned int)klen;
	state->buf[state->pos++] = (unsigned char)(nonce & 0xFF);
	state->buf[state->pos++] = (unsigned char)(nonce >> 8);
	state->cnt = 1;
}

void sm3kdf_absorb(sm3kdf_ctx* state, const unsigned char* input, unsigned long long inlen)
{
	memcpy(state->buf, input, (unsigned int)inlen);
	state->pos = (unsigned int)inlen;
	state->cnt = 1;
}

void sm3kdf_squeezeblocks(unsigned char* out, unsigned long long nblocks, sm3kdf_ctx* state)
{
	unsigned char *cCnt;
	unsigned int nCnt;
	int i;

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
