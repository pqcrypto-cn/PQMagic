#include "include/sm3.h"

#define cpu_to_be32(v) (((v)>>24) | (((v)>>8)&0xff00) | (((v)<<8)&0xff0000) | ((v)<<24))

#define ROTATELEFT(X,n)  (((X)<<(n%32)) | ((X)>>(32-(n%32))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z) )
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z) )
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

# define ONE_ROUND_16(A, B, C, D, E, F, G, H, idx)\
	SS1 = ROTATELEFT(A, 12) + E + Ti[idx];\
	SS1 = ROTATELEFT(SS1, 7);\
	SS2 = SS1 ^ ROTATELEFT(A, 12);\
	k = W[idx];\
	D = FF0(A, B, C) + D + SS2 + (k ^ W[idx + 4]);\
	H = GG0(E, F, G) + H + SS1 + k;\
	H = P0(H);\
	B = ROTATELEFT(B, 9);\
	F = ROTATELEFT(F, 19);\


# define ONE_ROUNDS_16(A, B, C, D, E, F, G, H, idx)\
	ONE_ROUND_16(A, B, C, D, E, F, G, H, idx);\
	ONE_ROUND_16(D, A, B, C, H, E, F, G, idx+1);\
	ONE_ROUND_16(C, D, A, B, G, H, E, F, idx+2);\
	ONE_ROUND_16(B, C, D, A, F, G, H, E, idx+3);\

# define ONE_ROUND_64(A, B, C, D, E, F, G, H, idx)\
	SS1 =ROTATELEFT(A, 12) + E + Ti[idx];\
	SS1 = ROTATELEFT(SS1, 7);\
	SS2 = SS1 ^ ROTATELEFT(A, 12);\
	k = W[idx];\
	D = FF1(A, B, C) + D + SS2 + (k ^ W[idx + 4]);\
	H = GG1(E, F, G) + H + SS1 + k;\
	H = P0(H);\
	B = ROTATELEFT(B, 9);\
	F = ROTATELEFT(F, 19);\
	
# define ONE_ROUNDS_64(A, B, C, D, E, F, G, H, idx)\
	ONE_ROUND_64(A, B, C, D, E, F, G, H, idx);\
	ONE_ROUND_64(D, A, B, C, H, E, F, G, idx+1);\
	ONE_ROUND_64(C, D, A, B, G, H, E, F, idx+2);\
	ONE_ROUND_64(B, C, D, A, F, G, H, E, idx+3);\

// Ti table, T[i] = ROT(T, i);
static uint32_t Ti[64] =
{
	0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
	0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
	0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
	0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
};

void sm3_init(SM3_CTX *ctx)
{
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void sm3_update(SM3_CTX *ctx, const u1 * data, size_t data_len)
{
	uint32_t nblock = 0, offset = 0;
	uint32_t left = 0;

	if (ctx->num)
	{
		left = SM3_BLOCK_SIZE - ctx->num;
		if (data_len < left)
		{
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
			return;
		}
		else
		{
			memcpy(ctx->block + ctx->num, data, left);
			sm3_compress(ctx->digest, ctx->block, 1);
			ctx->nblocks++;
			data += left;
			data_len -= left;
			ctx->num = 0;
		}
	}
	nblock = data_len / SM3_BLOCK_SIZE;
	left = data_len % SM3_BLOCK_SIZE;
	offset = data_len - left;
	ctx->num = left;
	if (nblock > 0)
	{
		sm3_compress(ctx->digest, data, nblock);
		ctx->nblocks += nblock;
	}
	memcpy(ctx->block, data + offset, left);
	
}

void sm3_final(SM3_CTX *ctx, u1 digest[SM3_DIGEST_LENGTH])
{
	uint32_t i = 0;
	uint32_t * pdigest = (uint32_t *)digest;
	uint32_t * count = (uint32_t *)(ctx->block + SM3_BLOCK_SIZE - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_BLOCK_SIZE)
	{
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
	}
	else
	{
		memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
		sm3_compress(ctx->digest, ctx->block, 1);
		memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
	}

	count[0] = (uint32_t)(cpu_to_be32((ctx->nblocks) >> 23));
	count[1] = (uint32_t)(cpu_to_be32((ctx->nblocks << 9) + (ctx->num << 3)));

	sm3_compress(ctx->digest, ctx->block, 1);

	for (i = 0; i < 8; ++i)
	{
		pdigest[i] = cpu_to_be32(ctx->digest[i]);
	}
}

void sm3_compress(u4 digest[8], const u1* block, u4 nblocks)
{
	uint32_t i = 0, j = 0, k;
	uint32_t W[68] = { 0 };
	uint32_t *pblock = NULL;
	uint32_t A, B, C, D, E, F, G, H;
	uint32_t SS1, SS2;

	// Compress each block
	A = digest[0]; B = digest[1]; C = digest[2]; D = digest[3];
	E = digest[4]; F = digest[5]; G = digest[6]; H = digest[7];

	for (i = 0; i < nblocks; i++)
	{
		pblock = (uint32_t *)block;
		block += SM3_BLOCK_SIZE;
		for (j = 0; j < 16; j++)
		{
			SS2 = pblock[j];
			W[j] = cpu_to_be32(SS2);
		}
		for (j = 16; j < 68; j++)
		{
			SS2 = W[j - 3];
			SS1 = W[j - 16] ^ W[j - 9] ^ ROTATELEFT(SS2, 15);
			SS2 = W[j - 13];
			W[j] = P1(SS1) ^ ROTATELEFT(SS2, 7) ^ W[j - 6];
		}

		ONE_ROUNDS_16(A, B, C, D, E, F, G, H, 0);
		ONE_ROUNDS_16(A, B, C, D, E, F, G, H, 4);
		ONE_ROUNDS_16(A, B, C, D, E, F, G, H, 8);
		ONE_ROUNDS_16(A, B, C, D, E, F, G, H, 12);

		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 16);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 20);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 24);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 28);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 32);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 36);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 40);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 44);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 48);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 52);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 56);
		ONE_ROUNDS_64(A, B, C, D, E, F, G, H, 60);

		digest[0] = A = digest[0] ^ A;
		digest[1] = B = digest[1] ^ B;
		digest[2] = C = digest[2] ^ C;
		digest[3] = D = digest[3] ^ D;
		digest[4] = E = digest[4] ^ E;
		digest[5] = F = digest[5] ^ F;
		digest[6] = G = digest[6] ^ G;
		digest[7] = H = digest[7] ^ H;
	}
}

size_t sm3(const u1 *data, size_t datalen, u1 dgst[SM3_DIGEST_LENGTH])
{
	SM3_CTX ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, data, datalen);
	sm3_final(&ctx, dgst);

	memset(&ctx, 0, sizeof(SM3_CTX));
	return SM3_DIGEST_LENGTH;
}


#define IPAD	0x36
#define OPAD	0x5C
void sm3_hmac_init(SM3_HMAC_CTX *ctx, u1 *key, size_t keylen)
{
	int i = 0;

	if (keylen <= SM3_BLOCK_SIZE)
	{
		memcpy(ctx->key, key, keylen);
		memset(ctx->key + keylen, 0, SM3_BLOCK_SIZE - keylen);
	}
	else
	{
		sm3_init(&ctx->sm3_ctx);
		sm3_update(&ctx->sm3_ctx, key, keylen);
		sm3_final(&ctx->sm3_ctx, ctx->key);
		memset(ctx->key + SM3_DIGEST_LENGTH, 0, SM3_BLOCK_SIZE - SM3_DIGEST_LENGTH);
	}
	for (i = 0; i < SM3_BLOCK_SIZE; i++)
	{
		ctx->key[i] ^= IPAD;
	}

	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
}

void sm3_hmac_update(SM3_HMAC_CTX *ctx, const u1 *data, size_t data_len)
{
	sm3_update(&ctx->sm3_ctx, data, data_len);
}

void sm3_hmac_final(SM3_HMAC_CTX *ctx, u1 mac[SM3_HMAC_SIZE])
{
	int i = 0;

	for (i = 0; i < SM3_BLOCK_SIZE; i++)
	{
		ctx->key[i] ^= (IPAD ^ OPAD);
	}
	sm3_final(&ctx->sm3_ctx, mac);
	sm3_init(&ctx->sm3_ctx);
	sm3_update(&ctx->sm3_ctx, ctx->key, SM3_BLOCK_SIZE);
	sm3_update(&ctx->sm3_ctx, mac, SM3_DIGEST_LENGTH);
	sm3_final(&ctx->sm3_ctx, mac);
}

size_t sm3_hmac(const u1 *data, size_t data_len, u1 *key, size_t key_len, u1 mac[SM3_HMAC_SIZE])
{
	SM3_HMAC_CTX ctx;
	sm3_hmac_init(&ctx, key, key_len);
	sm3_hmac_update(&ctx, data, data_len);
	sm3_hmac_final(&ctx, mac);
	memset(&ctx, 0, sizeof(ctx));
	return SM3_HMAC_SIZE;
}




