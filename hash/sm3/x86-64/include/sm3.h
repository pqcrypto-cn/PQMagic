
#ifndef __sm3_h__
#define __sm3_h__

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

typedef unsigned long long	u8;
typedef unsigned int		u4;
typedef unsigned short		u2;
typedef unsigned char		u1;

// All in bytes
#define SM3_BLOCK_SIZE      64
#define SM3_DIGEST_LENGTH	32
#define SM3_HMAC_SIZE	    32
#define SM3_CBLOCK	        (SM3_BLOCK_SIZE)

typedef struct _SM3_CTX
{
	uint32_t   digest[8];
	uint32_t   nblocks;                // How many blocks have been compressed. 
	uint8_t    block[SM3_BLOCK_SIZE];  // Store the rest data which not enougn one block
	uint32_t   num;                    // Record how many bytes in block[]

} SM3_CTX;

void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const u1 *data, size_t data_len);
void sm3_final(SM3_CTX *ctx, u1 digest[SM3_DIGEST_LENGTH]);
void sm3_compress(u4 digest[8], const u1* block, u4 nblocks);
size_t sm3(const u1 *data, size_t datalen, u1 dgst[SM3_DIGEST_LENGTH]);


typedef struct _SM3_HMAC_CTX
{
	SM3_CTX sm3_ctx;
	u1 key[SM3_BLOCK_SIZE];

} SM3_HMAC_CTX;

void sm3_hmac_init(SM3_HMAC_CTX *ctx, u1 *key, size_t key_len);
void sm3_hmac_update(SM3_HMAC_CTX *ctx, const u1 *data, size_t data_len);
void sm3_hmac_final(SM3_HMAC_CTX *ctx, u1 mac[SM3_HMAC_SIZE]);
size_t sm3_hmac(const u1 * data, size_t datalen, u1 * key, size_t key_len, u1 mac[SM3_HMAC_SIZE]);


#endif // end of sm3.h

