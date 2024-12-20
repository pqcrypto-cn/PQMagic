#ifndef SPX_SHA2_H
#define SPX_SHA2_H

#include "params.h"

#define SPX_SHA256_BLOCK_BYTES 64
#define SPX_SHA256_OUTPUT_BYTES 32  /* This does not necessarily equal SPX_N */

#define SPX_SHA512_BLOCK_BYTES 128
#define SPX_SHA512_OUTPUT_BYTES 64

#if SPX_SHA256_OUTPUT_BYTES < SPX_N
    #error Linking against SHA-256 with N larger than 32 bytes is not supported
#endif

#define SPX_SHA256_ADDR_BYTES 22

#include <stddef.h>
#include <stdint.h>

#define sha256_inc_init SPX_NAMESPACE(msha256_inc_initgf1_256)
void sha256_inc_init(uint8_t *state);
#define sha256_inc_blocks SPX_NAMESPACE(sha256_inc_blocks)
void sha256_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
#define sha256_inc_finalize SPX_NAMESPACE(sha256_inc_finalize)
void sha256_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
#define sha256 SPX_NAMESPACE(sha256)
void sha256(uint8_t *out, const uint8_t *in, size_t inlen);

#define sha512_inc_init SPX_NAMESPACE(sha512_inc_init)
void sha512_inc_init(uint8_t *state);
#define sha512_inc_blocks SPX_NAMESPACE(sha512_inc_blocks)
void sha512_inc_blocks(uint8_t *state, const uint8_t *in, size_t inblocks);
#define sha512_inc_finalize SPX_NAMESPACE(sha512_inc_finalize)
void sha512_inc_finalize(uint8_t *out, uint8_t *state, const uint8_t *in, size_t inlen);
#define sha512 SPX_NAMESPACE(sha512)
void sha512(uint8_t *out, const uint8_t *in, size_t inlen);

#define mgf1_256 SPX_NAMESPACE(mgf1_256)
void mgf1_256(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define mgf1_512 SPX_NAMESPACE(mgf1_512)
void mgf1_512(unsigned char *out, unsigned long outlen,
          const unsigned char *in, unsigned long inlen);

#define seed_state SPX_NAMESPACE(seed_state)
void seed_state(spx_ctx *ctx);


#endif
