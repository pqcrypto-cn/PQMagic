// SPDX-License-Identifier: Apache-2.0

#include <pike_hash.h>
#include <stdint.h>
#include <string.h>

#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SM3

#define FF1(x, y, z) ((x) ^ (y) ^ (z))
#define FF2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG1(x, y, z) ((x) ^ (y) ^ (z))
#define GG2(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define P0(x) ((x) ^ rol32((x), 9) ^ rol32((x), 17))
#define P1(x) ((x) ^ rol32((x), 15) ^ rol32((x), 23))

static uint32_t rol32(uint32_t x, unsigned int n)
{
    n &= 31;
    return n == 0 ? x : ((x << n) | (x >> (32 - n)));
}

static uint32_t load_be32(const unsigned char *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void store_be32(unsigned char *out, uint32_t x)
{
    out[0] = (unsigned char)(x >> 24);
    out[1] = (unsigned char)(x >> 16);
    out[2] = (unsigned char)(x >> 8);
    out[3] = (unsigned char)x;
}

static void sm3_init(uint32_t digest[8])
{
    digest[0] = 0x7380166F;
    digest[1] = 0x4914B2B9;
    digest[2] = 0x172442D7;
    digest[3] = 0xDA8A0600;
    digest[4] = 0xA96F30BC;
    digest[5] = 0x163138AA;
    digest[6] = 0xE38DEE4D;
    digest[7] = 0xB0FB0E4E;
}

static void sm3_compress(uint32_t digest[8], const unsigned char *msg, size_t blocks)
{
    while (blocks-- != 0) {
        uint32_t A, B, C, D, E, F, G, H;
        uint32_t W[68];
        uint32_t Wp[64];

        for (int i = 0; i < 16; i++) {
            W[i] = load_be32(msg + 4 * i);
        }
        for (int i = 16; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ rol32(W[i - 3], 15)) ^ rol32(W[i - 13], 7) ^ W[i - 6];
        }
        for (int i = 0; i < 64; i++) {
            Wp[i] = W[i] ^ W[i + 4];
        }

        A = digest[0];
        B = digest[1];
        C = digest[2];
        D = digest[3];
        E = digest[4];
        F = digest[5];
        G = digest[6];
        H = digest[7];

        for (int i = 0; i < 64; i++) {
            uint32_t T = i < 16 ? 0x79cc4519U : 0x7a879d8aU;
            uint32_t SS1 = rol32(rol32(A, 12) + E + rol32(T, (unsigned int)i), 7);
            uint32_t SS2 = SS1 ^ rol32(A, 12);
            uint32_t TT1 = (i < 16 ? FF1(A, B, C) : FF2(A, B, C)) + D + SS2 + Wp[i];
            uint32_t TT2 = (i < 16 ? GG1(E, F, G) : GG2(E, F, G)) + H + SS1 + W[i];

            D = C;
            C = rol32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rol32(F, 19);
            F = E;
            E = P0(TT2);
        }

        digest[0] ^= A;
        digest[1] ^= B;
        digest[2] ^= C;
        digest[3] ^= D;
        digest[4] ^= E;
        digest[5] ^= F;
        digest[6] ^= G;
        digest[7] ^= H;
        msg += 64;
    }
}

static void sm3_hash_bytes(unsigned char out[32], const unsigned char *msg, size_t msg_len)
{
    uint32_t digest[8];
    unsigned char block[64];
    uint64_t bit_len = (uint64_t)msg_len * 8;
    size_t full_blocks = msg_len / 64;
    size_t remaining = msg_len % 64;

    sm3_init(digest);
    if (full_blocks != 0) {
        sm3_compress(digest, msg, full_blocks);
    }

    memset(block, 0, sizeof(block));
    memcpy(block, msg + full_blocks * 64, remaining);
    block[remaining] = 0x80;
    if (remaining >= 56) {
        sm3_compress(digest, block, 1);
        memset(block, 0, sizeof(block));
    }
    store_be32(block + 56, (uint32_t)(bit_len >> 32));
    store_be32(block + 60, (uint32_t)bit_len);
    sm3_compress(digest, block, 1);

    for (int i = 0; i < 8; i++) {
        store_be32(out + 4 * i, digest[i]);
    }
}

static void sm3_stream_refill(pike_xof_ctx_t *ctx)
{
    unsigned char msg[ctx->seed_len + 4];

    memcpy(msg, ctx->seed, ctx->seed_len);
    store_be32(msg + ctx->seed_len, ctx->counter);
    sm3_hash_bytes(ctx->block, msg, ctx->seed_len + 4);
    ctx->counter++;
    ctx->block_pos = 0;
}

#endif

int pike_xof(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen)
{
#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
    return SHAKE256(out, outlen, in, inlen);
#else
    pike_xof_ctx_t ctx;
    pike_xof_stream_init(&ctx, in, inlen);
    pike_xof_stream_squeeze(&ctx, out, outlen);
    pike_xof_stream_release(&ctx);
    return 0;
#endif
}

int pike_hash_256(unsigned char *out, const unsigned char *in, size_t inlen)
{
#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
    return pike_xof(out, 32, in, inlen);
#else
    sm3_hash_bytes(out, in, inlen);
    return 0;
#endif
}

void pike_xof_stream_init(pike_xof_ctx_t *ctx, const unsigned char *seed, size_t seed_len)
{
#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
    shake256_absorb(&ctx->shake, seed, seed_len);
    ctx->block_pos = SHAKE256_RATE;
#else
    ctx->seed = seed;
    ctx->seed_len = seed_len;
    ctx->counter = 1;
    ctx->block_pos = sizeof(ctx->block);
#endif
}

void pike_xof_stream_squeeze(pike_xof_ctx_t *ctx, unsigned char *out, size_t outlen)
{
    while (outlen != 0) {
#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
        const size_t block_len = SHAKE256_RATE;
        if (ctx->block_pos == block_len) {
            shake256_squeezeblocks(ctx->block, 1, &ctx->shake);
            ctx->block_pos = 0;
        }
#else
        const size_t block_len = sizeof(ctx->block);
        if (ctx->block_pos == block_len) {
            sm3_stream_refill(ctx);
        }
#endif
        size_t take = block_len - ctx->block_pos;
        if (take > outlen) {
            take = outlen;
        }
        memcpy(out, ctx->block + ctx->block_pos, take);
        out += take;
        outlen -= take;
        ctx->block_pos += take;
    }
}

void pike_xof_stream_release(pike_xof_ctx_t *ctx)
{
#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
    shake256_ctx_release(&ctx->shake);
#else
    (void)ctx;
#endif
}
