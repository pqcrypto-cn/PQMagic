#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hash.h"
#include "spx_sm3.h"

/* For SHAKE256, there is no immediate reason to initialize at the start,
   so this function is an empty operation. */
void initialize_hash_function(spx_ctx* ctx)
{
    (void)ctx; /* Suppress an 'unused parameter' warning. */
}

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
void prf_addr(unsigned char *out, const spx_ctx *ctx,
              const uint32_t addr[8])
{
    unsigned char buf[2*SPX_N + SPX_SM3_ADDR_BYTES];
    unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];

    memcpy(buf, ctx->pub_seed, SPX_N);
    memcpy(buf + SPX_N, addr, SPX_SM3_ADDR_BYTES);
    memcpy(buf + SPX_N + SPX_SM3_ADDR_BYTES, ctx->sk_seed, SPX_N);

    // SPX_N is less then SPX_SM3_OUTPUT_BYTES, no need extend.
    // sm3_extended(out, SPX_N, buf, 2*SPX_N + SPX_SM3_ADDR_BYTES);
    sm3(buf, 2*SPX_N + SPX_SM3_ADDR_BYTES, outbuf);
    memcpy(out, outbuf, SPX_N);
}

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 * Computes PRF_msg
 */
void gen_message_random(unsigned char *R, const unsigned char *sk_prf,
                        const unsigned char *optrand,
                        const unsigned char *m, unsigned long long mlen,
                        const spx_ctx *ctx)
{
    (void)ctx;

    unsigned char outbuf[SM3_HMAC_SIZE];
    SM3_HMAC_CTX hctx;

    // optrand || M
    sm3_hmac_init(&hctx, (u1 *)sk_prf, SPX_N);
    sm3_hmac_update(&hctx, optrand, SPX_N);
    sm3_hmac_update(&hctx, m, (size_t)mlen);
    sm3_hmac_final(&hctx, outbuf);

    memcpy(R, outbuf, SPX_N);
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 * Computes H_msg.
 */
void hash_message(unsigned char *digest, uint64_t *tree, uint32_t *leaf_idx,
                  const unsigned char *R, const unsigned char *pk,
                  const unsigned char *m, unsigned long long mlen,
                  const spx_ctx *ctx)
{
    (void)ctx;
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

    unsigned char seed[2*SPX_N + SPX_SM3_OUTPUT_BYTES];
    unsigned char buf[SPX_DGST_BYTES];
    unsigned char *bufp = buf;

    SM3_CTX sm3_ctx;

    // SM3(R ‖ PK.seed ‖ PK.root ‖ M)
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, R, SPX_N);
    sm3_update(&sm3_ctx, pk, SPX_PK_BYTES);
    sm3_update(&sm3_ctx, m, (size_t)mlen);
    sm3_final(&sm3_ctx, seed + 2*SPX_N);

    // H_msg: MGF1-SHA-X(R ‖ PK.seed ‖ seed)
    memcpy(seed, R, SPX_N);
    memcpy(seed + SPX_N, pk, SPX_N);

    /* By doing this in two steps, we prevent hashing the message twice;
       otherwise each iteration in MGF1 would hash the message again. */
    mgf1_sm3(bufp, SPX_DGST_BYTES, seed, 2*SPX_N + SPX_SM3_OUTPUT_BYTES);

    memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
    bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
    #error For given height and depth, 64 bits cannot represent all subtrees
#endif

    *tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = (uint32_t)bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
