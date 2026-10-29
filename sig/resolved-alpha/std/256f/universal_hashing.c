/*
 *  SPDX-License-Identifier: MIT
 */

#include "instances.h"
#include "universal_hashing.h"
#include "utils.h"

#include <assert.h>
#include <string.h>

static bf64_t compute_h1(const uint8_t* t, const uint8_t* x, unsigned int lambda,
                         unsigned int input_bits) {
  (void)lambda;
  const bf64_t b_t = bf64_load(t);

  const unsigned int gf64_bits  = 64;
  const unsigned int gf64_bytes = gf64_bits / 8;
  const unsigned int length_64  = (input_bits + gf64_bits - 1) / gf64_bits;

  uint8_t tmp[sizeof(uint64_t)] = {0};
  const unsigned int tail_bits  = input_bits % gf64_bits;
  const unsigned int tail_bytes = tail_bits == 0 ? gf64_bytes : (tail_bits + 7) / 8;
  memcpy(tmp, x + (length_64 - 1) * gf64_bytes, tail_bytes);

  bf64_t h1        = bf64_zero();
  bf64_t running_t = bf64_one();

  for (unsigned int block = length_64; block-- > 0;) {
    const uint8_t* block_ptr = block == length_64 - 1 ? tmp : x + block * gf64_bytes;
    h1                       = bf64_add(h1, bf64_mul(running_t, bf64_load(block_ptr)));
    running_t                = bf64_mul(running_t, b_t);
  }

  return h1;
}

static bf384_t bf384_mul_64_compat(bf384_t lhs, bf64_t rhs) {
  uint8_t rhs_bytes[BF384_NUM_BYTES] = {0};
  bf64_store(rhs_bytes, rhs);
  return bf384_mul(lhs, bf384_load(rhs_bytes));
}

static bf512_t bf512_mul_64_compat(bf512_t lhs, bf64_t rhs) {
  uint8_t rhs_bytes[BF512_NUM_BYTES] = {0};
  bf64_store(rhs_bytes, rhs);
  return bf512_mul(lhs, bf512_load(rhs_bytes));
}

static void vole_hash_128_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x,
                                       unsigned int ell, unsigned int degree) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF128_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF128_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF128_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF128_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF128_NUM_BYTES;
  const unsigned int lambda_bits = BF128_NUM_BYTES * 8;
  const unsigned int first_part_bits = ell + (degree - 1) * lambda_bits;
  const uint8_t* x1 = x + first_part_bits / 8;
  const unsigned int length_lambda = (first_part_bits + lambda_bits - 1) / lambda_bits;

  uint8_t tmp[BF128_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF128_NUM_BYTES,
         first_part_bits % lambda_bits == 0 ? BF128_NUM_BYTES : (first_part_bits % lambda_bits) / 8);
  bf128_t h0 = bf128_load(tmp);

  const bf128_t b_s = bf128_load(s);
  bf128_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf128_mul(running_s, b_s)) {
    h0 = bf128_add(h0, bf128_mul(running_s, bf128_load(x + (length_lambda - 1 - i) * BF128_NUM_BYTES)));
  }

  bf64_t h1 = compute_h1(t, x, lambda_bits, first_part_bits);
  bf128_t h2 = bf128_add(bf128_mul(bf128_load(r0), h0), bf128_mul_64(bf128_load(r1), h1));
  bf128_t h3 = bf128_add(bf128_mul(bf128_load(r2), h0), bf128_mul_64(bf128_load(r3), h1));

  bf128_store(h, h2);
  bf128_store(tmp, h3);
  memcpy(h + BF128_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF128_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_128(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell) {
  vole_hash_128_with_degree(h, sd, x, ell, 3);
}
static void vole_hash_160_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x,
                                       unsigned int ell, unsigned int degree) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF160_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF160_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF160_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF160_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF160_NUM_BYTES;
  const unsigned int lambda_bits = BF160_NUM_BYTES * 8;
  const unsigned int first_part_bits = ell + (degree - 1) * lambda_bits;
  const uint8_t* x1 = x + first_part_bits / 8;
  const unsigned int length_lambda = (first_part_bits + lambda_bits - 1) / lambda_bits;

  uint8_t tmp[BF160_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF160_NUM_BYTES,
         first_part_bits % lambda_bits == 0 ? BF160_NUM_BYTES : (first_part_bits % lambda_bits) / 8);
  bf160_t h0 = bf160_load(tmp);

  const bf160_t b_s = bf160_load(s);
  bf160_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf160_mul(running_s, b_s)) {
    h0 = bf160_add(h0, bf160_mul(running_s, bf160_load(x + (length_lambda - 1 - i) * BF160_NUM_BYTES)));
  }

  bf64_t h1 = compute_h1(t, x, lambda_bits, first_part_bits);
  bf160_t h2 = bf160_add(bf160_mul(bf160_load(r0), h0), bf160_mul_64(bf160_load(r1), h1));
  bf160_t h3 = bf160_add(bf160_mul(bf160_load(r2), h0), bf160_mul_64(bf160_load(r3), h1));

  bf160_store(h, h2);
  bf160_store(tmp, h3);
  memcpy(h + BF160_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF160_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_160(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell) {
  vole_hash_160_with_degree(h, sd, x, ell, 3);
}
static void vole_hash_192_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x,
                                       unsigned int ell, unsigned int degree) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF192_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF192_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF192_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF192_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF192_NUM_BYTES;
  const unsigned int lambda_bits = BF192_NUM_BYTES * 8;
  const unsigned int first_part_bits = ell + (degree - 1) * lambda_bits;
  const uint8_t* x1 = x + first_part_bits / 8;
  const unsigned int length_lambda = (first_part_bits + lambda_bits - 1) / lambda_bits;

  uint8_t tmp[BF192_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF192_NUM_BYTES,
         first_part_bits % lambda_bits == 0 ? BF192_NUM_BYTES : (first_part_bits % lambda_bits) / 8);
  bf192_t h0 = bf192_load(tmp);

  const bf192_t b_s = bf192_load(s);
  bf192_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf192_mul(running_s, b_s)) {
    h0 = bf192_add(h0, bf192_mul(running_s, bf192_load(x + (length_lambda - 1 - i) * BF192_NUM_BYTES)));
  }

  bf64_t h1 = compute_h1(t, x, lambda_bits, first_part_bits);
  bf192_t h2 = bf192_add(bf192_mul(bf192_load(r0), h0), bf192_mul_64(bf192_load(r1), h1));
  bf192_t h3 = bf192_add(bf192_mul(bf192_load(r2), h0), bf192_mul_64(bf192_load(r3), h1));

  bf192_store(h, h2);
  bf192_store(tmp, h3);
  memcpy(h + BF192_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF192_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_192(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell) {
  vole_hash_192_with_degree(h, sd, x, ell, 3);
}
static void vole_hash_256_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x,
                                       unsigned int ell, unsigned int degree) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF256_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF256_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF256_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF256_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF256_NUM_BYTES;
  const unsigned int lambda_bits = BF256_NUM_BYTES * 8;
  const unsigned int first_part_bits = ell + (degree - 1) * lambda_bits;
  const uint8_t* x1 = x + first_part_bits / 8;
  const unsigned int length_lambda = (first_part_bits + lambda_bits - 1) / lambda_bits;

  uint8_t tmp[BF256_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF256_NUM_BYTES,
         first_part_bits % lambda_bits == 0 ? BF256_NUM_BYTES : (first_part_bits % lambda_bits) / 8);
  bf256_t h0 = bf256_load(tmp);

  const bf256_t b_s = bf256_load(s);
  bf256_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf256_mul(running_s, b_s)) {
    h0 = bf256_add(h0, bf256_mul(running_s, bf256_load(x + (length_lambda - 1 - i) * BF256_NUM_BYTES)));
  }

  bf64_t h1 = compute_h1(t, x, lambda_bits, first_part_bits);
  bf256_t h2 = bf256_add(bf256_mul(bf256_load(r0), h0), bf256_mul_64(bf256_load(r1), h1));
  bf256_t h3 = bf256_add(bf256_mul(bf256_load(r2), h0), bf256_mul_64(bf256_load(r3), h1));

  bf256_store(h, h2);
  bf256_store(tmp, h3);
  memcpy(h + BF256_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF256_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_256(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell) {
  vole_hash_256_with_degree(h, sd, x, ell, 3);
}
static void vole_hash_384_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x,
                                       unsigned int ell, unsigned int degree) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF384_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF384_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF384_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF384_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF384_NUM_BYTES;
  const unsigned int lambda_bits = BF384_NUM_BYTES * 8;
  const unsigned int first_part_bits = ell + (degree - 1) * lambda_bits;
  const uint8_t* x1 = x + first_part_bits / 8;
  const unsigned int length_lambda = (first_part_bits + lambda_bits - 1) / lambda_bits;

  uint8_t tmp[BF384_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF384_NUM_BYTES,
         first_part_bits % lambda_bits == 0 ? BF384_NUM_BYTES : (first_part_bits % lambda_bits) / 8);
  bf384_t h0 = bf384_load(tmp);

  const bf384_t b_s = bf384_load(s);
  bf384_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf384_mul(running_s, b_s)) {
    h0 = bf384_add(h0, bf384_mul(running_s, bf384_load(x + (length_lambda - 1 - i) * BF384_NUM_BYTES)));
  }

  bf64_t h1 = compute_h1(t, x, lambda_bits, first_part_bits);
  bf384_t h2 = bf384_add(bf384_mul(bf384_load(r0), h0), bf384_mul_64_compat(bf384_load(r1), h1));
  bf384_t h3 = bf384_add(bf384_mul(bf384_load(r2), h0), bf384_mul_64_compat(bf384_load(r3), h1));

  bf384_store(h, h2);
  bf384_store(tmp, h3);
  memcpy(h + BF384_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF384_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_384(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell) {
  vole_hash_384_with_degree(h, sd, x, ell, 3);
}
static void vole_hash_512_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x,
                                       unsigned int ell, unsigned int degree) {
  const uint8_t* r0 = sd;
  const uint8_t* r1 = sd + 1 * BF512_NUM_BYTES;
  const uint8_t* r2 = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* r3 = sd + 3 * BF512_NUM_BYTES;
  const uint8_t* s  = sd + 4 * BF512_NUM_BYTES;
  const uint8_t* t  = sd + 5 * BF512_NUM_BYTES;
  const unsigned int lambda_bits = BF512_NUM_BYTES * 8;
  const unsigned int first_part_bits = ell + (degree - 1) * lambda_bits;
  const uint8_t* x1 = x + first_part_bits / 8;
  const unsigned int length_lambda = (first_part_bits + lambda_bits - 1) / lambda_bits;

  uint8_t tmp[BF512_NUM_BYTES] = {0};
  memcpy(tmp, x + (length_lambda - 1) * BF512_NUM_BYTES,
         first_part_bits % lambda_bits == 0 ? BF512_NUM_BYTES : (first_part_bits % lambda_bits) / 8);
  bf512_t h0 = bf512_load(tmp);

  const bf512_t b_s = bf512_load(s);
  bf512_t running_s = b_s;
  for (unsigned int i = 1; i != length_lambda; ++i, running_s = bf512_mul(running_s, b_s)) {
    h0 = bf512_add(h0, bf512_mul(running_s, bf512_load(x + (length_lambda - 1 - i) * BF512_NUM_BYTES)));
  }

  bf64_t h1 = compute_h1(t, x, lambda_bits, first_part_bits);
  bf512_t h2 = bf512_add(bf512_mul(bf512_load(r0), h0), bf512_mul_64_compat(bf512_load(r1), h1));
  bf512_t h3 = bf512_add(bf512_mul(bf512_load(r2), h0), bf512_mul_64_compat(bf512_load(r3), h1));

  bf512_store(h, h2);
  bf512_store(tmp, h3);
  memcpy(h + BF512_NUM_BYTES, tmp, UNIVERSAL_HASH_B);
  xor_u8_array(h, x1, h, BF512_NUM_BYTES + UNIVERSAL_HASH_B);
}

void vole_hash_512(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell) {
  vole_hash_512_with_degree(h, sd, x, ell, 3);
}
void vole_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell, uint32_t lambda) {
  vole_hash_with_degree(h, sd, x, ell, lambda, 3);
}

void vole_hash_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell,
                           uint32_t lambda, unsigned int degree) {
  switch (lambda) {
  case 512:
    vole_hash_512_with_degree(h, sd, x, ell, degree);
    break;
  case 384:
    vole_hash_384_with_degree(h, sd, x, ell, degree);
    break;
  case 256:
    vole_hash_256_with_degree(h, sd, x, ell, degree);
    break;
  case 192:
    vole_hash_192_with_degree(h, sd, x, ell, degree);
    break;
  case 160:
    vole_hash_160_with_degree(h, sd, x, ell, degree);
    break;
  default:
    vole_hash_128_with_degree(h, sd, x, ell, degree);
    break;
  }
}

void zk_hash_128_init(zk_hash_128_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF128_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF128_NUM_BYTES;

  ctx->h0 = bf128_zero();
  ctx->h1 = bf128_zero();
  ctx->s  = bf128_load(s);
  ctx->t  = bf64_load(t);
  ctx->sd = sd;
}

void zk_hash_128_update(zk_hash_128_ctx* ctx, bf128_t v) {
  ctx->h0 = bf128_add(bf128_mul(ctx->h0, ctx->s), v);
  ctx->h1 = bf128_add(bf128_mul_64(ctx->h1, ctx->t), v);
}

void zk_hash_128_finalize(uint8_t* h, zk_hash_128_ctx* ctx, bf128_t x1) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF128_NUM_BYTES;

  bf128_store(h, bf128_add(bf128_add(bf128_mul(bf128_load(r0), ctx->h0),
                                     bf128_mul(bf128_load(r1), ctx->h1)),
                           x1));
}

void zk_hash_128_2_init(zk_hash_128_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF128_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF128_NUM_BYTES;

  ctx->h0[0] = bf128_zero();
  ctx->h0[1] = bf128_zero();
  ctx->h1[0] = bf128_zero();
  ctx->h1[1] = bf128_zero();
  ctx->s     = bf128_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_128_2_update(zk_hash_128_2_ctx* ctx, bf128_t v_0, bf128_t v_1) {
  ctx->h0[0] = bf128_add(bf128_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf128_add(bf128_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf128_add(bf128_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf128_add(bf128_mul_64(ctx->h1[1], ctx->t), v_1);
}

void zk_hash_128_2_raise_and_update(zk_hash_128_2_ctx* ctx, bf128_t v_1) {
  zk_hash_128_2_update(ctx, bf128_zero(), v_1);
}

void zk_hash_128_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_128_2_ctx* ctx, bf128_t x1_0,
                            bf128_t x1_1) {
  const bf128_t r0 = bf128_load(ctx->sd);
  const bf128_t r1 = bf128_load(ctx->sd + BF128_NUM_BYTES);

  bf128_store(h_0,
              bf128_add(bf128_add(bf128_mul(r0, ctx->h0[0]), bf128_mul(r1, ctx->h1[0])), x1_0));
  bf128_store(h_1,
              bf128_add(bf128_add(bf128_mul(r0, ctx->h0[1]), bf128_mul(r1, ctx->h1[1])), x1_1));
}

void zk_hash_128_3_init(zk_hash_128_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF128_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF128_NUM_BYTES;

  ctx->h0[0] = bf128_zero();
  ctx->h0[1] = bf128_zero();
  ctx->h0[2] = bf128_zero();
  ctx->h1[0] = bf128_zero();
  ctx->h1[1] = bf128_zero();
  ctx->h1[2] = bf128_zero();
  ctx->s     = bf128_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_128_3_update(zk_hash_128_3_ctx* ctx, bf128_t v_0, bf128_t v_1, bf128_t v_2) {
  ctx->h0[0] = bf128_add(bf128_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf128_add(bf128_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf128_add(bf128_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf128_add(bf128_mul_64(ctx->h1[1], ctx->t), v_1);
  ctx->h0[2] = bf128_add(bf128_mul(ctx->h0[2], ctx->s), v_2);
  ctx->h1[2] = bf128_add(bf128_mul_64(ctx->h1[2], ctx->t), v_2);
}

void zk_hash_128_3_raise_and_update(zk_hash_128_3_ctx* ctx, bf128_t v_1, bf128_t v_2) {
  zk_hash_128_3_update(ctx, bf128_zero(), v_1, v_2);
}

void zk_hash_128_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_128_3_ctx* ctx,
                            bf128_t x1_0, bf128_t x1_1, bf128_t x1_2) {
  const bf128_t r0 = bf128_load(ctx->sd);
  const bf128_t r1 = bf128_load(ctx->sd + BF128_NUM_BYTES);

  bf128_store(h_0,
              bf128_add(bf128_add(bf128_mul(r0, ctx->h0[0]), bf128_mul(r1, ctx->h1[0])), x1_0));
  bf128_store(h_1,
              bf128_add(bf128_add(bf128_mul(r0, ctx->h0[1]), bf128_mul(r1, ctx->h1[1])), x1_1));
  bf128_store(h_2,
              bf128_add(bf128_add(bf128_mul(r0, ctx->h0[2]), bf128_mul(r1, ctx->h1[2])), x1_2));
}

void zk_hash_160_init(zk_hash_160_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF160_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF160_NUM_BYTES;

  ctx->h0 = bf160_zero();
  ctx->h1 = bf160_zero();
  ctx->s  = bf160_load(s);
  ctx->t  = bf64_load(t);
  ctx->sd = sd;
}

void zk_hash_160_update(zk_hash_160_ctx* ctx, bf160_t v) {
  ctx->h0 = bf160_add(bf160_mul(ctx->h0, ctx->s), v);
  ctx->h1 = bf160_add(bf160_mul_64(ctx->h1, ctx->t), v);
}

void zk_hash_160_finalize(uint8_t* h, zk_hash_160_ctx* ctx, bf160_t x1) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF160_NUM_BYTES;

  bf160_t ret = bf160_add(bf160_add(bf160_mul(bf160_load(r0), ctx->h0),
                                    bf160_mul(bf160_load(r1), ctx->h1)),
                          x1);
  bf160_store(h, ret);
}

void zk_hash_160_2_init(zk_hash_160_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF160_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF160_NUM_BYTES;

  ctx->h0[0] = bf160_zero();
  ctx->h0[1] = bf160_zero();
  ctx->h1[0] = bf160_zero();
  ctx->h1[1] = bf160_zero();
  ctx->s     = bf160_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_160_2_update(zk_hash_160_2_ctx* ctx, bf160_t v_0, bf160_t v_1) {
  ctx->h0[0] = bf160_add(bf160_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf160_add(bf160_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf160_add(bf160_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf160_add(bf160_mul_64(ctx->h1[1], ctx->t), v_1);
}

void zk_hash_160_2_raise_and_update(zk_hash_160_2_ctx* ctx, bf160_t v_1) {
  zk_hash_160_2_update(ctx, bf160_zero(), v_1);
}

void zk_hash_160_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_160_2_ctx* ctx, bf160_t x1_0,
                            bf160_t x1_1) {
  const bf160_t r0 = bf160_load(ctx->sd);
  const bf160_t r1 = bf160_load(ctx->sd + BF160_NUM_BYTES);

  bf160_store(h_0,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[0]), bf160_mul(r1, ctx->h1[0])), x1_0));
  bf160_store(h_1,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[1]), bf160_mul(r1, ctx->h1[1])), x1_1));
}

void zk_hash_160_3_init(zk_hash_160_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF160_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF160_NUM_BYTES;

  ctx->h0[0] = bf160_zero();
  ctx->h0[1] = bf160_zero();
  ctx->h0[2] = bf160_zero();
  ctx->h1[0] = bf160_zero();
  ctx->h1[1] = bf160_zero();
  ctx->h1[2] = bf160_zero();
  ctx->s     = bf160_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_160_3_update(zk_hash_160_3_ctx* ctx, bf160_t v_0, bf160_t v_1, bf160_t v_2) {
  ctx->h0[0] = bf160_add(bf160_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf160_add(bf160_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf160_add(bf160_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf160_add(bf160_mul_64(ctx->h1[1], ctx->t), v_1);
  ctx->h0[2] = bf160_add(bf160_mul(ctx->h0[2], ctx->s), v_2);
  ctx->h1[2] = bf160_add(bf160_mul_64(ctx->h1[2], ctx->t), v_2);
}

void zk_hash_160_3_raise_and_update(zk_hash_160_3_ctx* ctx, bf160_t v_1, bf160_t v_2) {
  zk_hash_160_3_update(ctx, bf160_zero(), v_1, v_2);
}

void zk_hash_160_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_160_3_ctx* ctx,
                            bf160_t x1_0, bf160_t x1_1, bf160_t x1_2) {
  const bf160_t r0 = bf160_load(ctx->sd);
  const bf160_t r1 = bf160_load(ctx->sd + BF160_NUM_BYTES);

  bf160_store(h_0,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[0]), bf160_mul(r1, ctx->h1[0])), x1_0));
  bf160_store(h_1,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[1]), bf160_mul(r1, ctx->h1[1])), x1_1));
  bf160_store(h_2,
              bf160_add(bf160_add(bf160_mul(r0, ctx->h0[2]), bf160_mul(r1, ctx->h1[2])), x1_2));
}

void zk_hash_192_init(zk_hash_192_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF192_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF192_NUM_BYTES;

  ctx->h0 = bf192_zero();
  ctx->h1 = bf192_zero();
  ctx->s  = bf192_load(s);
  ctx->t  = bf64_load(t);
  ctx->sd = sd;
}

void zk_hash_192_update(zk_hash_192_ctx* ctx, bf192_t v) {
  ctx->h0 = bf192_add(bf192_mul(ctx->h0, ctx->s), v);
  ctx->h1 = bf192_add(bf192_mul_64(ctx->h1, ctx->t), v);
}

void zk_hash_192_finalize(uint8_t* h, zk_hash_192_ctx* ctx, bf192_t x1) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF192_NUM_BYTES;

  bf192_store(h, bf192_add(bf192_add(bf192_mul(bf192_load(r0), ctx->h0),
                                     bf192_mul(bf192_load(r1), ctx->h1)),
                           x1));
}

void zk_hash_192_2_init(zk_hash_192_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF192_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF192_NUM_BYTES;

  ctx->h0[0] = bf192_zero();
  ctx->h0[1] = bf192_zero();
  ctx->h1[0] = bf192_zero();
  ctx->h1[1] = bf192_zero();
  ctx->s     = bf192_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_192_2_update(zk_hash_192_2_ctx* ctx, bf192_t v_0, bf192_t v_1) {
  ctx->h0[0] = bf192_add(bf192_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf192_add(bf192_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf192_add(bf192_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf192_add(bf192_mul_64(ctx->h1[1], ctx->t), v_1);
}

void zk_hash_192_2_raise_and_update(zk_hash_192_2_ctx* ctx, bf192_t v_1) {
  zk_hash_192_2_update(ctx, bf192_zero(), v_1);
}

void zk_hash_192_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_192_2_ctx* ctx, bf192_t x1_0,
                            bf192_t x1_1) {
  const bf192_t r0 = bf192_load(ctx->sd);
  const bf192_t r1 = bf192_load(ctx->sd + BF192_NUM_BYTES);

  bf192_store(h_0,
              bf192_add(bf192_add(bf192_mul(r0, ctx->h0[0]), bf192_mul(r1, ctx->h1[0])), x1_0));
  bf192_store(h_1,
              bf192_add(bf192_add(bf192_mul(r0, ctx->h0[1]), bf192_mul(r1, ctx->h1[1])), x1_1));
}

void zk_hash_192_3_init(zk_hash_192_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF192_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF192_NUM_BYTES;

  ctx->h0[0] = bf192_zero();
  ctx->h0[1] = bf192_zero();
  ctx->h0[2] = bf192_zero();
  ctx->h1[0] = bf192_zero();
  ctx->h1[1] = bf192_zero();
  ctx->h1[2] = bf192_zero();
  ctx->s     = bf192_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_192_3_update(zk_hash_192_3_ctx* ctx, bf192_t v_0, bf192_t v_1, bf192_t v_2) {
  ctx->h0[0] = bf192_add(bf192_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf192_add(bf192_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf192_add(bf192_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf192_add(bf192_mul_64(ctx->h1[1], ctx->t), v_1);
  ctx->h0[2] = bf192_add(bf192_mul(ctx->h0[2], ctx->s), v_2);
  ctx->h1[2] = bf192_add(bf192_mul_64(ctx->h1[2], ctx->t), v_2);
}

void zk_hash_192_3_raise_and_update(zk_hash_192_3_ctx* ctx, bf192_t v_1, bf192_t v_2) {
  zk_hash_192_3_update(ctx, bf192_zero(), v_1, v_2);
}

void zk_hash_192_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_192_3_ctx* ctx,
                            bf192_t x1_0, bf192_t x1_1, bf192_t x1_2) {
  const bf192_t r0 = bf192_load(ctx->sd);
  const bf192_t r1 = bf192_load(ctx->sd + BF192_NUM_BYTES);

  bf192_store(h_0,
              bf192_add(bf192_add(bf192_mul(r0, ctx->h0[0]), bf192_mul(r1, ctx->h1[0])), x1_0));
  bf192_store(h_1,
              bf192_add(bf192_add(bf192_mul(r0, ctx->h0[1]), bf192_mul(r1, ctx->h1[1])), x1_1));
  bf192_store(h_2,
              bf192_add(bf192_add(bf192_mul(r0, ctx->h0[2]), bf192_mul(r1, ctx->h1[2])), x1_2));
}

void zk_hash_256_init(zk_hash_256_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF256_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF256_NUM_BYTES;

  ctx->h0 = bf256_zero();
  ctx->h1 = bf256_zero();
  ctx->s  = bf256_load(s);
  ctx->t  = bf64_load(t);
  ctx->sd = sd;
}

void zk_hash_256_update(zk_hash_256_ctx* ctx, bf256_t v) {
  ctx->h0 = bf256_add(bf256_mul(ctx->h0, ctx->s), v);
  ctx->h1 = bf256_add(bf256_mul_64(ctx->h1, ctx->t), v);
}

void zk_hash_256_finalize(uint8_t* h, zk_hash_256_ctx* ctx, bf256_t x1) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF256_NUM_BYTES;

  bf256_store(h, bf256_add(bf256_add(bf256_mul(bf256_load(r0), ctx->h0),
                                     bf256_mul(bf256_load(r1), ctx->h1)),
                           x1));
}

void zk_hash_256_2_init(zk_hash_256_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF256_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF256_NUM_BYTES;

  ctx->h0[0] = bf256_zero();
  ctx->h0[1] = bf256_zero();
  ctx->h1[0] = bf256_zero();
  ctx->h1[1] = bf256_zero();
  ctx->s     = bf256_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_256_2_update(zk_hash_256_2_ctx* ctx, bf256_t v_0, bf256_t v_1) {
  ctx->h0[0] = bf256_add(bf256_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf256_add(bf256_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf256_add(bf256_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf256_add(bf256_mul_64(ctx->h1[1], ctx->t), v_1);
}

void zk_hash_256_2_raise_and_update(zk_hash_256_2_ctx* ctx, bf256_t v_1) {
  zk_hash_256_2_update(ctx, bf256_zero(), v_1);
}

void zk_hash_256_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_256_2_ctx* ctx, bf256_t x1_0,
                            bf256_t x1_1) {
  const bf256_t r0 = bf256_load(ctx->sd);
  const bf256_t r1 = bf256_load(ctx->sd + BF256_NUM_BYTES);

  bf256_store(h_0,
              bf256_add(bf256_add(bf256_mul(r0, ctx->h0[0]), bf256_mul(r1, ctx->h1[0])), x1_0));
  bf256_store(h_1,
              bf256_add(bf256_add(bf256_mul(r0, ctx->h0[1]), bf256_mul(r1, ctx->h1[1])), x1_1));
}

void zk_hash_256_3_init(zk_hash_256_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF256_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF256_NUM_BYTES;

  ctx->h0[0] = bf256_zero();
  ctx->h0[1] = bf256_zero();
  ctx->h0[2] = bf256_zero();
  ctx->h1[0] = bf256_zero();
  ctx->h1[1] = bf256_zero();
  ctx->h1[2] = bf256_zero();
  ctx->s     = bf256_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_256_3_update(zk_hash_256_3_ctx* ctx, bf256_t v_0, bf256_t v_1, bf256_t v_2) {
  ctx->h0[0] = bf256_add(bf256_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf256_add(bf256_mul_64(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf256_add(bf256_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf256_add(bf256_mul_64(ctx->h1[1], ctx->t), v_1);
  ctx->h0[2] = bf256_add(bf256_mul(ctx->h0[2], ctx->s), v_2);
  ctx->h1[2] = bf256_add(bf256_mul_64(ctx->h1[2], ctx->t), v_2);
}

void zk_hash_256_3_raise_and_update(zk_hash_256_3_ctx* ctx, bf256_t v_1, bf256_t v_2) {
  zk_hash_256_3_update(ctx, bf256_zero(), v_1, v_2);
}

void zk_hash_256_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_256_3_ctx* ctx,
                            bf256_t x1_0, bf256_t x1_1, bf256_t x1_2) {
  const bf256_t r0 = bf256_load(ctx->sd);
  const bf256_t r1 = bf256_load(ctx->sd + BF256_NUM_BYTES);

  bf256_store(h_0,
              bf256_add(bf256_add(bf256_mul(r0, ctx->h0[0]), bf256_mul(r1, ctx->h1[0])), x1_0));
  bf256_store(h_1,
              bf256_add(bf256_add(bf256_mul(r0, ctx->h0[1]), bf256_mul(r1, ctx->h1[1])), x1_1));
  bf256_store(h_2,
              bf256_add(bf256_add(bf256_mul(r0, ctx->h0[2]), bf256_mul(r1, ctx->h1[2])), x1_2));
}

void zk_hash_384_init(zk_hash_384_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF384_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF384_NUM_BYTES;

  ctx->h0 = bf384_zero();
  ctx->h1 = bf384_zero();
  ctx->s  = bf384_load(s);
  ctx->t  = bf64_load(t);
  ctx->sd = sd;
}

void zk_hash_384_update(zk_hash_384_ctx* ctx, bf384_t v) {
  ctx->h0 = bf384_add(bf384_mul(ctx->h0, ctx->s), v);
  ctx->h1 = bf384_add(bf384_mul_64_compat(ctx->h1, ctx->t), v);
}

void zk_hash_384_finalize(uint8_t* h, zk_hash_384_ctx* ctx, bf384_t x1) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF384_NUM_BYTES;

  bf384_store(h, bf384_add(bf384_add(bf384_mul(bf384_load(r0), ctx->h0),
                                     bf384_mul(bf384_load(r1), ctx->h1)),
                           x1));
}

void zk_hash_384_2_init(zk_hash_384_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF384_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF384_NUM_BYTES;

  ctx->h0[0] = bf384_zero();
  ctx->h0[1] = bf384_zero();
  ctx->h1[0] = bf384_zero();
  ctx->h1[1] = bf384_zero();
  ctx->s     = bf384_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_384_2_update(zk_hash_384_2_ctx* ctx, bf384_t v_0, bf384_t v_1) {
  ctx->h0[0] = bf384_add(bf384_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf384_add(bf384_mul_64_compat(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf384_add(bf384_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf384_add(bf384_mul_64_compat(ctx->h1[1], ctx->t), v_1);
}

void zk_hash_384_2_raise_and_update(zk_hash_384_2_ctx* ctx, bf384_t v_1) {
  zk_hash_384_2_update(ctx, bf384_zero(), v_1);
}

void zk_hash_384_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_384_2_ctx* ctx, bf384_t x1_0,
                            bf384_t x1_1) {
  const bf384_t r0 = bf384_load(ctx->sd);
  const bf384_t r1 = bf384_load(ctx->sd + BF384_NUM_BYTES);

  bf384_store(h_0,
              bf384_add(bf384_add(bf384_mul(r0, ctx->h0[0]), bf384_mul(r1, ctx->h1[0])), x1_0));
  bf384_store(h_1,
              bf384_add(bf384_add(bf384_mul(r0, ctx->h0[1]), bf384_mul(r1, ctx->h1[1])), x1_1));
}

void zk_hash_384_3_init(zk_hash_384_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF384_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF384_NUM_BYTES;

  ctx->h0[0] = bf384_zero();
  ctx->h0[1] = bf384_zero();
  ctx->h0[2] = bf384_zero();
  ctx->h1[0] = bf384_zero();
  ctx->h1[1] = bf384_zero();
  ctx->h1[2] = bf384_zero();
  ctx->s     = bf384_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_384_3_update(zk_hash_384_3_ctx* ctx, bf384_t v_0, bf384_t v_1, bf384_t v_2) {
  ctx->h0[0] = bf384_add(bf384_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf384_add(bf384_mul_64_compat(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf384_add(bf384_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf384_add(bf384_mul_64_compat(ctx->h1[1], ctx->t), v_1);
  ctx->h0[2] = bf384_add(bf384_mul(ctx->h0[2], ctx->s), v_2);
  ctx->h1[2] = bf384_add(bf384_mul_64_compat(ctx->h1[2], ctx->t), v_2);
}

void zk_hash_384_3_raise_and_update(zk_hash_384_3_ctx* ctx, bf384_t v_1, bf384_t v_2) {
  zk_hash_384_3_update(ctx, bf384_zero(), v_1, v_2);
}

void zk_hash_384_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_384_3_ctx* ctx,
                            bf384_t x1_0, bf384_t x1_1, bf384_t x1_2) {
  const bf384_t r0 = bf384_load(ctx->sd);
  const bf384_t r1 = bf384_load(ctx->sd + BF384_NUM_BYTES);

  bf384_store(h_0,
              bf384_add(bf384_add(bf384_mul(r0, ctx->h0[0]), bf384_mul(r1, ctx->h1[0])), x1_0));
  bf384_store(h_1,
              bf384_add(bf384_add(bf384_mul(r0, ctx->h0[1]), bf384_mul(r1, ctx->h1[1])), x1_1));
  bf384_store(h_2,
              bf384_add(bf384_add(bf384_mul(r0, ctx->h0[2]), bf384_mul(r1, ctx->h1[2])), x1_2));
}

void zk_hash_512_init(zk_hash_512_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF512_NUM_BYTES;

  ctx->h0 = bf512_zero();
  ctx->h1 = bf512_zero();
  ctx->s  = bf512_load(s);
  ctx->t  = bf64_load(t);
  ctx->sd = sd;
}

void zk_hash_512_update(zk_hash_512_ctx* ctx, bf512_t v) {
  ctx->h0 = bf512_add(bf512_mul(ctx->h0, ctx->s), v);
  ctx->h1 = bf512_add(bf512_mul_64_compat(ctx->h1, ctx->t), v);
}

void zk_hash_512_finalize(uint8_t* h, zk_hash_512_ctx* ctx, bf512_t x1) {
  const uint8_t* r0 = ctx->sd;
  const uint8_t* r1 = ctx->sd + BF512_NUM_BYTES;

  bf512_store(h, bf512_add(bf512_add(bf512_mul(bf512_load(r0), ctx->h0),
                                     bf512_mul(bf512_load(r1), ctx->h1)),
                           x1));
}

void zk_hash_512_2_init(zk_hash_512_2_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF512_NUM_BYTES;

  ctx->h0[0] = bf512_zero();
  ctx->h0[1] = bf512_zero();
  ctx->h1[0] = bf512_zero();
  ctx->h1[1] = bf512_zero();
  ctx->s     = bf512_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_512_2_update(zk_hash_512_2_ctx* ctx, bf512_t v_0, bf512_t v_1) {
  ctx->h0[0] = bf512_add(bf512_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf512_add(bf512_mul_64_compat(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf512_add(bf512_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf512_add(bf512_mul_64_compat(ctx->h1[1], ctx->t), v_1);
}

void zk_hash_512_2_raise_and_update(zk_hash_512_2_ctx* ctx, bf512_t v_1) {
  zk_hash_512_2_update(ctx, bf512_zero(), v_1);
}

void zk_hash_512_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_512_2_ctx* ctx, bf512_t x1_0,
                            bf512_t x1_1) {
  const bf512_t r0 = bf512_load(ctx->sd);
  const bf512_t r1 = bf512_load(ctx->sd + BF512_NUM_BYTES);

  bf512_store(h_0,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[0]), bf512_mul(r1, ctx->h1[0])), x1_0));
  bf512_store(h_1,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[1]), bf512_mul(r1, ctx->h1[1])), x1_1));
}

void zk_hash_512_3_init(zk_hash_512_3_ctx* ctx, const uint8_t* sd) {
  const uint8_t* s = sd + 2 * BF512_NUM_BYTES;
  const uint8_t* t = sd + 3 * BF512_NUM_BYTES;

  ctx->h0[0] = bf512_zero();
  ctx->h0[1] = bf512_zero();
  ctx->h0[2] = bf512_zero();
  ctx->h1[0] = bf512_zero();
  ctx->h1[1] = bf512_zero();
  ctx->h1[2] = bf512_zero();
  ctx->s     = bf512_load(s);
  ctx->t     = bf64_load(t);
  ctx->sd    = sd;
}

void zk_hash_512_3_update(zk_hash_512_3_ctx* ctx, bf512_t v_0, bf512_t v_1, bf512_t v_2) {
  ctx->h0[0] = bf512_add(bf512_mul(ctx->h0[0], ctx->s), v_0);
  ctx->h1[0] = bf512_add(bf512_mul_64_compat(ctx->h1[0], ctx->t), v_0);
  ctx->h0[1] = bf512_add(bf512_mul(ctx->h0[1], ctx->s), v_1);
  ctx->h1[1] = bf512_add(bf512_mul_64_compat(ctx->h1[1], ctx->t), v_1);
  ctx->h0[2] = bf512_add(bf512_mul(ctx->h0[2], ctx->s), v_2);
  ctx->h1[2] = bf512_add(bf512_mul_64_compat(ctx->h1[2], ctx->t), v_2);
}

void zk_hash_512_3_raise_and_update(zk_hash_512_3_ctx* ctx, bf512_t v_1, bf512_t v_2) {
  zk_hash_512_3_update(ctx, bf512_zero(), v_1, v_2);
}

void zk_hash_512_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_512_3_ctx* ctx,
                            bf512_t x1_0, bf512_t x1_1, bf512_t x1_2) {
  const bf512_t r0 = bf512_load(ctx->sd);
  const bf512_t r1 = bf512_load(ctx->sd + BF512_NUM_BYTES);

  bf512_store(h_0,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[0]), bf512_mul(r1, ctx->h1[0])), x1_0));
  bf512_store(h_1,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[1]), bf512_mul(r1, ctx->h1[1])), x1_1));
  bf512_store(h_2,
              bf512_add(bf512_add(bf512_mul(r0, ctx->h0[2]), bf512_mul(r1, ctx->h1[2])), x1_2));
}

#if defined(SIG_TESTS)
void zk_hash_128(uint8_t* h, const uint8_t* sd, const bf128_t* x, unsigned int ell) {
  zk_hash_128_ctx ctx;
  zk_hash_128_init(&ctx, sd);
  for (unsigned int i = 0; i != ell; ++i) {
    zk_hash_128_update(&ctx, x[i]);
  }
  zk_hash_128_finalize(h, &ctx, x[ell]);
}

void zk_hash_160(uint8_t* h, const uint8_t* sd, const bf160_t* x, unsigned int ell) {
  zk_hash_160_ctx ctx;
  zk_hash_160_init(&ctx, sd);
  for (unsigned int i = 0; i != ell; ++i) {
    zk_hash_160_update(&ctx, x[i]);
  }
  zk_hash_160_finalize(h, &ctx, x[ell]);
}

void zk_hash_192(uint8_t* h, const uint8_t* sd, const bf192_t* x, unsigned int ell) {
  zk_hash_192_ctx ctx;
  zk_hash_192_init(&ctx, sd);
  for (unsigned int i = 0; i != ell; ++i) {
    zk_hash_192_update(&ctx, x[i]);
  }
  zk_hash_192_finalize(h, &ctx, x[ell]);
}

void zk_hash_256(uint8_t* h, const uint8_t* sd, const bf256_t* x, unsigned int ell) {
  zk_hash_256_ctx ctx;
  zk_hash_256_init(&ctx, sd);
  for (unsigned int i = 0; i != ell; ++i) {
    zk_hash_256_update(&ctx, x[i]);
  }
  zk_hash_256_finalize(h, &ctx, x[ell]);
}

void zk_hash_384(uint8_t* h, const uint8_t* sd, const bf384_t* x, unsigned int ell) {
  zk_hash_384_ctx ctx;
  zk_hash_384_init(&ctx, sd);
  for (unsigned int i = 0; i != ell; ++i) {
    zk_hash_384_update(&ctx, x[i]);
  }
  zk_hash_384_finalize(h, &ctx, x[ell]);
}

void zk_hash_512(uint8_t* h, const uint8_t* sd, const bf512_t* x, unsigned int ell) {
  zk_hash_512_ctx ctx;
  zk_hash_512_init(&ctx, sd);
  for (unsigned int i = 0; i != ell; ++i) {
    zk_hash_512_update(&ctx, x[i]);
  }
  zk_hash_512_finalize(h, &ctx, x[ell]);
}
#endif

void leaf_hash_128(uint8_t* h, const uint8_t* uhash, const uint8_t* x) {
  const uint8_t* x0 = x;
  const uint8_t* x1 = x + BF128_NUM_BYTES;

  bf384_store(h, bf384_add(bf384_mul_128(bf384_load(uhash), bf128_load(x0)), bf384_load(x1)));
}

void leaf_hash_160(uint8_t* h, const uint8_t* uhash, const uint8_t* x) {
  const uint8_t* x0 = x;
  const uint8_t* x1 = x + BF160_NUM_BYTES;
  bf160_t h0 = bf160_mul(bf160_load(uhash), bf160_load(x0));
  bf160_t h1 = bf160_mul(bf160_load(uhash + BF160_NUM_BYTES), bf160_load(x0));
  bf160_t h2 = bf160_mul(bf160_load(uhash + 2 * BF160_NUM_BYTES), bf160_load(x0));
  h0 = bf160_add(h0, bf160_load(x1));
  h1 = bf160_add(h1, bf160_load(x1 + BF160_NUM_BYTES));
  h2 = bf160_add(h2, bf160_load(x1 + 2 * BF160_NUM_BYTES));
  bf160_store(h, h0);
  bf160_store(h + BF160_NUM_BYTES, h1);
  bf160_store(h + 2 * BF160_NUM_BYTES, h2);
}
void leaf_hash_192(uint8_t* h, const uint8_t* uhash, const uint8_t* x) {
  const uint8_t* x0 = x;
  const uint8_t* x1 = x + BF192_NUM_BYTES;

  bf576_store(h, bf576_add(bf576_mul_192(bf576_load(uhash), bf192_load(x0)), bf576_load(x1)));
}

void leaf_hash_256(uint8_t* h, const uint8_t* uhash, const uint8_t* x) {
  const uint8_t* x0 = x;
  const uint8_t* x1 = x + BF256_NUM_BYTES;

  bf768_store(h, bf768_add(bf768_mul_256(bf768_load(uhash), bf256_load(x0)), bf768_load(x1)));
}

void leaf_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int lambda) {
  switch (lambda) {
  case 256:
    leaf_hash_256(h, sd, x);
    break;
  case 192:
    leaf_hash_192(h, sd, x);
    break;
  case 160:
    leaf_hash_160(h, sd, x);
    break;
  default:
    leaf_hash_128(h, sd, x);
    break;
  }
}
