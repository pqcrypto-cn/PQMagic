/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIG_UNIVERSAL_HASHING_H
#define SIG_UNIVERSAL_HASHING_H

#include <stdint.h>

#include "macros.h"
#include "fields.h"

SIG_BEGIN_C_DECL

void vole_hash_128(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell);
void vole_hash_160(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell);
void vole_hash_192(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell);
void vole_hash_256(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell);
void vole_hash_384(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell);
void vole_hash_512(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell);
void vole_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell, uint32_t lambda);
void vole_hash_with_degree(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int ell,
                           uint32_t lambda, unsigned int degree);

#if defined(SIG_TESTS)
void zk_hash_128(uint8_t* h, const uint8_t* sd, const bf128_t* x, unsigned int ell);
void zk_hash_160(uint8_t* h, const uint8_t* sd, const bf160_t* x, unsigned int ell);
void zk_hash_192(uint8_t* h, const uint8_t* sd, const bf192_t* x, unsigned int ell);
void zk_hash_256(uint8_t* h, const uint8_t* sd, const bf256_t* x, unsigned int ell);
void zk_hash_384(uint8_t* h, const uint8_t* sd, const bf384_t* x, unsigned int ell);
void zk_hash_512(uint8_t* h, const uint8_t* sd, const bf512_t* x, unsigned int ell);
#endif

typedef struct {
  bf128_t h0;
  bf128_t h1;
  bf128_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_128_ctx;

void zk_hash_128_init(zk_hash_128_ctx* ctx, const uint8_t* sd);
void zk_hash_128_update(zk_hash_128_ctx* ctx, bf128_t v);
void zk_hash_128_finalize(uint8_t* h, zk_hash_128_ctx* ctx, bf128_t x1);

typedef struct {
  bf128_t h0[2];
  bf128_t h1[2];
  bf128_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_128_2_ctx;

void zk_hash_128_2_init(zk_hash_128_2_ctx* ctx, const uint8_t* sd);
void zk_hash_128_2_update(zk_hash_128_2_ctx* ctx, bf128_t v_0, bf128_t v_1);
void zk_hash_128_2_raise_and_update(zk_hash_128_2_ctx* ctx, bf128_t v_1);
void zk_hash_128_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_128_2_ctx* ctx, bf128_t x1_0,
                            bf128_t x1_1);

typedef struct {
  bf128_t h0[3];
  bf128_t h1[3];
  bf128_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_128_3_ctx;

void zk_hash_128_3_init(zk_hash_128_3_ctx* ctx, const uint8_t* sd);
void zk_hash_128_3_update(zk_hash_128_3_ctx* ctx, bf128_t v_0, bf128_t v_1, bf128_t v_2);
void zk_hash_128_3_raise_and_update(zk_hash_128_3_ctx* ctx, bf128_t v_1, bf128_t v_2);
void zk_hash_128_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_128_3_ctx* ctx,
                            bf128_t x1_0, bf128_t x1_1, bf128_t x1_2);

typedef struct {
  bf160_t h0;
  bf160_t h1;
  bf160_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_160_ctx;

void zk_hash_160_init(zk_hash_160_ctx* ctx, const uint8_t* sd);
void zk_hash_160_update(zk_hash_160_ctx* ctx, bf160_t v);
void zk_hash_160_finalize(uint8_t* h, zk_hash_160_ctx* ctx, bf160_t x1);

typedef struct {
  bf160_t h0[2];
  bf160_t h1[2];
  bf160_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_160_2_ctx;

void zk_hash_160_2_init(zk_hash_160_2_ctx* ctx, const uint8_t* sd);
void zk_hash_160_2_update(zk_hash_160_2_ctx* ctx, bf160_t v_0, bf160_t v_1);
void zk_hash_160_2_raise_and_update(zk_hash_160_2_ctx* ctx, bf160_t v_1);
void zk_hash_160_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_160_2_ctx* ctx, bf160_t x1_0,
                            bf160_t x1_1);

typedef struct {
  bf160_t h0[3];
  bf160_t h1[3];
  bf160_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_160_3_ctx;

void zk_hash_160_3_init(zk_hash_160_3_ctx* ctx, const uint8_t* sd);
void zk_hash_160_3_update(zk_hash_160_3_ctx* ctx, bf160_t v_0, bf160_t v_1, bf160_t v_2);
void zk_hash_160_3_raise_and_update(zk_hash_160_3_ctx* ctx, bf160_t v_1, bf160_t v_2);
void zk_hash_160_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_160_3_ctx* ctx,
                            bf160_t x1_0, bf160_t x1_1, bf160_t x1_2);

typedef struct {
  bf192_t h0;
  bf192_t h1;
  bf192_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_192_ctx;

void zk_hash_192_init(zk_hash_192_ctx* ctx, const uint8_t* sd);
void zk_hash_192_update(zk_hash_192_ctx* ctx, bf192_t v);
void zk_hash_192_finalize(uint8_t* h, zk_hash_192_ctx* ctx, bf192_t x1);

typedef struct {
  bf192_t h0[2];
  bf192_t h1[2];
  bf192_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_192_2_ctx;

void zk_hash_192_2_init(zk_hash_192_2_ctx* ctx, const uint8_t* sd);
void zk_hash_192_2_update(zk_hash_192_2_ctx* ctx, bf192_t v_0, bf192_t v_1);
void zk_hash_192_2_raise_and_update(zk_hash_192_2_ctx* ctx, bf192_t v_1);
void zk_hash_192_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_192_2_ctx* ctx, bf192_t x1_0,
                            bf192_t x1_1);

typedef struct {
  bf192_t h0[3];
  bf192_t h1[3];
  bf192_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_192_3_ctx;

void zk_hash_192_3_init(zk_hash_192_3_ctx* ctx, const uint8_t* sd);
void zk_hash_192_3_update(zk_hash_192_3_ctx* ctx, bf192_t v_0, bf192_t v_1, bf192_t v_2);
void zk_hash_192_3_raise_and_update(zk_hash_192_3_ctx* ctx, bf192_t v_1, bf192_t v_2);
void zk_hash_192_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_192_3_ctx* ctx,
                            bf192_t x1_0, bf192_t x1_1, bf192_t x1_2);

typedef struct {
  bf256_t h0;
  bf256_t h1;
  bf256_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_256_ctx;

void zk_hash_256_init(zk_hash_256_ctx* ctx, const uint8_t* sd);
void zk_hash_256_update(zk_hash_256_ctx* ctx, bf256_t v);
void zk_hash_256_finalize(uint8_t* h, zk_hash_256_ctx* ctx, bf256_t x1);

typedef struct {
  bf256_t h0[2];
  bf256_t h1[2];
  bf256_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_256_2_ctx;

void zk_hash_256_2_init(zk_hash_256_2_ctx* ctx, const uint8_t* sd);
void zk_hash_256_2_update(zk_hash_256_2_ctx* ctx, bf256_t v_0, bf256_t v_1);
void zk_hash_256_2_raise_and_update(zk_hash_256_2_ctx* ctx, bf256_t v_1);
void zk_hash_256_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_256_2_ctx* ctx, bf256_t x1_0,
                            bf256_t x1_1);

typedef struct {
  bf256_t h0[3];
  bf256_t h1[3];
  bf256_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_256_3_ctx;

void zk_hash_256_3_init(zk_hash_256_3_ctx* ctx, const uint8_t* sd);
void zk_hash_256_3_update(zk_hash_256_3_ctx* ctx, bf256_t v_0, bf256_t v_1, bf256_t v_2);
void zk_hash_256_3_raise_and_update(zk_hash_256_3_ctx* ctx, bf256_t v_1, bf256_t v_2);
void zk_hash_256_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_256_3_ctx* ctx,
                            bf256_t x1_0, bf256_t x1_1, bf256_t x1_2);

typedef struct {
  bf384_t h0;
  bf384_t h1;
  bf384_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_384_ctx;

void zk_hash_384_init(zk_hash_384_ctx* ctx, const uint8_t* sd);
void zk_hash_384_update(zk_hash_384_ctx* ctx, bf384_t v);
void zk_hash_384_finalize(uint8_t* h, zk_hash_384_ctx* ctx, bf384_t x1);

typedef struct {
  bf384_t h0[2];
  bf384_t h1[2];
  bf384_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_384_2_ctx;

void zk_hash_384_2_init(zk_hash_384_2_ctx* ctx, const uint8_t* sd);
void zk_hash_384_2_update(zk_hash_384_2_ctx* ctx, bf384_t v_0, bf384_t v_1);
void zk_hash_384_2_raise_and_update(zk_hash_384_2_ctx* ctx, bf384_t v_1);
void zk_hash_384_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_384_2_ctx* ctx, bf384_t x1_0,
                            bf384_t x1_1);

typedef struct {
  bf384_t h0[3];
  bf384_t h1[3];
  bf384_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_384_3_ctx;

void zk_hash_384_3_init(zk_hash_384_3_ctx* ctx, const uint8_t* sd);
void zk_hash_384_3_update(zk_hash_384_3_ctx* ctx, bf384_t v_0, bf384_t v_1, bf384_t v_2);
void zk_hash_384_3_raise_and_update(zk_hash_384_3_ctx* ctx, bf384_t v_1, bf384_t v_2);
void zk_hash_384_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_384_3_ctx* ctx,
                            bf384_t x1_0, bf384_t x1_1, bf384_t x1_2);

typedef struct {
  bf512_t h0;
  bf512_t h1;
  bf512_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_512_ctx;

void zk_hash_512_init(zk_hash_512_ctx* ctx, const uint8_t* sd);
void zk_hash_512_update(zk_hash_512_ctx* ctx, bf512_t v);
void zk_hash_512_finalize(uint8_t* h, zk_hash_512_ctx* ctx, bf512_t x1);

typedef struct {
  bf512_t h0[2];
  bf512_t h1[2];
  bf512_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_512_2_ctx;

void zk_hash_512_2_init(zk_hash_512_2_ctx* ctx, const uint8_t* sd);
void zk_hash_512_2_update(zk_hash_512_2_ctx* ctx, bf512_t v_0, bf512_t v_1);
void zk_hash_512_2_raise_and_update(zk_hash_512_2_ctx* ctx, bf512_t v_1);
void zk_hash_512_2_finalize(uint8_t* h_0, uint8_t* h_1, zk_hash_512_2_ctx* ctx, bf512_t x1_0,
                            bf512_t x1_1);

typedef struct {
  bf512_t h0[3];
  bf512_t h1[3];
  bf512_t s;
  bf64_t t;
  const uint8_t* sd;
} zk_hash_512_3_ctx;

void zk_hash_512_3_init(zk_hash_512_3_ctx* ctx, const uint8_t* sd);
void zk_hash_512_3_update(zk_hash_512_3_ctx* ctx, bf512_t v_0, bf512_t v_1, bf512_t v_2);
void zk_hash_512_3_raise_and_update(zk_hash_512_3_ctx* ctx, bf512_t v_1, bf512_t v_2);
void zk_hash_512_3_finalize(uint8_t* h_0, uint8_t* h_1, uint8_t* h_2, zk_hash_512_3_ctx* ctx,
                            bf512_t x1_0, bf512_t x1_1, bf512_t x1_2);

void leaf_hash_128(uint8_t* h, const uint8_t* sd, const uint8_t* x);
void leaf_hash_160(uint8_t* h, const uint8_t* sd, const uint8_t* x);
void leaf_hash_192(uint8_t* h, const uint8_t* sd, const uint8_t* x);
void leaf_hash_256(uint8_t* h, const uint8_t* sd, const uint8_t* x);
void leaf_hash(uint8_t* h, const uint8_t* sd, const uint8_t* x, unsigned int lambda);

SIG_END_C_DECL

#endif
