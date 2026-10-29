/*
 *  SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <string.h>

#include "random_oracle.h"
#include "instances.h"

static const uint8_t domain_sep_H0   = 0;
static const uint8_t domain_sep_H1   = 1;
static const uint8_t domain_sep_H2_0 = 0;
static const uint8_t domain_sep_H2_1 = 1;
static const uint8_t domain_sep_H2_2 = 2;
static const uint8_t domain_sep_H2_3 = 3;
static const uint8_t domain_sep_H3   = 9;
static const uint8_t domain_sep_H4   = 10;

static inline unsigned int ro_security_param(unsigned int security_param) {
  switch (security_param) {
  case 128:
  case 160:
  case 192:
  case 256:
  case 384:
  case 512:
    return security_param;
  default:
    assert(!"unsupported security parameter");
    return 256;
  }
}

// H_0
void H0_init(H0_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, ro_security_param(security_param));
}

void H0_update(H0_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

void H0_final(H0_context_t* ctx, uint8_t* seed, size_t seed_len, uint8_t* commitment,
              size_t commitment_len) {
  H0_final_for_squeeze(ctx);
  hash_squeeze(ctx, seed, seed_len);
  hash_squeeze(ctx, commitment, commitment_len);
  hash_clear(ctx);
}

void H0_final_for_squeeze(H0_context_t* ctx) {
  hash_update(ctx, &domain_sep_H0, sizeof(domain_sep_H0));
  hash_final(ctx);
}

void H0_squeeze(H0_context_t* H0_ctx, uint8_t* dst, size_t len) {
  hash_squeeze(H0_ctx, dst, len);
}

void H0_clear(H0_context_t* H0_ctx) {
  hash_clear(H0_ctx);
}

void H0_x4_init(H0_context_x4_t* ctx, unsigned int security_param) {
  hash_init_x4(ctx, ro_security_param(security_param));
}

void H0_x4_update(H0_context_x4_t* ctx, const uint8_t* src0, const uint8_t* src1,
                  const uint8_t* src2, const uint8_t* src3, size_t len) {
  hash_update_x4_4(ctx, src0, src1, src2, src3, len);
}

void H0_x4_final(H0_context_x4_t* ctx, uint8_t* seed0, uint8_t* seed1, uint8_t* seed2,
                 uint8_t* seed3, size_t seed_len, uint8_t* commitment0, uint8_t* commitment1,
                 uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len) {
  hash_update_x4_1(ctx, &domain_sep_H0, sizeof(domain_sep_H0));
  hash_final_x4(ctx);
  hash_squeeze_x4_4(ctx, seed0, seed1, seed2, seed3, seed_len);
  hash_squeeze_x4_4(ctx, commitment0, commitment1, commitment2, commitment3, commitment_len);
  hash_clear_x4(ctx);
}

// H_1
void H1_init(H1_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, ro_security_param(security_param));
}

void H1_update(H1_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

void H1_final(H1_context_t* ctx, uint8_t* digest, size_t len) {
  hash_update(ctx, &domain_sep_H1, sizeof(domain_sep_H1));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// H_2
void H2_init(H2_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, ro_security_param(security_param));
}

void H2_copy(H2_context_t* new_ctx, const H2_context_t* ctx) {
  hash_copy(new_ctx, ctx);
}

void H2_update(H2_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

void H2_update_u32_le(H2_context_t* ctx, uint32_t v) {
  hash_update_uint32_le(ctx, v);
}

void H2_0_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  hash_update(ctx, &domain_sep_H2_0, sizeof(domain_sep_H2_0));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

void H2_1_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  hash_update(ctx, &domain_sep_H2_1, sizeof(domain_sep_H2_1));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

void H2_2_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  hash_update(ctx, &domain_sep_H2_2, sizeof(domain_sep_H2_2));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

void H2_3_final(H2_context_t* ctx, uint8_t* digest, size_t len) {
  hash_update(ctx, &domain_sep_H2_3, sizeof(domain_sep_H2_3));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_clear(ctx);
}

// H_3
void H3_init(H3_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, ro_security_param(security_param));
}

void H3_update(H3_context_t* ctx, const uint8_t* src, size_t len) {
  hash_update(ctx, src, len);
}

void H3_final(H3_context_t* ctx, uint8_t* digest, size_t len, uint8_t* iv) {
  hash_update(ctx, &domain_sep_H3, sizeof(domain_sep_H3));
  hash_final(ctx);
  hash_squeeze(ctx, digest, len);
  hash_squeeze(ctx, iv, IV_SIZE);
  hash_clear(ctx);
}

// H_4
void H4_init(H4_context_t* ctx, unsigned int security_param) {
  hash_init(ctx, ro_security_param(security_param));
}

void H4_update(H4_context_t* ctx, const uint8_t* iv) {
  hash_update(ctx, iv, IV_SIZE);
}

void H4_final(H4_context_t* ctx, uint8_t* iv) {
  hash_update(ctx, &domain_sep_H4, sizeof(domain_sep_H4));
  hash_final(ctx);
  hash_squeeze(ctx, iv, IV_SIZE);
  hash_clear(ctx);
}
