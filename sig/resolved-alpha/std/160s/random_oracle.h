/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIG_RANDOM_ORACLE_H
#define SIG_RANDOM_ORACLE_H

#include "xof.h"
#include "macros.h"

SIG_BEGIN_C_DECL

// implementation of H_0

typedef hash_context H0_context_t;

void H0_init(H0_context_t* H0_ctx, unsigned int security_param);
void H0_update(H0_context_t* H0_ctx, const uint8_t* src, size_t len);
void H0_final(H0_context_t* H0_ctx, uint8_t* seed, size_t seed_len, uint8_t* commitment,
              size_t commitment_len);
void H0_final_for_squeeze(H0_context_t* H0_ctx);
// only for use with H0_final_for_squeeze
void H0_squeeze(H0_context_t* H0_ctx, uint8_t* dst, size_t len);
void H0_clear(H0_context_t* H0_ctx);

typedef hash_context_x4 H0_context_x4_t;

void H0_x4_init(H0_context_x4_t* H0_ctx, unsigned int security_param);
void H0_x4_update(H0_context_x4_t* H0_ctx, const uint8_t* src0, const uint8_t* src1,
                  const uint8_t* src2, const uint8_t* src3, size_t len);
void H0_x4_final(H0_context_x4_t* ctx, uint8_t* seed0, uint8_t* seed1, uint8_t* seed2,
                 uint8_t* seed3, size_t seed_len, uint8_t* commitment0, uint8_t* commitment1,
                 uint8_t* commitment2, uint8_t* commitment3, size_t commitment_len);

// implementation of H_1

typedef hash_context H1_context_t;

void H1_init(H1_context_t* H1_ctx, unsigned int security_param);
void H1_update(H1_context_t* H1_ctx, const uint8_t* src, size_t len);
void H1_final(H1_context_t* H1_ctx, uint8_t* digest, size_t len);

// implementation of H_2

typedef hash_context H2_context_t;

void H2_init(H2_context_t* ctx, unsigned int security_param);
void H2_copy(H2_context_t* new_ctx, const H2_context_t* ctx);
void H2_update(H2_context_t* ctx, const uint8_t* src, size_t len);
void H2_update_u32_le(H2_context_t* ctx, uint32_t v);
void H2_0_final(H2_context_t* ctx, uint8_t* digest, size_t len);
void H2_1_final(H2_context_t* ctx, uint8_t* digest, size_t len);
void H2_2_final(H2_context_t* ctx, uint8_t* digest, size_t len);
void H2_3_final(H2_context_t* ctx, uint8_t* digest, size_t len);

// implementation for H_3

typedef hash_context H3_context_t;

void H3_init(H3_context_t* ctx, unsigned int security_param);
void H3_update(H3_context_t* ctx, const uint8_t* src, size_t len);
void H3_final(H3_context_t* ctx, uint8_t* digest, size_t len, uint8_t* iv);

// implementation for H_4

typedef hash_context H4_context_t;

void H4_init(H4_context_t* ctx, unsigned int security_param);
void H4_update(H4_context_t* ctx, const uint8_t* pre_iv);
void H4_final(H4_context_t* ctx, uint8_t* iv);

SIG_END_C_DECL

#endif
