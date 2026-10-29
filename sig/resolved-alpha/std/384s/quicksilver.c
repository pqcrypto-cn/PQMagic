/*
 *  SPDX-License-Identifier: MIT
 */

#include "quicksilver.h"

#include "rsd.h"
#include "fields.h"
#include "universal_hashing.h"
#include "utils.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RSD_BLOCK_SIZE 6
#define RSD_PACKED_BLOCK_BITS (RSD_BLOCK_SIZE - 1)
#define RSD_SKETCH_POWERS 19

static size_t ceil_bytes(size_t bits) {
  return (bits + 7) / 8;
}

static void* qs_aligned_alloc(size_t alignment, size_t size) {
  if ((alignment & (alignment - 1)) != 0) {
    return NULL;
  }
  if (alignment < sizeof(void*)) {
    alignment = sizeof(void*);
  }

  void* raw = malloc(size + alignment - 1 + sizeof(void*));
  if (!raw) {
    return NULL;
  }

  uintptr_t start   = (uintptr_t)raw + sizeof(void*);
  uintptr_t aligned = (start + alignment - 1) & ~(uintptr_t)(alignment - 1);
  ((void**)aligned)[-1] = raw;
  return (void*)aligned;
}

static void qs_aligned_free(void* ptr) {
  if (ptr) {
    free(((void**)ptr)[-1]);
  }
}

#define PAD_TO(s, a) (((s) + (a) - 1) & ~((a) - 1))
#define FIELD_ALLOC(ALIGN, TYPE, s) qs_aligned_alloc(ALIGN, PAD_TO((s) * sizeof(TYPE), ALIGN))

#define DEFINE_RSD_QS(BITS, PFX, TYPE, ALIGN, HASH)                                               \
  static PFX##_t* column_to_row_major_##BITS(uint8_t** v, unsigned int ell) {                     \
    PFX##_t* new_v = FIELD_ALLOC(ALIGN, TYPE, ell + BITS * 2);                                    \
    assert(new_v);                                                                                \
    for (unsigned int row = 0; row != ell + BITS * 2; ++row) {                                    \
      uint8_t new_row[BITS / 8];                                                                  \
      memset(new_row, 0, sizeof(new_row));                                                        \
      for (unsigned int column = 0; column != BITS; ++column) {                                   \
        ptr_set_bit(new_row, column, ptr_get_bit(v[column], row));                                \
      }                                                                                           \
      new_v[row] = PFX##_load(new_row);                                                           \
    }                                                                                             \
    return new_v;                                                                                 \
  }                                                                                               \
                                                                                                  \
  static void init_powers_##BITS(PFX##_t powers[RSD_SKETCH_POWERS]) {                             \
    uint8_t alpha_bytes[BITS / 8];                                                                \
    memset(alpha_bytes, 0, sizeof(alpha_bytes));                                                   \
    ptr_set_bit(alpha_bytes, 1, 1);                                                               \
    const PFX##_t alpha = PFX##_load(alpha_bytes);                                                \
    powers[0] = PFX##_one();                                                                      \
    for (unsigned int i = 1; i < RSD_SKETCH_POWERS; ++i) {                                        \
      powers[i] = PFX##_mul(powers[i - 1], alpha);                                                \
    }                                                                                             \
  }                                                                                               \
                                                                                                  \
  static PFX##_t lc_value_##BITS(const uint8_t* bits, const PFX##_t powers[RSD_SKETCH_POWERS],    \
                                 const unsigned int* exps, unsigned int count) {                  \
    PFX##_t out = PFX##_zero();                                                                   \
    for (unsigned int i = 0; i < count; ++i) {                                                    \
      out = PFX##_add(out, PFX##_mul_bit(powers[exps[i]], ptr_get_bit(bits, i)));                 \
    }                                                                                             \
    return out;                                                                                   \
  }                                                                                               \
                                                                                                  \
  static PFX##_t lc_auth_##BITS(const PFX##_t* auth, const PFX##_t powers[RSD_SKETCH_POWERS],     \
                                const unsigned int* exps, unsigned int count) {                   \
    PFX##_t out = PFX##_zero();                                                                   \
    for (unsigned int i = 0; i < count; ++i) {                                                    \
      out = PFX##_add(out, PFX##_mul(auth[i], powers[exps[i]]));                                  \
    }                                                                                             \
    return out;                                                                                   \
  }                                                                                               \
                                                                                                  \
  static void decode_noise_tags_##BITS(uint8_t* e_bits, PFX##_t* e_tag, const uint8_t* w,         \
                                       const PFX##_t* w_tag, const uint8_t* matrix_b,             \
                                       const uint8_t* y, const sig_paramset_t* params) {          \
    const unsigned int n        = params->rsd_code_length;                                        \
    const unsigned int k        = params->rsd_dimension;                                          \
    const unsigned int a_bits   = n - k;                                                          \
    const unsigned int b_blocks = k / RSD_BLOCK_SIZE;                                             \
    memset(e_bits, 0, ceil_bytes(n));                                                             \
    for (unsigned int block = 0; block < b_blocks; ++block) {                                     \
      uint8_t parity = 1;                                                                         \
      PFX##_t last_tag = PFX##_zero();                                                            \
      for (unsigned int j = 0; j < RSD_PACKED_BLOCK_BITS; ++j) {                                  \
        const unsigned int w_idx = block * RSD_PACKED_BLOCK_BITS + j;                             \
        const uint8_t bit        = ptr_get_bit(w, w_idx);                                         \
        ptr_set_bit(e_bits, a_bits + block * RSD_BLOCK_SIZE + j, bit);                            \
        e_tag[a_bits + block * RSD_BLOCK_SIZE + j] = w_tag[w_idx];                                \
        parity ^= bit;                                                                            \
        last_tag = PFX##_add(last_tag, w_tag[w_idx]);                                             \
      }                                                                                           \
      ptr_set_bit(e_bits, a_bits + block * RSD_BLOCK_SIZE + RSD_PACKED_BLOCK_BITS, parity);       \
      e_tag[a_bits + block * RSD_BLOCK_SIZE + RSD_PACKED_BLOCK_BITS] = last_tag;                  \
    }                                                                                             \
    for (unsigned int row = 0; row < a_bits; ++row) {                                             \
      uint8_t bit = ptr_get_bit(y, row);                                                          \
      PFX##_t tag = PFX##_zero();                                                                 \
      for (unsigned int col = 0; col < k; ++col) {                                                \
        if (ptr_get_bit(matrix_b, row * k + col)) {                                               \
          bit ^= ptr_get_bit(e_bits, a_bits + col);                                               \
          tag = PFX##_add(tag, e_tag[a_bits + col]);                                              \
        }                                                                                         \
      }                                                                                           \
      ptr_set_bit(e_bits, row, bit);                                                              \
      e_tag[row] = tag;                                                                           \
    }                                                                                             \
  }                                                                                               \
                                                                                                  \
  static void decode_noise_keys_##BITS(PFX##_t* e_key, const PFX##_t* w_key, PFX##_t delta,       \
                                       const uint8_t* matrix_b, const uint8_t* y,                 \
                                       const sig_paramset_t* params) {                            \
    const unsigned int n        = params->rsd_code_length;                                        \
    const unsigned int k        = params->rsd_dimension;                                          \
    const unsigned int a_bits   = n - k;                                                          \
    const unsigned int b_blocks = k / RSD_BLOCK_SIZE;                                             \
    (void)n;                                                                                      \
    for (unsigned int block = 0; block < b_blocks; ++block) {                                     \
      PFX##_t last_key = delta;                                                                   \
      for (unsigned int j = 0; j < RSD_PACKED_BLOCK_BITS; ++j) {                                  \
        const unsigned int w_idx = block * RSD_PACKED_BLOCK_BITS + j;                             \
        e_key[a_bits + block * RSD_BLOCK_SIZE + j] = w_key[w_idx];                                \
        last_key = PFX##_add(last_key, w_key[w_idx]);                                             \
      }                                                                                           \
      e_key[a_bits + block * RSD_BLOCK_SIZE + RSD_PACKED_BLOCK_BITS] = last_key;                  \
    }                                                                                             \
    for (unsigned int row = 0; row < a_bits; ++row) {                                             \
      PFX##_t key = PFX##_mul_bit(delta, ptr_get_bit(y, row));                                    \
      for (unsigned int col = 0; col < k; ++col) {                                                \
        if (ptr_get_bit(matrix_b, row * k + col)) {                                               \
          key = PFX##_add(key, e_key[a_bits + col]);                                              \
        }                                                                                         \
      }                                                                                           \
      e_key[row] = key;                                                                           \
    }                                                                                             \
  }                                                                                               \
                                                                                                  \
  static void constraints_prover_##BITS(HASH##_2_ctx* hasher, const uint8_t* w,                  \
                                        const PFX##_t* w_tag, const uint8_t* owf_in,             \
                                        const uint8_t* owf_out, const sig_paramset_t* params) {   \
    static const unsigned int exp_a[] = {0, 1, 2, 3, 4};                                          \
    static const unsigned int exp_b[] = {0, 5, 10, 15};                                           \
    static const unsigned int exp_c[] = {0, 6, 12, 18};                                           \
    PFX##_t powers[RSD_SKETCH_POWERS];                                                            \
    init_powers_##BITS(powers);                                                                   \
    uint8_t* matrix_b = rsd_sample_matrix_b(owf_in, params);                                      \
    uint8_t* e_bits = calloc(ceil_bytes(params->rsd_code_length), 1);                             \
    PFX##_t* e_tag = FIELD_ALLOC(ALIGN, TYPE, params->rsd_code_length);                           \
    assert(e_bits && e_tag);                                                                      \
    decode_noise_tags_##BITS(e_bits, e_tag, w, w_tag, matrix_b, owf_out, params);                 \
    for (unsigned int block = 0; block < params->rsd_noise_weight; ++block) {                     \
      const uint8_t* block_bits = e_bits + (block * RSD_BLOCK_SIZE) / 8;                          \
      const unsigned int bit_off = (block * RSD_BLOCK_SIZE) % 8;                                  \
      uint8_t tmp = 0;                                                                            \
      for (unsigned int j = 0; j < RSD_BLOCK_SIZE; ++j) {                                         \
        ptr_set_bit(&tmp, j, ptr_get_bit(block_bits, bit_off + j));                               \
      }                                                                                           \
      const PFX##_t* auth = e_tag + block * RSD_BLOCK_SIZE;                                       \
      PFX##_t av = lc_value_##BITS(&tmp, powers, exp_a, 5);                                       \
      PFX##_t bv = lc_value_##BITS(&tmp, powers, exp_b, 4);                                       \
      PFX##_t at = lc_auth_##BITS(auth, powers, exp_a, 5);                                        \
      PFX##_t bt = lc_auth_##BITS(auth, powers, exp_b, 4);                                        \
      PFX##_t ct = lc_auth_##BITS(auth, powers, exp_c, 4);                                        \
      PFX##_t a0 = PFX##_mul(at, bt);                                                             \
      PFX##_t a1 = PFX##_add(PFX##_mul(av, bt), PFX##_mul(bv, at));                               \
      a1 = PFX##_add(a1, ct);                                                                     \
      HASH##_2_update(hasher, a0, a1);                                                            \
    }                                                                                             \
    const unsigned int a_bits = params->rsd_code_length - params->rsd_dimension;                  \
    assert(a_bits % RSD_BLOCK_SIZE == 0);                                                         \
    const unsigned int lin_blocks = a_bits / RSD_BLOCK_SIZE;                                      \
    PFX##_t* linear_terms = FIELD_ALLOC(ALIGN, TYPE, BITS);                                       \
    assert(linear_terms);                                                                         \
    for (unsigned int start = 0; start < lin_blocks; start += BITS) {                             \
      const unsigned int end = start + BITS < lin_blocks ? start + BITS : lin_blocks;             \
      memset(linear_terms, 0, BITS * sizeof(TYPE));                                               \
      for (unsigned int block = start; block < end; ++block) {                                    \
        const PFX##_t* auth = e_tag + block * RSD_BLOCK_SIZE;                                     \
        PFX##_t block_tag = PFX##_zero();                                                         \
        for (unsigned int j = 0; j < RSD_BLOCK_SIZE; ++j) {                                       \
          block_tag = PFX##_add(block_tag, auth[j]);                                              \
        }                                                                                         \
        linear_terms[block - start] = block_tag;                                                  \
      }                                                                                           \
      PFX##_t packed_tag = PFX##_sum_poly(linear_terms);                                          \
      HASH##_2_raise_and_update(hasher, packed_tag);                                              \
    }                                                                                             \
    qs_aligned_free(linear_terms);                                                                \
    qs_aligned_free(e_tag);                                                                       \
    free(e_bits);                                                                                 \
    free(matrix_b);                                                                               \
  }                                                                                               \
                                                                                                  \
  static void constraints_verifier_##BITS(HASH##_ctx* hasher, const PFX##_t* w_key,              \
                                          const uint8_t* owf_in, const uint8_t* owf_out,          \
                                          PFX##_t delta, const sig_paramset_t* params) {          \
    static const unsigned int exp_a[] = {0, 1, 2, 3, 4};                                          \
    static const unsigned int exp_b[] = {0, 5, 10, 15};                                           \
    static const unsigned int exp_c[] = {0, 6, 12, 18};                                           \
    PFX##_t powers[RSD_SKETCH_POWERS];                                                            \
    init_powers_##BITS(powers);                                                                   \
    uint8_t* matrix_b = rsd_sample_matrix_b(owf_in, params);                                      \
    PFX##_t* e_key = FIELD_ALLOC(ALIGN, TYPE, params->rsd_code_length);                           \
    assert(e_key);                                                                                \
    decode_noise_keys_##BITS(e_key, w_key, delta, matrix_b, owf_out, params);                     \
    for (unsigned int block = 0; block < params->rsd_noise_weight; ++block) {                     \
      const PFX##_t* auth = e_key + block * RSD_BLOCK_SIZE;                                       \
      PFX##_t ak = lc_auth_##BITS(auth, powers, exp_a, 5);                                        \
      PFX##_t bk = lc_auth_##BITS(auth, powers, exp_b, 4);                                        \
      PFX##_t ck = lc_auth_##BITS(auth, powers, exp_c, 4);                                        \
      PFX##_t b = PFX##_add(PFX##_mul(ak, bk), PFX##_mul(delta, ck));                             \
      HASH##_update(hasher, b);                                                                   \
    }                                                                                             \
    const unsigned int a_bits = params->rsd_code_length - params->rsd_dimension;                  \
    assert(a_bits % RSD_BLOCK_SIZE == 0);                                                         \
    const unsigned int lin_blocks = a_bits / RSD_BLOCK_SIZE;                                      \
    PFX##_t* linear_terms = FIELD_ALLOC(ALIGN, TYPE, BITS);                                       \
    assert(linear_terms);                                                                         \
    for (unsigned int start = 0; start < lin_blocks; start += BITS) {                             \
      const unsigned int end = start + BITS < lin_blocks ? start + BITS : lin_blocks;             \
      memset(linear_terms, 0, BITS * sizeof(TYPE));                                               \
      for (unsigned int block = start; block < end; ++block) {                                    \
        const PFX##_t* auth = e_key + block * RSD_BLOCK_SIZE;                                     \
        PFX##_t block_key = delta;                                                                \
        for (unsigned int j = 0; j < RSD_BLOCK_SIZE; ++j) {                                       \
          block_key = PFX##_add(block_key, auth[j]);                                              \
        }                                                                                         \
        linear_terms[block - start] = block_key;                                                  \
      }                                                                                           \
      PFX##_t packed_key = PFX##_sum_poly(linear_terms);                                          \
      HASH##_update(hasher, PFX##_mul(packed_key, delta));                                        \
    }                                                                                             \
    qs_aligned_free(linear_terms);                                                                \
    qs_aligned_free(e_key);                                                                       \
    free(matrix_b);                                                                               \
  }                                                                                               \
                                                                                                  \
  static void prover_##BITS(uint8_t* a0_tilde, uint8_t* a1_tilde, const uint8_t* w,              \
                            const uint8_t* u, uint8_t** V, const uint8_t* owf_in,                \
                            const uint8_t* owf_out, const uint8_t* chall_2,                      \
                            const sig_paramset_t* params) {                                      \
    const unsigned int ell = params->lenwit;                                                      \
    PFX##_t* w_tag = column_to_row_major_##BITS(V, ell);                                          \
    PFX##_t u_star = PFX##_sum_poly_bits(u);                                                      \
    PFX##_t v_star = PFX##_sum_poly(w_tag + ell);                                                 \
    HASH##_2_ctx hasher;                                                                          \
    HASH##_2_init(&hasher, chall_2);                                                              \
    constraints_prover_##BITS(&hasher, w, w_tag, owf_in, owf_out, params);                        \
    HASH##_2_finalize(a0_tilde, a1_tilde, &hasher, v_star, u_star);                               \
    qs_aligned_free(w_tag);                                                                       \
  }                                                                                               \
                                                                                                  \
  static void verifier_##BITS(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,                  \
                              const uint8_t* owf_in, const uint8_t* owf_out,                     \
                              const uint8_t* chall_2, const uint8_t* chall_3,                    \
                              const uint8_t* a1_tilde, const sig_paramset_t* params) {            \
    const unsigned int ell = params->lenwit;                                                      \
    PFX##_t delta = PFX##_load(chall_3);                                                          \
    PFX##_t* q_key = column_to_row_major_##BITS(Q, ell);                                          \
    PFX##_t q_star = PFX##_sum_poly(q_key + ell);                                                 \
    for (unsigned int i = 0; i < ell; ++i) {                                                      \
      q_key[i] = PFX##_add(q_key[i], PFX##_mul_bit(delta, ptr_get_bit(d, i)));                    \
    }                                                                                             \
    HASH##_ctx b_ctx;                                                                             \
    HASH##_init(&b_ctx, chall_2);                                                                 \
    constraints_verifier_##BITS(&b_ctx, q_key, owf_in, owf_out, delta, params);                   \
    qs_aligned_free(q_key);                                                                       \
    uint8_t q_tilde[BITS / 8];                                                                    \
    HASH##_finalize(q_tilde, &b_ctx, q_star);                                                     \
    PFX##_t ret = PFX##_add(PFX##_load(q_tilde), PFX##_mul(PFX##_load(a1_tilde), delta));         \
    PFX##_store(a0_tilde, ret);                                                                   \
  }

DEFINE_RSD_QS(160, bf160, bf160_t, BF160_ALIGN, zk_hash_160)
DEFINE_RSD_QS(256, bf256, bf256_t, BF256_ALIGN, zk_hash_256)
DEFINE_RSD_QS(384, bf384, bf384_t, BF384_ALIGN, zk_hash_384)
DEFINE_RSD_QS(512, bf512, bf512_t, BF512_ALIGN, zk_hash_512)

void rsd_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, const uint8_t* w,
                           const uint8_t* u, uint8_t** V, const uint8_t* owf_in,
                           const uint8_t* owf_out, const uint8_t* chall_2,
                           const sig_paramset_t* params) {
  switch (params->csp) {
  case 160:
    prover_160(a0_tilde, a1_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    return;
  case 256:
    prover_256(a0_tilde, a1_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    return;
  case 384:
    prover_384(a0_tilde, a1_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    return;
  case 512:
    prover_512(a0_tilde, a1_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    return;
  default:
    assert(!"unsupported resolved-alpha parameter set");
  }
}

void rsd_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,
                             const uint8_t* owf_in, const uint8_t* owf_out,
                             const uint8_t* chall_2, const uint8_t* chall_3,
                             const uint8_t* a1_tilde, const sig_paramset_t* params) {
  switch (params->csp) {
  case 160:
    verifier_160(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, params);
    return;
  case 256:
    verifier_256(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, params);
    return;
  case 384:
    verifier_384(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, params);
    return;
  case 512:
    verifier_512(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, params);
    return;
  default:
    assert(!"unsupported resolved-alpha parameter set");
  }
}
