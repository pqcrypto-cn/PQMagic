/*
 *  SPDX-License-Identifier: MIT
 */

#include "rsd.h"

#include "prg.h"
#include "utils.h"
#include "xof.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RSD_BLOCK_SIZE 6
#define RSD_PACKED_BLOCK_BITS (RSD_BLOCK_SIZE - 1)

static size_t ceil_bytes(size_t bits) {
  return (bits + 7) / 8;
}

static uint8_t reduce_mod_block_size(const uint8_t* bytes, unsigned int bits) {
  uint8_t r = 0;
  for (unsigned int i = bits; i-- > 0;) {
    r = (uint8_t)((2 * r + ptr_get_bit(bytes, i)) % RSD_BLOCK_SIZE);
  }
  return r;
}

static void rsd_sample_noise(uint8_t* e, const uint8_t* seed_sk, const sig_paramset_t* params) {
  const unsigned int csp       = params->csp;
  const unsigned int csp_bytes = csp / 8;
  const unsigned int block_num = params->rsd_noise_weight;

  memset(e, 0, ceil_bytes(params->rsd_code_length));
  for (unsigned int i = 0; i < block_num; ++i) {
    uint8_t iv[IV_SIZE] = {0};
    uint8_t r[MAX_CSP_BYTES];
    iv[0] = (uint8_t)i;
    iv[1] = (uint8_t)(i >> 8);
    prg(seed_sk, iv, 0, r, csp, csp_bytes);
    const uint8_t pos = reduce_mod_block_size(r, csp);
    ptr_set_bit(e, i * RSD_BLOCK_SIZE + pos, 1);
  }
}

uint8_t* rsd_sample_matrix_b(const uint8_t* seed_pk, const sig_paramset_t* params) {
  const size_t rows         = params->rsd_code_length - params->rsd_dimension;
  const size_t cols         = params->rsd_dimension;
  const size_t matrix_bytes = ceil_bytes(rows * cols);
  const uint8_t domain      = 3;

  uint8_t* matrix = malloc(matrix_bytes);
  assert(matrix);

  hash_context ctx;
  hash_init(&ctx, params->csp);
  hash_update(&ctx, &domain, sizeof(domain));
  hash_update(&ctx, seed_pk, params->owf_input_size);
  hash_final(&ctx);
  hash_squeeze(&ctx, matrix, matrix_bytes);
  hash_clear(&ctx);
  return matrix;
}

static void rsd_syndrome_from_noise(uint8_t* syndrome, const uint8_t* matrix_b,
                                    const uint8_t* e, const sig_paramset_t* params) {
  const unsigned int rows = params->rsd_code_length - params->rsd_dimension;
  const unsigned int cols = params->rsd_dimension;

  memset(syndrome, 0, params->owf_output_size);
  for (unsigned int row = 0; row < rows; ++row) {
    uint8_t bit = ptr_get_bit(e, row);
    for (unsigned int col = 0; col < cols; ++col) {
      bit ^= ptr_get_bit(matrix_b, row * cols + col) &
             ptr_get_bit(e, rows + col);
    }
    ptr_set_bit(syndrome, row, bit);
  }
}

void rsd_owf(const uint8_t* seed_sk, const uint8_t* seed_pk, uint8_t* syndrome,
             const sig_paramset_t* params) {
  uint8_t* e        = calloc(ceil_bytes(params->rsd_code_length), 1);
  uint8_t* matrix_b = rsd_sample_matrix_b(seed_pk, params);
  assert(e);

  rsd_sample_noise(e, seed_sk, params);
  rsd_syndrome_from_noise(syndrome, matrix_b, e, params);

  free(matrix_b);
  free(e);
}

void rsd_extend_witness(uint8_t* witness, const uint8_t* seed_sk,
                        const uint8_t* seed_pk, const sig_paramset_t* params) {
  (void)seed_pk;
  uint8_t* e = calloc(ceil_bytes(params->rsd_code_length), 1);
  assert(e);
  rsd_sample_noise(e, seed_sk, params);

  memset(witness, 0, ceil_bytes(params->lenwit));
  const unsigned int a_bits   = params->rsd_code_length - params->rsd_dimension;
  const unsigned int b_blocks = params->rsd_dimension / RSD_BLOCK_SIZE;
  for (unsigned int block = 0; block < b_blocks; ++block) {
    for (unsigned int j = 0; j < RSD_PACKED_BLOCK_BITS; ++j) {
      const uint8_t bit = ptr_get_bit(e, a_bits + block * RSD_BLOCK_SIZE + j);
      ptr_set_bit(witness, block * RSD_PACKED_BLOCK_BITS + j, bit);
    }
  }
  free(e);
}
