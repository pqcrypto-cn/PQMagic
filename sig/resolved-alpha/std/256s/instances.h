/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef INSTANCES_H
#define INSTANCES_H

#include "macros.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_CSP 512
#define MAX_CSP_BYTES (MAX_CSP / 8)
#define MAX_DEPTH 13
#define MAX_TAU 72
#define UNIVERSAL_HASH_B_BITS 16
#define UNIVERSAL_HASH_B (UNIVERSAL_HASH_B_BITS / 8)
#define AES_BLOCK_SIZE 16
#define IV_SIZE 15 // 120-bit IV per NGCC spec

SIG_BEGIN_C_DECL

typedef enum sig_paramid_t {
  PARAMETER_SET_INVALID   = 0,
  RESOLVED_ALPHA_160S     = 1,
  RESOLVED_ALPHA_160F     = 2,
  RESOLVED_ALPHA_256S     = 3,
  RESOLVED_ALPHA_256F     = 4,
  RESOLVED_ALPHA_384S     = 5,
  RESOLVED_ALPHA_384F     = 6,
  RESOLVED_ALPHA_512S     = 7,
  RESOLVED_ALPHA_512F     = 8,
  PARAMETER_SET_MAX_INDEX = 9
} sig_paramid_t;

typedef struct sig_paramset_t {
  // main parameters
  uint16_t csp;
  uint8_t tau;
  uint8_t POWLevel;
  uint16_t T_open;
  uint16_t lenwit;

  // extra parameters
  uint16_t k;
  uint8_t tau0;
  uint8_t tau1;
  uint32_t L;

  // additional parameters
  uint32_t sig_size;
  uint16_t owf_input_size;
  uint16_t owf_output_size;

  // RSD OWF parameters
  uint16_t rsd_code_length;
  uint16_t rsd_dimension;
  uint16_t rsd_noise_weight;
  uint8_t rsd_block_size;
  uint16_t rsd_witness_bits;
} sig_paramset_t;

const char* ATTR_CONST sig_get_param_name(sig_paramid_t paramid);
const sig_paramset_t* ATTR_CONST sig_get_paramset(sig_paramid_t paramid);

SIG_END_C_DECL

#endif
