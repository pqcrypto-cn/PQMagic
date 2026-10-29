/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIG_UTILS_H
#define SIG_UTILS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "endian_compat.h"
#include "macros.h"
#include "instances.h"

SIG_BEGIN_C_DECL

static inline void xor_u8_array(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
}

static inline void masked_xor_u8_array(const uint8_t* a, const uint8_t* b, uint8_t* out,
                                       uint8_t mask_bit, size_t len) {
  uint8_t mask = -(mask_bit & 1);
  for (size_t i = 0; i < len; i++) {
    out[i] = a[i] ^ (b[i] & mask);
  }
}

#define get_bit(value, index) (((value) >> (index)) & 1)
#define set_bit(value, index) ((value) << (index))
#define ptr_get_bit(value, index) (((value)[(index) / 8] >> ((index) % 8)) & 1)
#define ptr_set_bit(dst, index, value)                                                             \
  do {                                                                                             \
    const unsigned int ptr_set_bit_index_mod_8 = (index) % 8;                                      \
    (dst)[(index) / 8] = ((dst)[(index) / 8] & ~(1 << ptr_set_bit_index_mod_8)) |                  \
                         ((value) << ptr_set_bit_index_mod_8);                                     \
  } while (0)

// DecodeAllChall_3
bool decode_all_chall_3(uint16_t* decoded_chall, const uint8_t* chall,
                        const sig_paramset_t* params);

SIG_END_C_DECL

#endif
