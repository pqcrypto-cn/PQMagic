/*
 *  SPDX-License-Identifier: MIT
 */

#include "tccr.h"
#include "enc.h"
#include "endian_compat.h"

#include <assert.h>
#include <string.h>

// N_block = 2 case of the specification: key = x_R || iv || 0*, input_i = i || x_L.
static void tccr_hash_nblock2(const uint8_t* x, const uint8_t* s, const uint8_t* iv, uint8_t* out,
                              unsigned int csp) {
  const size_t csp_bytes   = csp / 8;
  const size_t key_bytes   = enc_key_len(csp);
  const size_t block_bytes = enc_block_len(csp);
  const size_t x_l_bytes   = block_bytes - 1;
  const size_t x_r_bytes   = csp_bytes - x_l_bytes;
  const size_t pad_bytes   = key_bytes + block_bytes - 16 - csp_bytes;

  assert(key_bytes <= MAX_CSP_BYTES);
  assert(block_bytes <= MAX_CSP_BYTES);
  assert((csp_bytes + block_bytes - 1) / block_bytes == 2);
  assert(x_r_bytes + IV_SIZE + pad_bytes == key_bytes);
  (void)pad_bytes;

  uint8_t x_bar[MAX_CSP_BYTES];
  for (size_t i = 0; i < csp_bytes; ++i) {
    x_bar[i] = x[i] ^ s[i];
  }

  uint8_t key[MAX_CSP_BYTES] = {0};
  memcpy(key, x_bar + x_l_bytes, x_r_bytes);
  memcpy(key + x_r_bytes, iv, IV_SIZE);

  uint8_t plaintext[MAX_CSP_BYTES] = {0};
  memcpy(plaintext + 1, x_bar, x_l_bytes);

  uint8_t ciphertext[MAX_CSP_BYTES];
  for (size_t i = 0; i != 2; ++i) {
    plaintext[0] = (uint8_t)i;
    enc(key, plaintext, ciphertext, csp);

    const size_t out_offset = i * block_bytes;
    const size_t out_bytes  = (i == 0) ? block_bytes : csp_bytes - block_bytes;
    for (size_t j = 0; j != out_bytes; ++j) {
      out[out_offset + j] = ciphertext[j] ^ plaintext[j];
    }
  }
}

void tccr_hash(const uint8_t* x, const uint8_t* s, const uint8_t* iv, uint8_t* out,
               unsigned int csp) {
  tccr_hash_nblock2(x, s, iv, out, csp);
}

void tccr_hash_x0_x1(const uint8_t* x, const uint8_t* s, const uint8_t* iv, uint8_t* out0,
                     uint8_t* out1, unsigned int csp) {
  tccr_hash(x, s, iv, out0, csp);
  uint8_t tmp[MAX_CSP_BYTES];
  memcpy(tmp, x, csp / 8);
  tmp[0] ^= 1;
  tccr_hash(tmp, s, iv, out1, csp);
}
