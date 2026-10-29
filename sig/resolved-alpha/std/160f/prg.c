/*
 *  SPDX-License-Identifier: MIT
 */

#include "prg.h"

#include "enc.h"
#include "endian_compat.h"
#include "instances.h"
#include "tccr.h"

#include <assert.h>
#include <string.h>

#if defined(SIG_TESTS)
void prg_increment_iv(uint8_t* iv) {
  uint32_t iv0;
  memcpy(&iv0, iv, sizeof(uint32_t));
  iv0 = htole32(le32toh(iv0) + 1);
  memcpy(iv, &iv0, sizeof(uint32_t));
}
#endif

static void prg_aes_counter_mode(const uint8_t* key, const uint8_t* iv, uint32_t tweak,
                                 uint8_t* out, unsigned int csp, size_t outlen) {
  const size_t csp_bytes   = csp / 8;
  const size_t full_blocks = outlen / AES_BLOCK_SIZE;
  const size_t tail        = outlen % AES_BLOCK_SIZE;

  uint8_t enc_key[32]   = {0};
  uint8_t plaintext[16] = {0};
  uint8_t block[16];

  assert(csp_bytes <= sizeof(enc_key));
  assert(csp == 160 || csp == 256);

  memcpy(enc_key, key, csp_bytes);
  memcpy(plaintext, iv, IV_SIZE);

  for (size_t i = 0; i < full_blocks; ++i) {
    plaintext[IV_SIZE] = (uint8_t)(tweak + i);
    enc(enc_key, plaintext, out + i * AES_BLOCK_SIZE, csp);
  }

  if (tail) {
    plaintext[IV_SIZE] = (uint8_t)(tweak + full_blocks);
    enc(enc_key, plaintext, block, csp);
    memcpy(out + full_blocks * AES_BLOCK_SIZE, block, tail);
  }
}

static void prg_shacal2_counter_mode(const uint8_t* key, const uint8_t* iv, uint32_t tweak,
                                     uint8_t* out, size_t outlen) {
  const size_t block_len   = 256 / 8;
  const size_t full_blocks = outlen / block_len;
  const size_t tail        = outlen % block_len;

  uint8_t plaintext[32] = {0};
  uint8_t block[32];

  memcpy(plaintext, iv, IV_SIZE);

  for (size_t i = 0; i < full_blocks; ++i) {
    plaintext[IV_SIZE] = (uint8_t)(tweak + i);
    enc(key, plaintext, out + i * block_len, 512);
  }

  if (tail) {
    plaintext[IV_SIZE] = (uint8_t)(tweak + full_blocks);
    enc(key, plaintext, block, 512);
    memcpy(out + full_blocks * block_len, block, tail);
  }
}

static void prg_tccr_mode(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                          unsigned int csp, size_t outlen) {
  const size_t csp_bytes   = csp / 8;
  const size_t full_blocks = outlen / csp_bytes;
  const size_t tail        = outlen % csp_bytes;

  uint8_t s[MAX_CSP_BYTES] = {0};
  uint8_t block[MAX_CSP_BYTES];

  for (size_t i = 0; i < full_blocks; ++i) {
    s[0] = (uint8_t)(tweak + i);
    tccr_hash(key, s, iv, out + i * csp_bytes, csp);
  }

  if (tail) {
    s[0] = (uint8_t)(tweak + full_blocks);
    tccr_hash(key, s, iv, block, csp);
    memcpy(out + full_blocks * csp_bytes, block, tail);
  }
}

void prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out, unsigned int csp,
         size_t outlen) {
  if (csp == 384) {
    prg_tccr_mode(key, iv, tweak, out, csp, outlen);
    return;
  }

  if (csp == 512) {
    prg_shacal2_counter_mode(key, iv, tweak, out, outlen);
    return;
  }

  assert(csp == 160 || csp == 256);
  prg_aes_counter_mode(key, iv, tweak, out, csp, outlen);
}

void prg_2_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                  unsigned int csp) {
  prg(key, iv, tweak, out, csp, csp * 2 / 8);
}

void prg_4_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                  unsigned int csp) {
  prg(key, iv, tweak, out, csp, csp * 4 / 8);
}
