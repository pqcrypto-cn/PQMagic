/*
 *  SPDX-License-Identifier: MIT
 */

#if defined(_WIN32) && !defined(HAVE_OPENSSL)
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0601
#elif _WIN32_WINNT < 0x0601
#error "At least Windows 7 is required."
#endif
#endif

#include "enc.h"

#include "endian_compat.h"
#include "fields.h"
#include "utils.h"

#if defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <assert.h>
#include <stdbool.h>
#include <string.h>

static inline uint32_t rotr32(uint32_t x, unsigned int n) {
  return (x >> n) | (x << (32 - n));
}

#define KEY_WORDS_128 4
#define KEY_WORDS_192 6
#define KEY_WORDS_256 8

#define AES_BLOCK_WORDS 4
#define RIJNDAEL_BLOCK_WORDS_192 6
#define RIJNDAEL_BLOCK_WORDS_256 8

static const bf8_t round_constants[30] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91,
};

static const bf8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// ## AES ##
// Round Functions
static void add_round_key(unsigned int round, aes_block_t state, const aes_round_keys_t* round_key,
                          unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    xor_u8_array(&state[c][0], &round_key->round_keys[round][c][0], &state[c][0], AES_NR);
  }
}

static void sub_bytes(aes_block_t state, unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    for (unsigned int r = 0; r < AES_NR; r++) {
      state[c][r] = aes_sbox[state[c][r]];
    }
  }
}

static void shift_row(aes_block_t state, unsigned int block_words) {
  aes_block_t new_state;
  switch (block_words) {
  case 4:
  case 6:
    for (unsigned int i = 0; i < block_words; ++i) {
      new_state[i][0] = state[i][0];
      new_state[i][1] = state[(i + 1) % block_words][1];
      new_state[i][2] = state[(i + 2) % block_words][2];
      new_state[i][3] = state[(i + 3) % block_words][3];
    }
    break;
  case 8:
    for (unsigned int i = 0; i < block_words; i++) {
      new_state[i][0] = state[i][0];
      new_state[i][1] = state[(i + 1) % 8][1];
      new_state[i][2] = state[(i + 3) % 8][2];
      new_state[i][3] = state[(i + 4) % 8][3];
    }
    break;
  }

  for (unsigned int i = 0; i < block_words; ++i) {
    memcpy(&state[i][0], &new_state[i][0], AES_NR);
  }
}

static void mix_column(aes_block_t state, unsigned int block_words) {
  for (unsigned int c = 0; c < block_words; c++) {
    bf8_t tmp[4];
    tmp[0] = bf8_mul(state[c][0], 0x02) ^ bf8_mul(state[c][1], 0x03) ^ state[c][2] ^ state[c][3];
    tmp[1] = state[c][0] ^ bf8_mul(state[c][1], 0x02) ^ bf8_mul(state[c][2], 0x03) ^ state[c][3];
    tmp[2] = state[c][0] ^ state[c][1] ^ bf8_mul(state[c][2], 0x02) ^ bf8_mul(state[c][3], 0x03);
    tmp[3] = bf8_mul(state[c][0], 0x03) ^ state[c][1] ^ state[c][2] ^ bf8_mul(state[c][3], 0x02);

    memcpy(state[c], tmp, sizeof(tmp));
  }
}

// Key Expansion functions
static void sub_words(bf8_t* words) {
  words[0] = aes_sbox[words[0]];
  words[1] = aes_sbox[words[1]];
  words[2] = aes_sbox[words[2]];
  words[3] = aes_sbox[words[3]];
}

static void rot_word(bf8_t* words) {
#if 0
  bf8_t tmp = words[0];
  words[0]  = words[1];
  words[1]  = words[2];
  words[2]  = words[3];
  words[3]  = tmp;
#else
  // in the most ideal case, this generates a simple rord instruction
  uint32_t w;
  memcpy(&w, words, sizeof(w));
  w = htole32(rotr32(le32toh(w), 8));
  memcpy(words, &w, sizeof(w));
#endif
}

void expand_key(aes_round_keys_t* round_keys, const uint8_t* key, unsigned int key_words,
                unsigned int block_words, unsigned int num_rounds) {
  for (unsigned int k = 0; k < key_words; k++) {
    memcpy(round_keys->round_keys[k / block_words][k % block_words], &key[4 * k], 4);
  }

  for (unsigned int k = key_words; k < block_words * (num_rounds + 1); ++k) {
    bf8_t tmp[AES_NR];
    memcpy(tmp, round_keys->round_keys[(k - 1) / block_words][(k - 1) % block_words], sizeof(tmp));

    if (k % key_words == 0) {
      rot_word(tmp);
      sub_words(tmp);
      tmp[0] ^= round_constants[(k / key_words) - 1];
    }

    if (key_words > 6 && (k % key_words) == 4) {
      sub_words(tmp);
    }

    const unsigned int m = k - key_words;
    xor_u8_array(round_keys->round_keys[m / block_words][m % block_words], tmp,
                 round_keys->round_keys[k / block_words][k % block_words], 4);
  }
}

// Calling Functions

void aes128_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_128, AES_BLOCK_WORDS, AES_ROUNDS_128);
}

void aes192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_192, AES_BLOCK_WORDS, AES_ROUNDS_192);
}

void aes256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_256, AES_BLOCK_WORDS, AES_ROUNDS_256);
}

void rijndael192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_192, RIJNDAEL_BLOCK_WORDS_192, AES_ROUNDS_192);
}

void rijndael256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key) {
  expand_key(round_key, key, KEY_WORDS_256, RIJNDAEL_BLOCK_WORDS_256, AES_ROUNDS_256);
}

static void load_state(aes_block_t state, const uint8_t* src, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; ++i) {
    state[i / 4][i % 4] = bf8_load(&src[i]);
  }
}

#if defined(SIG_TESTS)
ATTR_CONST static bf8_t bf_exp_238(bf8_t x) {
  // 238 == 0b11101110
  bf8_t y = bf8_square(x); // x^2
  x       = bf8_square(y); // x^4
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^8
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^16
  x       = bf8_square(x); // x^32
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^64
  y       = bf8_mul(x, y);
  x       = bf8_square(x); // x^128
  return bf8_mul(x, y);
}

uint8_t invnorm(uint8_t in) {
  // instead of computing in^(-17), we calculate in^238
  in = bf_exp_238(in);
  return set_bit(get_bit(in, 0), 0) ^ set_bit(get_bit(in, 6), 1) ^ set_bit(get_bit(in, 7), 2) ^
         set_bit(get_bit(in, 2), 3);
}
#endif

static uint8_t* store_state(uint8_t* dst, aes_block_t state, unsigned int block_words) {
  for (unsigned int i = 0; i != block_words * 4; ++i, ++dst) {
    bf8_store(dst, state[i / 4][i % 4]);
  }
  return dst;
}

static void aes_encrypt(const aes_round_keys_t* keys, aes_block_t state, unsigned int block_words,
                        unsigned int num_rounds) {
  // first round
  add_round_key(0, state, keys, block_words);

  for (unsigned int round = 1; round < num_rounds; ++round) {
    sub_bytes(state, block_words);
    shift_row(state, block_words);
    mix_column(state, block_words);
    add_round_key(round, state, keys, block_words);
  }

  // last round
  sub_bytes(state, block_words);
  shift_row(state, block_words);
  add_round_key(num_rounds, state, keys, block_words);
}

void aes128_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  aes_encrypt(key, state, AES_BLOCK_WORDS, AES_ROUNDS_128);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
}

void aes192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  aes_encrypt(key, state, AES_BLOCK_WORDS, AES_ROUNDS_192);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
}

void aes256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, AES_BLOCK_WORDS);
  aes_encrypt(key, state, AES_BLOCK_WORDS, AES_ROUNDS_256);
  store_state(ciphertext, state, AES_BLOCK_WORDS);
}

void rijndael192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                               uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, RIJNDAEL_BLOCK_WORDS_192);
  aes_encrypt(key, state, RIJNDAEL_BLOCK_WORDS_192, AES_ROUNDS_192);
  store_state(ciphertext, state, RIJNDAEL_BLOCK_WORDS_192);
}

void rijndael256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                               uint8_t* ciphertext) {
  aes_block_t state;
  load_state(state, plaintext, RIJNDAEL_BLOCK_WORDS_256);
  aes_encrypt(key, state, RIJNDAEL_BLOCK_WORDS_256, AES_ROUNDS_256);
  store_state(ciphertext, state, RIJNDAEL_BLOCK_WORDS_256);
}

#if defined(HAVE_OPENSSL)
int generic_aes_ecb_new(generic_aes_ecb_t* context, const uint8_t* key, unsigned int seclvl) {
  const EVP_CIPHER* cipher = NULL;
  switch (seclvl) {
  case 256:
    cipher = EVP_aes_256_ecb();
    break;
  case 192:
    cipher = EVP_aes_192_ecb();
    break;
  case 128:
    cipher = EVP_aes_128_ecb();
    break;
  }
  if (!cipher) {
    return -1;
  }

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    return -1;
  }

  EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);
  EVP_CIPHER_CTX_set_padding(ctx, 0);
  context->ctx = ctx;
  return 0;
}

int generic_aes_ecb_encrypt(generic_aes_ecb_t* ctx, uint8_t* ciphertext, const uint8_t* plaintext,
                            size_t blocks) {
  int len = 0;
  const int length = (int)(blocks * AES_BLOCK_SIZE);
  int ret = EVP_EncryptUpdate(ctx->ctx, ciphertext, &len, plaintext, length);
  if (ret != 1 || len != length) {
    return -1;
  }
  return 0;
}

void generic_aes_ecb_free(generic_aes_ecb_t* ctx) {
  EVP_CIPHER_CTX_free(ctx->ctx);
}
#elif defined(_WIN32)
int generic_aes_ecb_new(generic_aes_ecb_t* ctx, const uint8_t* key, unsigned int seclvl) {
  BCRYPT_ALG_HANDLE aes_handle = NULL;
  BCRYPT_KEY_HANDLE key_handle = NULL;

  NTSTATUS ret = BCryptOpenAlgorithmProvider(&aes_handle, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(ret)) {
    return -1;
  }
  ret = BCryptSetProperty(aes_handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          (ULONG)((wcslen(BCRYPT_CHAIN_MODE_ECB) + 1) * sizeof(wchar_t)), 0);
  if (!BCRYPT_SUCCESS(ret)) {
    BCryptCloseAlgorithmProvider(aes_handle, 0);
    return -1;
  }

  ret = BCryptGenerateSymmetricKey(aes_handle, &key_handle, NULL, 0, (PUCHAR)key, seclvl / 8, 0);
  if (!BCRYPT_SUCCESS(ret)) {
    BCryptCloseAlgorithmProvider(aes_handle, 0);
    return -1;
  }

  ctx->aes_handle = aes_handle;
  ctx->key_handle = key_handle;
  return 0;
}

int generic_aes_ecb_encrypt(generic_aes_ecb_t* ctx, uint8_t* ciphertext, const uint8_t* plaintext,
                            size_t blocks) {
  ULONG len          = 0;
  const ULONG length = blocks * AES_BLOCK_SIZE;

  NTSTATUS ret =
      BCryptEncrypt(ctx->key_handle, plaintext, length, NULL, NULL, 0, ciphertext, length, &len, 0);
  if (!BCRYPT_SUCCESS(ret) || len != length) {
    return -1;
  }

  return 0;
}

void generic_aes_ecb_free(generic_aes_ecb_t* ctx) {
  BCryptDestroyKey(ctx->key_handle);
  BCryptCloseAlgorithmProvider(ctx->aes_handle, 0);
}
#else
int generic_aes_ecb_new(generic_aes_ecb_t* ctx, const uint8_t* key, unsigned int seclvl) {
  switch (seclvl) {
  case 256:
    aes256_init_round_keys(&ctx->round_keys, key);
    break;
  case 192:
    aes192_init_round_keys(&ctx->round_keys, key);
    break;
  case 128:
    aes128_init_round_keys(&ctx->round_keys, key);
    break;
  default:
    return -1;
  }

  ctx->seclvl = seclvl;
  return 0;
}

int generic_aes_ecb_encrypt(generic_aes_ecb_t* ctx, uint8_t* ciphertext, const uint8_t* plaintext,
                            size_t blocks) {
  switch (ctx->seclvl) {
  case 256: {
    for (; blocks; --blocks, plaintext += AES_BLOCK_SIZE, ciphertext += AES_BLOCK_SIZE) {
      aes_block_t state;
      load_state(state, plaintext, AES_BLOCK_WORDS);
      aes_encrypt(&ctx->round_keys, state, AES_BLOCK_WORDS, AES_ROUNDS_256);
      store_state(ciphertext, state, AES_BLOCK_WORDS);
    }
    break;
  }
  case 192: {
    for (; blocks; --blocks, plaintext += AES_BLOCK_SIZE, ciphertext += AES_BLOCK_SIZE) {
      aes_block_t state;
      load_state(state, plaintext, AES_BLOCK_WORDS);
      aes_encrypt(&ctx->round_keys, state, AES_BLOCK_WORDS, AES_ROUNDS_192);
      store_state(ciphertext, state, AES_BLOCK_WORDS);
    }
    break;
  }
  case 128: {
    for (; blocks; --blocks, plaintext += AES_BLOCK_SIZE, ciphertext += AES_BLOCK_SIZE) {
      aes_block_t state;
      load_state(state, plaintext, AES_BLOCK_WORDS);
      aes_encrypt(&ctx->round_keys, state, AES_BLOCK_WORDS, AES_ROUNDS_128);
      store_state(ciphertext, state, AES_BLOCK_WORDS);
    }
  }
  }

  return 0;
}

void generic_aes_ecb_free(generic_aes_ecb_t* ctx) {
  memset(&ctx->round_keys, 0, sizeof(ctx->round_keys));
}
#endif

size_t enc_key_len(unsigned int csp) {
  switch (csp) {
  case 160: return 192 / 8; // AES-192
  case 256: return 256 / 8; // AES-256
  case 384: return 256 / 8; // Rijndael-256
  case 512: return 512 / 8; // SHACAL-2
  default:  return 0;
  }
}

size_t enc_block_len(unsigned int csp) {
  switch (csp) {
  case 160: return 128 / 8; // AES-192
  case 256: return 128 / 8; // AES-256
  case 384: return 256 / 8; // Rijndael-256
  case 512: return 256 / 8; // SHACAL-2
  default:  return 0;
  }
}

unsigned int enc_num_rounds(unsigned int csp) {
  switch (csp) {
  case 160: return 12; // AES-192
  case 256: return 14; // AES-256
  case 384: return 14; // Rijndael-256
  case 512: return 64; // SHACAL-2
  default:  return 0;
  }
}

/* -------------------------------------------------------------------------- */
/* SHACAL-2 (SHA-256 used as a 512-bit-key, 256-bit-block cipher, no feed-forward) */

static const uint32_t K_SHA256[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
  0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
  0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
  0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
  0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
  0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
};

static inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
static inline uint32_t Sigma0(uint32_t x) {
  return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}
static inline uint32_t Sigma1(uint32_t x) {
  return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}
static inline uint32_t sigma0(uint32_t x) {
  return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}
static inline uint32_t sigma1(uint32_t x) {
  return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

static inline uint32_t load32be(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void store32be(uint8_t* p, uint32_t x) {
  p[0] = (uint8_t)(x >> 24);
  p[1] = (uint8_t)(x >> 16);
  p[2] = (uint8_t)(x >> 8);
  p[3] = (uint8_t)x;
}

static void shacal2_encrypt(const uint8_t* key, const uint8_t* plaintext, uint8_t* ciphertext) {
  uint32_t W[64];
  for (int i = 0; i < 16; i++) {
    W[i] = load32be(key + i * 4);
  }
  for (int i = 16; i < 64; i++) {
    W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
  }

  uint32_t a = load32be(plaintext + 0);
  uint32_t b = load32be(plaintext + 4);
  uint32_t c = load32be(plaintext + 8);
  uint32_t d = load32be(plaintext + 12);
  uint32_t e = load32be(plaintext + 16);
  uint32_t f = load32be(plaintext + 20);
  uint32_t g = load32be(plaintext + 24);
  uint32_t h = load32be(plaintext + 28);

  for (int i = 0; i < 64; i++) {
    uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + K_SHA256[i] + W[i];
    uint32_t T2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  store32be(ciphertext + 0, a);
  store32be(ciphertext + 4, b);
  store32be(ciphertext + 8, c);
  store32be(ciphertext + 12, d);
  store32be(ciphertext + 16, e);
  store32be(ciphertext + 20, f);
  store32be(ciphertext + 24, g);
  store32be(ciphertext + 28, h);
}

/* -------------------------------------------------------------------------- */
/* Public API */

void enc(const uint8_t* key, const uint8_t* plaintext, uint8_t* ciphertext, unsigned int csp) {
  if (csp == 512) {
    shacal2_encrypt(key, plaintext, ciphertext);
    return;
  }

  // Cache the last expanded key to avoid repeated key expansion.
  static aes_round_keys_t rk_cache;
  static uint8_t key_cache[64];
  static unsigned int csp_cache;
  static int cache_valid;

  size_t keylen = enc_key_len(csp);
  if (!cache_valid || csp_cache != csp || memcmp(key_cache, key, keylen) != 0) {
    switch (csp) {
    case 160: aes192_init_round_keys(&rk_cache, key); break;
    case 256: aes256_init_round_keys(&rk_cache, key); break;
    case 384: rijndael256_init_round_keys(&rk_cache, key); break;
    default:  break;
    }
    memcpy(key_cache, key, keylen);
    csp_cache   = csp;
    cache_valid = 1;
  }

  switch (csp) {
  case 160: aes192_encrypt_block(&rk_cache, plaintext, ciphertext); break;
  case 256: aes256_encrypt_block(&rk_cache, plaintext, ciphertext); break;
  case 384: rijndael256_encrypt_block(&rk_cache, plaintext, ciphertext); break;
  default:  break;
  }
}
