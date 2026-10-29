/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef ENC_H
#define ENC_H

#include "instances.h"
#include "macros.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#if defined(HAVE_OPENSSL)
#include <openssl/evp.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

SIG_BEGIN_C_DECL

#define AES_ROUNDS_128 10
#define AES_ROUNDS_192 12
#define AES_ROUNDS_256 14
#define AES_MAX_ROUNDS 14
#define AES_NR 4

typedef uint8_t aes_word_t[4];
typedef aes_word_t aes_round_key_t[8];
typedef aes_word_t aes_block_t[8];

typedef struct {
  aes_round_key_t round_keys[AES_MAX_ROUNDS + 1];
} aes_round_keys_t;

void aes128_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
void aes192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
void aes256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
void rijndael192_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);
void rijndael256_init_round_keys(aes_round_keys_t* round_key, const uint8_t* key);

void aes128_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext);
void aes192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext);
void aes256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                          uint8_t* ciphertext);
void rijndael192_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                               uint8_t* ciphertext);
void rijndael256_encrypt_block(const aes_round_keys_t* key, const uint8_t* plaintext,
                               uint8_t* ciphertext);

#if defined(SIG_TESTS)
uint8_t invnorm(uint8_t in);
#endif

void expand_key(aes_round_keys_t* round_keys, const uint8_t* key, unsigned int key_words,
                unsigned int block_words, unsigned int num_rounds);

typedef struct {
#if defined(HAVE_OPENSSL)
  EVP_CIPHER_CTX* ctx;
#elif defined(_WIN32)
  BCRYPT_ALG_HANDLE aes_handle;
  BCRYPT_KEY_HANDLE key_handle;
#else
  aes_round_keys_t round_keys;
  unsigned int seclvl;
#endif
} generic_aes_ecb_t;

int generic_aes_ecb_new(generic_aes_ecb_t* ctx, const uint8_t* key, unsigned int seclvl);
int generic_aes_ecb_encrypt(generic_aes_ecb_t* ctx, uint8_t* ciphertext, const uint8_t* plaintext,
                            size_t blocks);
void generic_aes_ecb_free(generic_aes_ecb_t* ctx);

size_t enc_key_len(unsigned int csp);
size_t enc_block_len(unsigned int csp);
unsigned int enc_num_rounds(unsigned int csp);
void enc(const uint8_t* key, const uint8_t* plaintext, uint8_t* ciphertext, unsigned int csp);

SIG_END_C_DECL

#endif
