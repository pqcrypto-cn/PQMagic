// SPDX-License-Identifier: Apache-2.0

#ifndef PIKE_HASH_H
#define PIKE_HASH_H

#include <stddef.h>

#define PIKE_XOF_BACKEND_SHAKE 1
#define PIKE_XOF_BACKEND_SM3 2

#ifndef PIKE_XOF_BACKEND
#define PIKE_XOF_BACKEND PIKE_XOF_BACKEND_SHAKE
#endif

#if PIKE_XOF_BACKEND != PIKE_XOF_BACKEND_SHAKE && PIKE_XOF_BACKEND != PIKE_XOF_BACKEND_SM3
#error "Unsupported PIKE_XOF_BACKEND"
#endif

#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
#include <fips202.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pike_xof_ctx_t {
#if PIKE_XOF_BACKEND == PIKE_XOF_BACKEND_SHAKE
    shake256ctx shake;
    unsigned char block[SHAKE256_RATE];
#else
    const unsigned char *seed;
    size_t seed_len;
    unsigned int counter;
    unsigned char block[32];
#endif
    size_t block_pos;
} pike_xof_ctx_t;

int pike_xof(unsigned char *out, size_t outlen, const unsigned char *in, size_t inlen);
int pike_hash_256(unsigned char *out, const unsigned char *in, size_t inlen);
void pike_xof_stream_init(pike_xof_ctx_t *ctx, const unsigned char *seed, size_t seed_len);
void pike_xof_stream_squeeze(pike_xof_ctx_t *ctx, unsigned char *out, size_t outlen);
void pike_xof_stream_release(pike_xof_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
