/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef XOF_H
#define XOF_H

/*
 * XOF (eXtendable Output Function) — dual-mode hash interface.
 *
 * Provides the same init / update / final / squeeze / clear API as hash_shake.h,
 * with two backends controlled by the -Dxof build option:
 *
 *   SHAKE (default):   Existing Keccak/SHAKE implementation from hash_shake.h.
 *                       csp selects SHAKE128 (128), SHAKE256 (160/192/256), or
 *                       raw Keccak[c*2,2c] (384/512).
 *
 *   pseudoXOF:         Delegates to the contest-provided one-shot pseudoXOF().
 *                       Input is buffered; each squeeze call extends the XOF
 *                       output incrementally.  csp is ignored (SM3 is fixed).
 *
 * Usage (identical in both modes):
 *   hash_context ctx;
 *   hash_init(&ctx, csp);
 *   hash_update(&ctx, data, datalen);
 *   hash_final(&ctx);
 *   hash_squeeze(&ctx, out, outlen);
 *   hash_clear(&ctx);
 */

#if defined(XOF_PSEUDO)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "endian_compat.h"

#include "auxfunc.h"

#define XOF_MSG_CHUNK 256

typedef struct {
  uint8_t *msg;
  size_t msg_len;
  size_t msg_cap;
  size_t squeezed;
  int finalized;
} hash_context;

static inline void hash_init(hash_context *ctx, unsigned int security_param) {
  (void)security_param;
  ctx->msg       = NULL;
  ctx->msg_len   = 0;
  ctx->msg_cap   = 0;
  ctx->squeezed  = 0;
  ctx->finalized = 0;
}

static inline void hash_update(hash_context *ctx, const uint8_t *data, size_t size) {
  if (ctx->msg_len + size > ctx->msg_cap) {
    size_t new_cap = ctx->msg_cap ? ctx->msg_cap * 2 : XOF_MSG_CHUNK;
    while (new_cap < ctx->msg_len + size) {
      new_cap *= 2;
    }
    uint8_t *new_msg = (uint8_t *)realloc(ctx->msg, new_cap);
    if (!new_msg) {
      return;
    }
    ctx->msg     = new_msg;
    ctx->msg_cap = new_cap;
  }
  memcpy(ctx->msg + ctx->msg_len, data, size);
  ctx->msg_len += size;
}

static inline void hash_update_uint32_le(hash_context *ctx, uint32_t data) {
  data = htole32(data);
  hash_update(ctx, (const uint8_t *)&data, sizeof(data));
}

static inline void hash_init_prefix(hash_context *ctx, unsigned int security_param,
                                    const uint8_t prefix) {
  hash_init(ctx, security_param);
  hash_update(ctx, &prefix, sizeof(prefix));
}

static inline void hash_final(hash_context *ctx) {
  ctx->finalized = 1;
  ctx->squeezed  = 0;
}

/*
 * Squeeze output from pseudoXOF.  Each call extends the output stream:
 * we request squeezed + buflen bytes and return only the new tail.
 * This gives consecutive non-overlapping chunks, matching SHAKE behaviour.
 */
static inline void hash_squeeze(hash_context *ctx, uint8_t *buffer, size_t buflen) {
  if (!ctx->finalized) {
    hash_final(ctx);
  }
  size_t total_bits = (ctx->squeezed + buflen) * 8;
  size_t out_bytes  = ctx->squeezed + buflen;
  uint8_t *tmp      = (uint8_t *)malloc(out_bytes);
  if (!tmp) {
    return;
  }
  pseudoXOF(total_bits, ctx->msg, ctx->msg_len * 8, tmp);
  memcpy(buffer, tmp + ctx->squeezed, buflen);
  free(tmp);
  ctx->squeezed += buflen;
}

static inline void hash_clear(hash_context *ctx) {
  free(ctx->msg);
  ctx->msg       = NULL;
  ctx->msg_len   = 0;
  ctx->msg_cap   = 0;
  ctx->squeezed  = 0;
  ctx->finalized = 0;
}

static inline void hash_copy(hash_context *dst, const hash_context *src) {
  dst->msg_len   = src->msg_len;
  dst->msg_cap   = src->msg_cap;
  dst->squeezed  = src->squeezed;
  dst->finalized = src->finalized;
  if (src->msg && src->msg_cap > 0) {
    dst->msg = (uint8_t *)malloc(src->msg_cap);
    if (dst->msg) {
      memcpy(dst->msg, src->msg, src->msg_len);
    }
  } else {
    dst->msg = NULL;
  }
}

/* hash_context_x4 is not supported in pseudoXOF mode. */
typedef struct {
  int dummy;
} hash_context_x4;

#define hash_init_x4(ctx, sp)         ((void)(ctx), (void)(sp))
#define hash_update_x4(ctx, d, s)     ((void)(ctx), (void)(d), (void)(s))
#define hash_update_x4_4(ctx, a,b,c,d,s) ((void)(ctx),(void)(a),(void)(b),(void)(c),(void)(d),(void)(s))
#define hash_update_x4_1(ctx, d, s)   ((void)(ctx), (void)(d), (void)(s))
#define hash_init_prefix_x4(ctx, sp, pfx) ((void)(ctx),(void)(sp),(void)(pfx))
#define hash_final_x4(ctx)            ((void)(ctx))
#define hash_squeeze_x4(ctx, b, s)    ((void)(ctx), (void)(b), (void)(s))
#define hash_squeeze_x4_4(ctx, a,b,c,d,s) ((void)(ctx),(void)(a),(void)(b),(void)(c),(void)(d),(void)(s))
#define hash_clear_x4(ctx)            ((void)(ctx))
#define hash_update_x4_uint32_le(ctx, d)   ((void)(ctx), (void)(d))
#define hash_update_x4_uint32s_le(ctx, d)  ((void)(ctx), (void)(d))

#else /* XOF_SHAKE (default) — delegate to existing Keccak implementation */

#include "hash_shake.h"

#define hash_copy(dst, src) memcpy(dst, src, sizeof(*(dst)))

#endif /* XOF_SHAKE */

#endif /* XOF_H */
