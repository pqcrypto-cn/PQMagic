/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef HASH_SHAKE_H
#define HASH_SHAKE_H

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include "macros.h"
#include "endian_compat.h"

#if defined(WITH_SHAKE_S390_CPACF)
/* use the KIMD/KLMD instructions from CPACF for SHAKE support on S390 */
#include "sha3/s390_cpacf.h"
#elif defined(OQS) || (0 && defined(PQCLEAN))
#if defined(OQS)
/* use OQS's SHAKE implementation */
#include <oqs/sha3.h>
#include <oqs/sha3x4.h>
#elif defined(PQCLEAN)
/* PQClean's SHAKE implementation
 *
 * PQClean current does not expose the AVX2-optimized version of Keccakx4.
 */
#include <fips202.h>
#define OQS_SHA3_shake128_inc_ctx shake128incctx
#define OQS_SHA3_shake128_inc_init shake128_inc_init
#define OQS_SHA3_shake128_inc_absorb shake128_inc_absorb
#define OQS_SHA3_shake128_inc_finalize shake128_inc_finalize
#define OQS_SHA3_shake128_inc_squeeze shake128_inc_squeeze
#define OQS_SHA3_shake128_inc_ctx_release shake128_inc_ctx_release
#define OQS_SHA3_shake256_inc_ctx shake256incctx
#define OQS_SHA3_shake256_inc_init shake256_inc_init
#define OQS_SHA3_shake256_inc_absorb shake256_inc_absorb
#define OQS_SHA3_shake256_inc_finalize shake256_inc_finalize
#define OQS_SHA3_shake256_inc_squeeze shake256_inc_squeeze
#define OQS_SHA3_shake256_inc_ctx_release shake256_inc_ctx_release
#endif

typedef struct hash_context_oqs_s {
  union {
    OQS_SHA3_shake128_inc_ctx shake128_ctx;
    OQS_SHA3_shake256_inc_ctx shake256_ctx;
  };
  unsigned char shake256;
} hash_context;

/**
 * Initialize hash context based on the security parameter. If the security parameter is 128,
 * SHAKE128 is used, otherwise SHAKE256 is used.
 */
static inline void hash_init(hash_context* ctx, unsigned int security_param) {
  if (security_param == 128) {
    OQS_SHA3_shake128_inc_init(&ctx->shake128_ctx);
    ctx->shake256 = 0;
  } else if (security_param == 160 || security_param == 192 || security_param == 256) {
    OQS_SHA3_shake256_inc_init(&ctx->shake256_ctx);
    ctx->shake256 = 1;
  } else {
    /* OQS backend only exposes SHAKE128/SHAKE256 contexts. */
    assert(!"OQS backend does not support SHAKE-384/SHAKE-512 incremental contexts");
    OQS_SHA3_shake256_inc_init(&ctx->shake256_ctx);
    ctx->shake256 = 1;
  }
}

static inline void hash_update(hash_context* ctx, const uint8_t* data, size_t size) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_inc_absorb(&ctx->shake256_ctx, data, size);
  } else {
    OQS_SHA3_shake128_inc_absorb(&ctx->shake128_ctx, data, size);
  }
}

static inline void hash_final(hash_context* ctx) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_inc_finalize(&ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_inc_finalize(&ctx->shake128_ctx);
  }
}

static inline void hash_squeeze(hash_context* ctx, uint8_t* buffer, size_t buflen) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_inc_squeeze(buffer, buflen, &ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_inc_squeeze(buffer, buflen, &ctx->shake128_ctx);
  }
}

static inline void hash_clear(hash_context* ctx) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_inc_ctx_release(&ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_inc_ctx_release(&ctx->shake128_ctx);
  }
}

/* Instances that work with 4 states in parallel using the base implementation. */
typedef struct hash_context_x4_oqs_s {
  union {
    OQS_SHA3_shake128_x4_inc_ctx shake128_ctx;
    OQS_SHA3_shake256_x4_inc_ctx shake256_ctx;
  };
  unsigned int shake256;
} hash_context_x4;

static inline void hash_init_x4(hash_context_x4* ctx, unsigned int security_param) {
  if (security_param == 128) {
    OQS_SHA3_shake128_x4_inc_init(&ctx->shake128_ctx);
    ctx->shake256 = 0;
  } else if (security_param == 160 || security_param == 192 || security_param == 256) {
    OQS_SHA3_shake256_x4_inc_init(&ctx->shake256_ctx);
    ctx->shake256 = 1;
  } else {
    /* OQS backend only exposes SHAKE128/SHAKE256 contexts. */
    assert(!"OQS backend does not support SHAKE-384/SHAKE-512 x4 incremental contexts");
    OQS_SHA3_shake256_x4_inc_init(&ctx->shake256_ctx);
    ctx->shake256 = 1;
  }
}

static inline void hash_update_x4(hash_context_x4* ctx, const uint8_t** data, size_t size) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_absorb(&ctx->shake256_ctx, data[0], data[1], data[2], data[3], size);
  } else {
    OQS_SHA3_shake128_x4_inc_absorb(&ctx->shake128_ctx, data[0], data[1], data[2], data[3], size);
  }
}

static inline void hash_update_x4_4(hash_context_x4* ctx, const uint8_t* data0,
                                    const uint8_t* data1, const uint8_t* data2,
                                    const uint8_t* data3, size_t size) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_absorb(&ctx->shake256_ctx, data0, data1, data2, data3, size);
  } else {
    OQS_SHA3_shake128_x4_inc_absorb(&ctx->shake128_ctx, data0, data1, data2, data3, size);
  }
}

static inline void hash_update_x4_1(hash_context_x4* ctx, const uint8_t* data, size_t size) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_absorb(&ctx->shake256_ctx, data, data, data, data, size);
  } else {
    OQS_SHA3_shake128_x4_inc_absorb(&ctx->shake128_ctx, data, data, data, data, size);
  }
}

static inline void hash_init_prefix_x4(hash_context_x4* ctx, unsigned int security_param,
                                       const uint8_t prefix) {
  if (security_param == 128) {
    OQS_SHA3_shake128_x4_inc_init(&ctx->shake128_ctx);
    OQS_SHA3_shake128_x4_inc_absorb(&ctx->shake128_ctx, &prefix, &prefix, &prefix, &prefix,
                                    sizeof(prefix));
    ctx->shake256 = 0;
  } else if (security_param == 160 || security_param == 192 || security_param == 256) {
    OQS_SHA3_shake256_x4_inc_init(&ctx->shake256_ctx);
    OQS_SHA3_shake256_x4_inc_absorb(&ctx->shake256_ctx, &prefix, &prefix, &prefix, &prefix,
                                    sizeof(prefix));
    ctx->shake256 = 1;
  } else {
    /* OQS backend only exposes SHAKE128/SHAKE256 contexts. */
    assert(!"OQS backend does not support SHAKE-384/SHAKE-512 x4 incremental contexts");
    OQS_SHA3_shake256_x4_inc_init(&ctx->shake256_ctx);
    OQS_SHA3_shake256_x4_inc_absorb(&ctx->shake256_ctx, &prefix, &prefix, &prefix, &prefix,
                                    sizeof(prefix));
    ctx->shake256 = 1;
  }
}

static inline void hash_final_x4(hash_context_x4* ctx) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_finalize(&ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_x4_inc_finalize(&ctx->shake128_ctx);
  }
}

static inline void hash_squeeze_x4(hash_context_x4* ctx, uint8_t** buffer, size_t buflen) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_squeeze(buffer[0], buffer[1], buffer[2], buffer[3], buflen,
                                     &ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_x4_inc_squeeze(buffer[0], buffer[1], buffer[2], buffer[3], buflen,
                                     &ctx->shake128_ctx);
  }
}

static inline void hash_squeeze_x4_4(hash_context_x4* ctx, uint8_t* buffer0, uint8_t* buffer1,
                                     uint8_t* buffer2, uint8_t* buffer3, size_t buflen) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_squeeze(buffer0, buffer1, buffer2, buffer3, buflen,
                                     &ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_x4_inc_squeeze(buffer0, buffer1, buffer2, buffer3, buflen,
                                     &ctx->shake128_ctx);
  }
}

static inline void hash_clear_x4(hash_context_x4* ctx) {
  if (ctx->shake256) {
    OQS_SHA3_shake256_x4_inc_ctx_release(&ctx->shake256_ctx);
  } else {
    OQS_SHA3_shake128_x4_inc_ctx_release(&ctx->shake128_ctx);
  }
}
#else
#if !defined(SUPERCOP)
#if defined(__cplusplus)
extern "C" {
#endif
/* use SHAKE implementation in sha3/ */
#include "sha3/KeccakHash.h"
#if defined(__cplusplus)
}
#endif
#else
/* use SUPERCOP implementation */
#include <libkeccak.a.headers/KeccakHash.h>
#endif

#if defined(WITH_KECCAK_X4)
/* use the Keccakx4 implementation */
#include "KeccakHashtimes4.h"
#endif

typedef Keccak_HashInstance hash_context;

/**
 * Initialize hash context based on the security parameter. If the security parameter is 128,
 * SHAKE128 is used, otherwise SHAKE256 is used.
 */
static inline void hash_init(hash_context* ctx, unsigned int security_param) {
  if (security_param == 128) {
    Keccak_HashInitialize_SHAKE128(ctx);
  } else if (security_param == 160 || security_param == 192 || security_param == 256) {
    Keccak_HashInitialize_SHAKE256(ctx);
  } else if (security_param == 384) {
    Keccak_HashInitialize(ctx, 832, 768, 0, 0x1F);
  } else if (security_param == 512) {
    Keccak_HashInitialize(ctx, 576, 1024, 0, 0x1F);
  } else {
    assert(!"unsupported security parameter");
    Keccak_HashInitialize_SHAKE256(ctx);
  }
}

static inline void hash_update(hash_context* ctx, const uint8_t* data, size_t size) {
  Keccak_HashUpdate(ctx, data, size << 3);
}

static inline void hash_final(hash_context* ctx) {
  Keccak_HashFinal(ctx, NULL);
}

static inline void hash_squeeze(hash_context* ctx, uint8_t* buffer, size_t buflen) {
  Keccak_HashSqueeze(ctx, buffer, buflen << 3);
}

#define hash_clear(ctx)                                                                            \
  { (void)ctx; }
#endif

static inline void hash_update_uint32_le(hash_context* ctx, uint32_t data) {
  data = htole32(data);
  hash_update(ctx, (const uint8_t*)&data, sizeof(data));
}

static inline void hash_init_prefix(hash_context* ctx, unsigned int security_param,
                                    const uint8_t prefix) {
  hash_init(ctx, security_param);
  hash_update(ctx, &prefix, sizeof(prefix));
}

#if defined(WITH_KECCAK_X4)
/* Instances that work with 4 states in parallel. */
typedef Keccak_HashInstancetimes4 hash_context_x4;

static inline void hash_init_x4(hash_context_x4* ctx, unsigned int security_param) {
  if (security_param == 128) {
    Keccak_HashInitializetimes4_SHAKE128(ctx);
  } else if (security_param == 160 || security_param == 192 || security_param == 256) {
    Keccak_HashInitializetimes4_SHAKE256(ctx);
  } else if (security_param == 384) {
    Keccak_HashInitializetimes4(ctx, 832, 768, 0, 0x1F);
  } else if (security_param == 512) {
    Keccak_HashInitializetimes4(ctx, 576, 1024, 0, 0x1F);
  } else {
    assert(!"unsupported security parameter");
    Keccak_HashInitializetimes4_SHAKE256(ctx);
  }
}

static inline void hash_update_x4(hash_context_x4* ctx, const uint8_t** data, size_t size) {
  Keccak_HashUpdatetimes4(ctx, data, size << 3);
}

static inline void hash_update_x4_4(hash_context_x4* ctx, const uint8_t* data0,
                                    const uint8_t* data1, const uint8_t* data2,
                                    const uint8_t* data3, size_t size) {
  const uint8_t* data[4] = {data0, data1, data2, data3};
  hash_update_x4(ctx, data, size);
}

static inline void hash_update_x4_1(hash_context_x4* ctx, const uint8_t* data, size_t size) {
  const uint8_t* tmp[4] = {data, data, data, data};
  hash_update_x4(ctx, tmp, size);
}

static inline void hash_init_prefix_x4(hash_context_x4* ctx, unsigned int security_param,
                                       const uint8_t prefix) {
  hash_init_x4(ctx, security_param);
  hash_update_x4_1(ctx, &prefix, sizeof(prefix));
}

static inline void hash_final_x4(hash_context_x4* ctx) {
  Keccak_HashFinaltimes4(ctx, NULL);
}

static inline void hash_squeeze_x4(hash_context_x4* ctx, uint8_t** buffer, size_t buflen) {
  Keccak_HashSqueezetimes4(ctx, buffer, buflen << 3);
}

static inline void hash_squeeze_x4_4(hash_context_x4* ctx, uint8_t* buffer0, uint8_t* buffer1,
                                     uint8_t* buffer2, uint8_t* buffer3, size_t buflen) {
  uint8_t* buffer[4] = {buffer0, buffer1, buffer2, buffer3};
  hash_squeeze_x4(ctx, buffer, buflen);
}

#define hash_clear_x4(ctx)
#elif !defined(OQS)
/* Instances that work with 4 states in parallel using the base Keccak implementation. */
typedef struct hash_context_x4_s {
  hash_context instances[4];
} hash_context_x4;

static inline void hash_init_x4(hash_context_x4* ctx, unsigned int security_param) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_init(&ctx->instances[i], security_param);
  }
}

static inline void hash_update_x4(hash_context_x4* ctx, const uint8_t** data, size_t size) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_update(&ctx->instances[i], data[i], size);
  }
}

static inline void hash_update_x4_4(hash_context_x4* ctx, const uint8_t* data0,
                                    const uint8_t* data1, const uint8_t* data2,
                                    const uint8_t* data3, size_t size) {
  hash_update(&ctx->instances[0], data0, size);
  hash_update(&ctx->instances[1], data1, size);
  hash_update(&ctx->instances[2], data2, size);
  hash_update(&ctx->instances[3], data3, size);
}

static inline void hash_update_x4_1(hash_context_x4* ctx, const uint8_t* data, size_t size) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_update(&ctx->instances[i], data, size);
  }
}

static inline void hash_init_prefix_x4(hash_context_x4* ctx, unsigned int security_param,
                                       const uint8_t prefix) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_init_prefix(&ctx->instances[i], security_param, prefix);
  }
}

static inline void hash_final_x4(hash_context_x4* ctx) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_final(&ctx->instances[i]);
  }
}

static inline void hash_squeeze_x4(hash_context_x4* ctx, uint8_t** buffer, size_t buflen) {
  for (unsigned int i = 0; i < 4; ++i) {
    hash_squeeze(&ctx->instances[i], buffer[i], buflen);
  }
}

static inline void hash_squeeze_x4_4(hash_context_x4* ctx, uint8_t* buffer0, uint8_t* buffer1,
                                     uint8_t* buffer2, uint8_t* buffer3, size_t buflen) {
  hash_squeeze(&ctx->instances[0], buffer0, buflen);
  hash_squeeze(&ctx->instances[1], buffer1, buflen);
  hash_squeeze(&ctx->instances[2], buffer2, buflen);
  hash_squeeze(&ctx->instances[3], buffer3, buflen);
}

#define hash_clear_x4(ctx)
#endif

static inline void hash_update_x4_uint32_le(hash_context_x4* ctx, uint32_t data) {
  const uint32_t data_le = htole32(data);
  hash_update_x4_1(ctx, (const uint8_t*)&data_le, sizeof(data_le));
}

static inline void hash_update_x4_uint32s_le(hash_context_x4* ctx, const uint32_t data[4]) {
  const uint32_t data0_le = htole16(data[0]);
  const uint32_t data1_le = htole16(data[1]);
  const uint32_t data2_le = htole16(data[2]);
  const uint32_t data3_le = htole16(data[3]);
  hash_update_x4_4(ctx, (const uint8_t*)&data0_le, (const uint8_t*)&data1_le,
                   (const uint8_t*)&data2_le, (const uint8_t*)&data3_le, sizeof(data[0]));
}

#endif
