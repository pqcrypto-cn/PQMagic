/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIG_FIELDS_H
#define SIG_FIELDS_H

#include "macros.h"
#include "endian_compat.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

SIG_BEGIN_C_DECL

typedef uint8_t bf8_t;
typedef uint64_t bf64_t;

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define BF_VALUE(v, i) ((v)[i])

typedef uint64_t bf128_t ATTR_VECTOR_SIZE(16);
typedef uint64_t bf160_t ATTR_VECTOR_SIZE(32);
typedef uint64_t bf192_t ATTR_VECTOR_SIZE(32);
typedef uint64_t bf256_t ATTR_VECTOR_SIZE(32);
typedef uint64_t bf512_t ATTR_VECTOR_SIZE(64);
typedef struct {
  bf128_t inner[3];
} bf384_t;
typedef struct {
  bf192_t inner[3];
} bf576_t;
typedef struct {
  bf256_t inner[3];
} bf768_t;

#define BF128_ALIGN 16
#define BF160_ALIGN 32
#define BF192_ALIGN 32
#define BF256_ALIGN 32
#define BF384_ALIGN 32
#define BF512_ALIGN 64

#define BF128C(x0, x1)                                                                             \
  { x0, x1 }
#define BF160C(x0, x1, x2)                                                                         \
  { x0, x1, x2, UINT64_C(0) }
#define BF192C(x0, x1, x2)                                                                         \
  { x0, x1, x2, UINT64_C(0) }
#define BF256C(x0, x1, x2, x3)                                                                     \
  { x0, x1, x2, x3 }
#define BF512C(x0, x1, x2, x3, x4, x5, x6, x7)                                                     \
  { x0, x1, x2, x3, x4, x5, x6, x7 }
#define BF384C(x0, x1, x2, x3, x4, x5)                                                             \
  {                                                                                                \
    { BF128C(x0, x1), BF128C(x2, x3), BF128C(x4, x5) }                                             \
  }
#define BF576C(x0, x1, x2, x3, x4, x5, x6, x7, x8)                                                 \
  {                                                                                                \
    { BF192C(x0, x1, x2), BF192C(x3, x4, x5), BF192C(x6, x7, x8) }                                 \
  }
#define BF768C(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11)                                   \
  {                                                                                                \
    { BF256C(x0, x1, x2, x3), BF256C(x4, x5, x6, x7), BF256C(x8, x9, x10, x11) }                   \
  }
#else
#define BF_VALUE(v, i) ((v).values[i])

typedef struct {
  uint64_t values[2];
} bf128_t;

typedef struct {
  uint64_t values[3];
} bf160_t;

typedef struct {
  uint64_t values[3];
} bf192_t;

typedef struct {
  uint64_t values[4];
} bf256_t;

typedef struct {
  uint64_t values[8];
} bf512_t;

typedef struct {
  uint64_t values[6];
} bf384_t;

typedef struct {
  uint64_t values[9];
} bf576_t;

typedef struct {
  uint64_t values[12];
} bf768_t;

#define BF128C(x0, x1)                                                                             \
  {                                                                                                \
    { x0, x1 }                                                                                     \
  }
#define BF160C(x0, x1, x2)                                                                         \
  {                                                                                                \
    { x0, x1, x2 }                                                                                 \
  }
#define BF192C(x0, x1, x2)                                                                         \
  {                                                                                                \
    { x0, x1, x2 }                                                                                 \
  }
#define BF256C(x0, x1, x2, x3)                                                                     \
  {                                                                                                \
    { x0, x1, x2, x3 }                                                                             \
  }
#define BF512C(x0, x1, x2, x3, x4, x5, x6, x7)                                                     \
  {                                                                                                \
    { x0, x1, x2, x3, x4, x5, x6, x7 }                                                             \
  }
#define BF384C(x0, x1, x2, x3, x4, x5)                                                             \
  {                                                                                                \
    { x0, x1, x2, x3, x4, x5 }                                                                     \
  }
#define BF576C(x0, x1, x2, x3, x4, x5, x6, x7, x8)                                                 \
  {                                                                                                \
    { x0, x1, x2, x3, x4, x5, x6, x7, x8 }                                                         \
  }
#define BF768C(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11)                                   \
  {                                                                                                \
    { x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11 }                                           \
  }

#define BF128_ALIGN 8
#define BF160_ALIGN 8
#define BF192_ALIGN 8
#define BF256_ALIGN 8
#define BF384_ALIGN 8
#define BF512_ALIGN 8
#endif

#define BF128_NUM_BYTES (128 / 8)
#define BF160_NUM_BYTES (160 / 8)
#define BF192_NUM_BYTES (192 / 8)
#define BF256_NUM_BYTES (256 / 8)
#define BF512_NUM_BYTES (512 / 8)
#define BF384_NUM_BYTES (384 / 8)
#define BF576_NUM_BYTES (576 / 8)
#define BF768_NUM_BYTES (768 / 8)

ATTR_CONST uint8_t bits_sq(uint8_t x);

// GF(2^8) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf8_t bf8_load(const uint8_t* src) {
  return *src;
}

ATTR_ALWAYS_INLINE static inline void bf8_store(uint8_t* dst, bf8_t src) {
  *dst = src;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf8_t bf8_zero(void) {
  return 0;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf8_t bf8_one(void) {
  return 1;
}

ATTR_CONST ATTR_ALWAYS_INLINE inline bf8_t bf8_add(bf8_t lhs, bf8_t rhs) {
  return lhs ^ rhs;
}

ATTR_CONST bf8_t bf8_mul(bf8_t lhs, bf8_t rhs);
ATTR_CONST bf8_t bf8_square(bf8_t lhs);
ATTR_CONST bf8_t bf8_inv(bf8_t lhs);

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf8_t bf8_from_bit(uint8_t bit) {
  return bit & 1;
}

// GF(2^64) implementation

ATTR_PURE ATTR_ALWAYS_INLINE inline bf64_t bf64_load(const uint8_t* src) {
  bf64_t ret;
  memcpy(&ret, src, sizeof(ret));
#if defined(SIG_IS_BIG_ENDIAN)
  ret = le64toh(ret);
#endif
  return ret;
}

ATTR_ALWAYS_INLINE inline void bf64_store(uint8_t* dst, bf64_t src) {
#if defined(SIG_IS_BIG_ENDIAN)
  src = htole64(src);
#endif
  memcpy(dst, &src, sizeof(src));
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf64_t bf64_zero(void) {
  return 0;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf64_t bf64_one(void) {
  return 1;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf64_t bf64_add(bf64_t lhs, bf64_t rhs) {
  return lhs ^ rhs;
}

ATTR_CONST bf64_t bf64_mul(bf64_t lhs, bf64_t rhs);

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf64_t bf64_from_bit(uint8_t bit) {
  return bit & 1;
}

// GF(2^128) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf128_t bf128_load(const uint8_t* src) {
  bf128_t ret;
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF128_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF128_NUM_BYTES);
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf128_store(uint8_t* dst, bf128_t src) {
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF128_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF128_NUM_BYTES);
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf128_t bf128_from_bf64(bf64_t src) {
  bf128_t ret      = BF128C(0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf128_t bf128_from_bf8(bf8_t src) {
  bf128_t ret      = BF128C(0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf128_t bf128_from_bit(uint8_t bit) {
  return bf128_from_bf8(bit & 1);
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf128_t bf128_zero(void) {
  const bf128_t ret = BF128C(0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf128_t bf128_one(void) {
  const bf128_t ret = BF128C(1, 0);
  return ret;
}

#if defined(SIG_TESTS)
ATTR_PURE bf128_t bf128_get_alpha(unsigned int idx);
#endif
ATTR_PURE bf128_t bf128_byte_combine(const bf128_t* x);
ATTR_PURE bf128_t bf128_byte_combine_bits(uint8_t x);
void bf128_sq_bit(bf128_t* out_tag, const bf128_t* in_tag);
void bf128_sq_bit_inplace(bf128_t* tag);
ATTR_PURE bf128_t bf128_byte_combine_sq(const bf128_t* x);
ATTR_PURE bf128_t bf128_byte_combine_bits_sq(uint8_t x);

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf128_add(lhs, rhs) ((lhs) ^ (rhs))
#else
ATTR_CONST static inline bf128_t bf128_add(bf128_t lhs, bf128_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf128_t bf128_mul(bf128_t lhs, bf128_t rhs);
ATTR_CONST bf128_t bf128_mul_64(bf128_t lhs, bf64_t rhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf128_mul_bit(lhs, rhs) ((lhs) & -((uint64_t)(rhs) & 1))
#else
ATTR_CONST bf128_t bf128_mul_bit(bf128_t lhs, uint8_t rhs);
#endif
ATTR_PURE bf128_t bf128_sum_poly(const bf128_t* xs);
ATTR_PURE bf128_t bf128_sum_poly_bits(const uint8_t* xs);

// GF(2^160) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf160_t bf160_load(const uint8_t* src) {
  bf160_t ret;
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF160_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
  uint32_t top;
  memcpy(&top, src, sizeof(top));
  BF_VALUE(ret, 2) = le32toh(top);
#else
  memset(&ret, 0, sizeof(ret));
  memcpy(&ret, src, BF160_NUM_BYTES);
#endif
#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(ret, 3) = 0;
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf160_store(uint8_t* dst, bf160_t src) {
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != 2; ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
  uint32_t top = htole32((uint32_t)BF_VALUE(src, 2));
  memcpy(dst, &top, sizeof(top));
#else
  memcpy(dst, &src, BF160_NUM_BYTES);
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf160_t bf160_from_bf64(bf64_t src) {
  bf160_t ret      = BF160C(0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf160_t bf160_from_bf8(bf8_t src) {
  bf160_t ret      = BF160C(0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf160_t bf160_from_bit(uint8_t bit) {
  return bf160_from_bf8(bit & 1);
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf160_t bf160_zero(void) {
  const bf160_t ret = BF160C(0, 0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf160_t bf160_one(void) {
  const bf160_t ret = BF160C(1, 0, 0);
  return ret;
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf160_add(lhs, rhs) ((lhs) ^ (rhs))
#else
ATTR_CONST static inline bf160_t bf160_add(bf160_t lhs, bf160_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf160_t bf160_mul(bf160_t lhs, bf160_t rhs);
ATTR_CONST bf160_t bf160_mul_64(bf160_t lhs, bf64_t rhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf160_mul_bit(lhs, rhs) ((lhs) & -((uint64_t)(rhs) & 1))
#else
ATTR_CONST bf160_t bf160_mul_bit(bf160_t lhs, uint8_t rhs);
#endif
ATTR_PURE bf160_t bf160_sum_poly(const bf160_t* xs);
ATTR_PURE bf160_t bf160_sum_poly_bits(const uint8_t* xs);

// GF(2^192) implemenation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf192_t bf192_load(const uint8_t* src) {
  bf192_t ret;
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF192_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF192_NUM_BYTES);
#endif
#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(ret, 3) = 0;
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf192_store(uint8_t* dst, bf192_t src) {
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF192_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF192_NUM_BYTES);
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf192_t bf192_from_bf64(bf64_t src) {
  bf192_t ret      = BF192C(0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf192_t bf192_from_bf8(bf8_t src) {
  bf192_t ret      = BF192C(0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf192_t bf192_from_bit(uint8_t bit) {
  return bf192_from_bf8(bit & 1);
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf192_t bf192_zero(void) {
  const bf192_t ret = BF192C(0, 0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf192_t bf192_one(void) {
  const bf192_t ret = BF192C(1, 0, 0);
  return ret;
}

#if defined(SIG_TESTS)
ATTR_PURE bf192_t bf192_get_alpha(unsigned int idx);
#endif
ATTR_PURE bf192_t bf192_byte_combine(const bf192_t* x);
ATTR_PURE bf192_t bf192_byte_combine_bits(uint8_t x);
void bf192_sq_bit(bf192_t* out_tag, const bf192_t* in_tag);
void bf192_sq_bit_inplace(bf192_t* tag);
ATTR_PURE bf192_t bf192_byte_combine_sq(const bf192_t* x);
ATTR_PURE bf192_t bf192_byte_combine_bits_sq(uint8_t x);

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf192_add(lhs, rhs) ((lhs) ^ (rhs))
#else
ATTR_CONST static inline bf192_t bf192_add(bf192_t lhs, bf192_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf192_t bf192_mul(bf192_t lhs, bf192_t rhs);
ATTR_CONST bf192_t bf192_mul_64(bf192_t lhs, bf64_t rhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf192_mul_bit(lhs, rhs) ((lhs) & -((uint64_t)(rhs) & 1))
#else
ATTR_CONST bf192_t bf192_mul_bit(bf192_t lhs, uint8_t rhs);
#endif
ATTR_PURE bf192_t bf192_sum_poly(const bf192_t* xs);
ATTR_PURE bf192_t bf192_sum_poly_bits(const uint8_t* xs);

// GF(2^256) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf256_t bf256_load(const uint8_t* src) {
  bf256_t ret;
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF256_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF256_NUM_BYTES);
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf256_store(uint8_t* dst, bf256_t src) {
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF256_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF256_NUM_BYTES);
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf256_t bf256_from_bf64(bf64_t src) {
  bf256_t ret      = BF256C(0, 0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf256_t bf256_from_bf8(bf8_t src) {
  bf256_t ret      = BF256C(0, 0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf256_t bf256_from_bit(uint8_t bit) {
  return bf256_from_bf8(bit & 1);
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf256_t bf256_zero(void) {
  const bf256_t ret = BF256C(0, 0, 0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf256_t bf256_one(void) {
  const bf256_t ret = BF256C(1, 0, 0, 0);
  return ret;
}

#if defined(SIG_TESTS)
ATTR_PURE bf256_t bf256_get_alpha(unsigned int idx);
#endif
ATTR_PURE bf256_t bf256_byte_combine(const bf256_t* x);
ATTR_PURE bf256_t bf256_byte_combine_bits(uint8_t x);
void bf256_sq_bit(bf256_t* out_tag, const bf256_t* in_tag);
void bf256_sq_bit_inplace(bf256_t* tag);
ATTR_PURE bf256_t bf256_byte_combine_sq(const bf256_t* x);
ATTR_PURE bf256_t bf256_byte_combine_bits_sq(uint8_t x);

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf256_add(lhs, rhs) ((lhs) ^ (rhs))
#else
ATTR_CONST static inline bf256_t bf256_add(bf256_t lhs, bf256_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf256_t bf256_mul(bf256_t lhs, bf256_t rhs);
ATTR_CONST bf256_t bf256_mul_64(bf256_t lhs, bf64_t rhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf256_mul_bit(lhs, rhs) ((lhs) & -((uint64_t)(rhs) & 1))
#else
ATTR_CONST bf256_t bf256_mul_bit(bf256_t lhs, uint8_t rhs);
#endif
ATTR_PURE bf256_t bf256_sum_poly(const bf256_t* xs);
ATTR_PURE bf256_t bf256_sum_poly_bits(const uint8_t* xs);

// GF(2^384) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf384_t bf384_load(const uint8_t* src) {
  bf384_t ret;
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int i = 0; i != BF384_NUM_BYTES / BF128_NUM_BYTES; ++i, src += BF128_NUM_BYTES) {
    ret.inner[i] = bf128_load(src);
  }
#else
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF384_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF384_NUM_BYTES);
#endif
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf384_store(uint8_t* dst, bf384_t src) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int i = 0; i != BF384_NUM_BYTES / BF128_NUM_BYTES; ++i, dst += BF128_NUM_BYTES) {
    bf128_store(dst, src.inner[i]);
  }
#else
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF384_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF384_NUM_BYTES);
#endif
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf384_t bf384_zero(void) {
  const bf384_t ret = BF384C(0, 0, 0, 0, 0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf384_t bf384_one(void) {
  const bf384_t ret = BF384C(1, 0, 0, 0, 0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf384_t bf384_from_bit(uint8_t bit) {
  return bit ? bf384_one() : bf384_zero();
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
ATTR_CONST static inline bf384_t bf384_add(bf384_t lhs, bf384_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.inner); ++i) {
    lhs.inner[i] ^= rhs.inner[i];
  }
  return lhs;
}
#else
ATTR_CONST static inline bf384_t bf384_add(bf384_t lhs, bf384_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf384_t bf384_mul_128(bf384_t lhs, bf128_t rhs);
ATTR_CONST bf384_t bf384_mul(bf384_t lhs, bf384_t rhs);
ATTR_CONST bf384_t bf384_mul_bit(bf384_t lhs, uint8_t rhs);
ATTR_PURE bf384_t bf384_sum_poly(const bf384_t* xs);
ATTR_PURE bf384_t bf384_sum_poly_bits(const uint8_t* xs);

// GF(2^512) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf512_t bf512_load(const uint8_t* src) {
  bf512_t ret;
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF512_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF512_NUM_BYTES);
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf512_store(uint8_t* dst, bf512_t src) {
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF512_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF512_NUM_BYTES);
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf512_t bf512_from_bf64(bf64_t src) {
  bf512_t ret      = BF512C(0, 0, 0, 0, 0, 0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf512_t bf512_from_bf8(bf8_t src) {
  bf512_t ret      = BF512C(0, 0, 0, 0, 0, 0, 0, 0);
  BF_VALUE(ret, 0) = src;
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf512_t bf512_from_bit(uint8_t bit) {
  return bf512_from_bf8(bit & 1);
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf512_t bf512_zero(void) {
  const bf512_t ret = BF512C(0, 0, 0, 0, 0, 0, 0, 0);
  return ret;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf512_t bf512_one(void) {
  const bf512_t ret = BF512C(1, 0, 0, 0, 0, 0, 0, 0);
  return ret;
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf512_add(lhs, rhs) ((lhs) ^ (rhs))
#else
ATTR_CONST static inline bf512_t bf512_add(bf512_t lhs, bf512_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf512_t bf512_mul(bf512_t lhs, bf512_t rhs);
ATTR_CONST bf512_t bf512_mul_64(bf512_t lhs, bf64_t rhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf512_mul_bit(lhs, rhs) ((lhs) & -((uint64_t)(rhs) & 1))
#else
ATTR_CONST bf512_t bf512_mul_bit(bf512_t lhs, uint8_t rhs);
#endif
ATTR_PURE bf512_t bf512_sum_poly(const bf512_t* xs);
ATTR_PURE bf512_t bf512_sum_poly_bits(const uint8_t* xs);

// GF(2^576) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf576_t bf576_load(const uint8_t* src) {
  bf576_t ret;
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int i = 0; i != BF576_NUM_BYTES / BF192_NUM_BYTES; ++i, src += BF192_NUM_BYTES) {
    ret.inner[i] = bf192_load(src);
  }
#else
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF576_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF576_NUM_BYTES);
#endif
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf576_store(uint8_t* dst, bf576_t src) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int i = 0; i != BF576_NUM_BYTES / BF192_NUM_BYTES; ++i, dst += BF192_NUM_BYTES) {
    bf192_store(dst, src.inner[i]);
  }
#else
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF576_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF576_NUM_BYTES);
#endif
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf576_t bf576_zero(void) {
  const bf576_t ret = BF576C(0, 0, 0, 0, 0, 0, 0, 0, 0);
  return ret;
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
ATTR_CONST static inline bf576_t bf576_add(bf576_t lhs, bf576_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.inner); ++i) {
    lhs.inner[i] ^= rhs.inner[i];
  }
  return lhs;
}
#else
ATTR_CONST static inline bf576_t bf576_add(bf576_t lhs, bf576_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf576_t bf576_mul_192(bf576_t lhs, bf192_t rhs);

// GF(2^768) implementation

ATTR_PURE ATTR_ALWAYS_INLINE static inline bf768_t bf768_load(const uint8_t* src) {
  bf768_t ret;
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int i = 0; i != BF768_NUM_BYTES / BF256_NUM_BYTES; ++i, src += BF256_NUM_BYTES) {
    ret.inner[i] = bf256_load(src);
  }
#else
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF768_NUM_BYTES / sizeof(uint64_t); ++i, src += sizeof(uint64_t)) {
    memcpy(&BF_VALUE(ret, i), src, sizeof(uint64_t));
    BF_VALUE(ret, i) = le64toh(BF_VALUE(ret, i));
  }
#else
  memcpy(&ret, src, BF768_NUM_BYTES);
#endif
#endif
  return ret;
}

ATTR_ALWAYS_INLINE static inline void bf768_store(uint8_t* dst, bf768_t src) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int i = 0; i != BF768_NUM_BYTES / BF256_NUM_BYTES; ++i, dst += BF256_NUM_BYTES) {
    bf256_store(dst, src.inner[i]);
  }
#else
#if defined(SIG_IS_BIG_ENDIAN)
  for (unsigned int i = 0; i != BF768_NUM_BYTES / sizeof(uint64_t); ++i, dst += sizeof(uint64_t)) {
    uint64_t tmp = htole64(BF_VALUE(src, i));
    memcpy(dst, &tmp, sizeof(tmp));
  }
#else
  memcpy(dst, &src, BF768_NUM_BYTES);
#endif
#endif
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline bf768_t bf768_zero(void) {
  const bf768_t ret = BF768C(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  return ret;
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
ATTR_CONST static inline bf768_t bf768_add(bf768_t lhs, bf768_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.inner); ++i) {
    lhs.inner[i] ^= rhs.inner[i];
  }
  return lhs;
}
#else
ATTR_CONST static inline bf768_t bf768_add(bf768_t lhs, bf768_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] ^= rhs.values[i];
  }
  return lhs;
}
#endif

ATTR_CONST bf768_t bf768_mul_256(bf768_t lhs, bf256_t rhs);

SIG_END_C_DECL

#endif
