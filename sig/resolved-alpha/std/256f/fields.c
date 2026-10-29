/*
 *  SPDX-License-Identifier: MIT
 */

#include "fields.h"
#include "utils.h"

// GF(2^8) with X^8 + X^4 + X^3 + X^1 + 1
#define bf8_modulus (UINT8_C((1 << 4) | (1 << 3) | (1 << 1) | 1))
// GF(2^64) with X^64 + X^4 + X^3 + X^1 + 1
#define bf64_modulus (UINT64_C((1 << 4) | (1 << 3) | (1 << 1) | 1))
// GF(2^128) with X^128 + X^7 + X^2 + X^1 + 1
#define bf128_modulus (UINT64_C((1 << 7) | (1 << 2) | (1 << 1) | 1))
// GF(2^192) with X^192 + X^7 + X^2 + X^1 + 1
#define bf192_modulus (UINT64_C((1 << 7) | (1 << 2) | (1 << 1) | 1))
// GF(2^160) with X^160 + X^5 + X^3 + X^2 + 1
#define bf160_modulus (UINT64_C((1 << 5) | (1 << 3) | (1 << 2) | 1))
// GF(2^256) with X^256 + X^10 + X^5 + X^2 + 1
#define bf256_modulus (UINT64_C((1 << 10) | (1 << 5) | (1 << 2) | 1))
// GF(2^384) with X^384 + X^16 + X^15 + X^6 + 1
#define bf384_modulus (UINT64_C((1 << 16) | (1 << 15) | (1 << 6) | 1))
// GF(2^512) with X^512 + X^8 + X^5 + X^2 + 1
#define bf512_modulus (UINT64_C((1 << 8) | (1 << 5) | (1 << 2) | 1))
// GF(2^576) with X^576 + X^13 + X^4 + X^3 + 1
#define bf576_modulus (UINT64_C((1 << 13) | (1 << 4) | (1 << 3) | 1))
// GF(2^768) with X^768 + X^19 + X^17 + X^4 + 1
#define bf768_modulus (UINT64_C((1 << 19) | (1 << 17) | (1 << 4) | 1))

#define U64C(x0, x1, x2, x3, x4, x5, x6, x7)                                                       \
  ((UINT64_C(x7) << 56) | (UINT64_C(x6) << 48) | (UINT64_C(x5) << 40) | (UINT64_C(x4) << 32) |     \
   (UINT64_C(x3) << 24) | (UINT64_C(x2) << 16) | (UINT64_C(x1) << 8) | UINT64_C(x0))

ATTR_CONST uint8_t bits_sq(uint8_t x) {
  uint8_t res = set_bit(get_bit(x, 0) ^ get_bit(x, 4) ^ get_bit(x, 6), 0);
  res |= set_bit(get_bit(x, 4) ^ get_bit(x, 6) ^ get_bit(x, 7), 1);
  res |= set_bit(get_bit(x, 1) ^ get_bit(x, 5), 2);
  res |= set_bit(get_bit(x, 4) ^ get_bit(x, 5) ^ get_bit(x, 6) ^ get_bit(x, 7), 3);
  res |= set_bit(get_bit(x, 2) ^ get_bit(x, 4) ^ get_bit(x, 7), 4);
  res |= set_bit(get_bit(x, 5) ^ get_bit(x, 6), 5);
  res |= set_bit(get_bit(x, 3) ^ get_bit(x, 5), 6);
  res |= set_bit(get_bit(x, 6) ^ get_bit(x, 7), 7);
  return res;
}

// GF(2^8) implementation

bf8_t bf8_mul(bf8_t lhs, bf8_t rhs) {
  bf8_t result = -(rhs & 1) & lhs;
  for (unsigned int idx = 1; idx < 8; ++idx) {
    const uint8_t mask = -((lhs >> 7) & 1);
    lhs                = (lhs << 1) ^ (mask & bf8_modulus);
    result ^= -((rhs >> idx) & 1) & lhs;
  }
  return result;
}

bf8_t bf8_square(bf8_t lhs) {
  bf8_t result = -(lhs & 1) & lhs;
  bf8_t rhs    = lhs;
  for (unsigned int idx = 1; idx < 8; ++idx) {
    const uint8_t mask = -((lhs >> 7) & 1);
    lhs                = (lhs << 1) ^ (mask & bf8_modulus);
    result ^= -((rhs >> idx) & 1) & lhs;
  }
  return result;
}

bf8_t bf8_inv(bf8_t in) {
  const bf8_t t2   = bf8_square(in);
  const bf8_t t3   = bf8_mul(in, t2);
  const bf8_t t5   = bf8_mul(t3, t2);
  const bf8_t t7   = bf8_mul(t5, t2);
  const bf8_t t14  = bf8_square(t7);
  const bf8_t t28  = bf8_square(t14);
  const bf8_t t56  = bf8_square(t28);
  const bf8_t t63  = bf8_mul(t56, t7);
  const bf8_t t126 = bf8_square(t63);
  const bf8_t t252 = bf8_square(t126);
  return bf8_mul(t252, t2);
}

// GF(2^64) implementation

bf64_t bf64_mul(bf64_t lhs, bf64_t rhs) {
  bf64_t result = (-(rhs & 1)) & lhs;
  for (unsigned int idx = 1; idx != 64; ++idx) {
    const uint64_t mask = -((lhs >> 63) & 1);
    lhs                 = (lhs << 1) ^ (mask & bf64_modulus);
    result ^= (-((rhs >> idx) & 1)) & lhs;
  }
  return result;
}

#define bf64_bit_to_mask(value, bit) -((((uint64_t)(value)) >> (bit)) & 1)

// GF(2^128) implementation

static const bf128_t bf128_alpha[7] = {
    BF128C(U64C(0x0d, 0xce, 0x60, 0x55, 0xac, 0xe8, 0x3f, 0xa1),
           U64C(0x1c, 0x9a, 0x97, 0xa9, 0x55, 0x85, 0x3d, 0x05)),
    BF128C(U64C(0xe1, 0xae, 0x88, 0x34, 0xca, 0x59, 0x77, 0xec),
           U64C(0x84, 0xbb, 0xbf, 0x9c, 0x43, 0xb7, 0xf4, 0x4c)),
    BF128C(U64C(0xa8, 0x46, 0x39, 0x36, 0xae, 0x02, 0xcf, 0xbf),
           U64C(0xc6, 0xd2, 0x51, 0x7d, 0x4f, 0x60, 0xad, 0x35)),
    BF128C(U64C(0x49, 0x98, 0x2e, 0x3c, 0x48, 0x30, 0x83, 0x6b),
           U64C(0xfe, 0x22, 0xa2, 0x40, 0x46, 0x36, 0xcb, 0x0d)),
    BF128C(U64C(0xb4, 0x82, 0x1b, 0x7b, 0x27, 0x49, 0x2b, 0x25),
           U64C(0xa5, 0xde, 0x88, 0x1a, 0xe1, 0x10, 0x98, 0x54)),
    BF128C(U64C(0x22, 0xff, 0x21, 0x25, 0xef, 0xf2, 0x2b, 0xc7),
           U64C(0x75, 0x1f, 0x0c, 0x6c, 0x68, 0xa5, 0x81, 0xd6)),
    BF128C(U64C(0xbc, 0xf9, 0x36, 0xe1, 0x94, 0x8e, 0x7a, 0x7a),
           U64C(0xe0, 0x8f, 0xb7, 0x4f, 0x1a, 0x31, 0x50, 0x09)),
};

#if defined(SIG_TESTS)
bf128_t bf128_get_alpha(unsigned int idx) {
  return bf128_alpha[idx];
}
#endif

bf128_t bf128_byte_combine(const bf128_t* x) {
  bf128_t bf_out = x[0];
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf128_add(bf_out, bf128_mul(x[i], bf128_alpha[i - 1]));
  }
  return bf_out;
}

void bf128_sq_bit(bf128_t* out_tag, const bf128_t* in_tag) {
  out_tag[0] = bf128_add(in_tag[0], bf128_add(in_tag[4], in_tag[6]));
  out_tag[1] = bf128_add(in_tag[4], bf128_add(in_tag[6], in_tag[7]));
  out_tag[2] = bf128_add(in_tag[1], in_tag[5]);
  out_tag[3] = bf128_add(bf128_add(in_tag[4], in_tag[5]), bf128_add(in_tag[6], in_tag[7]));
  out_tag[4] = bf128_add(in_tag[2], bf128_add(in_tag[4], in_tag[7]));
  out_tag[5] = bf128_add(in_tag[5], in_tag[6]);
  out_tag[6] = bf128_add(in_tag[3], in_tag[5]);
  out_tag[7] = bf128_add(in_tag[6], in_tag[7]);
}

void bf128_sq_bit_inplace(bf128_t* tag) {
  tag[0]           = bf128_add(tag[0], bf128_add(tag[4], tag[6]));
  const bf128_t i1 = tag[1];
  tag[1]           = bf128_add(tag[4], bf128_add(tag[6], tag[7]));
  const bf128_t i2 = tag[2];
  tag[2]           = bf128_add(i1, tag[5]);
  const bf128_t i3 = tag[3];
  tag[3]           = bf128_add(bf128_add(tag[4], tag[5]), bf128_add(tag[6], tag[7]));
  tag[4]           = bf128_add(i2, bf128_add(tag[4], tag[7]));
  const bf128_t i5 = tag[5];
  tag[5]           = bf128_add(tag[5], tag[6]);
  const bf128_t i6 = tag[6];
  tag[6]           = bf128_add(i3, i5);
  tag[7]           = bf128_add(i6, tag[7]);
}

bf128_t bf128_byte_combine_sq(const bf128_t* x) {
  bf128_t bf_tmp[8];
  bf128_sq_bit(bf_tmp, x);
  return bf128_byte_combine(bf_tmp);
}

bf128_t bf128_byte_combine_bits(uint8_t x) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  return bf128_from_bit(get_bit(x, 0)) ^ bf128_mul_bit(bf128_alpha[1 - 1], get_bit(x, 1)) ^
         bf128_mul_bit(bf128_alpha[2 - 1], get_bit(x, 2)) ^
         bf128_mul_bit(bf128_alpha[3 - 1], get_bit(x, 3)) ^
         bf128_mul_bit(bf128_alpha[4 - 1], get_bit(x, 4)) ^
         bf128_mul_bit(bf128_alpha[5 - 1], get_bit(x, 5)) ^
         bf128_mul_bit(bf128_alpha[6 - 1], get_bit(x, 6)) ^
         bf128_mul_bit(bf128_alpha[7 - 1], get_bit(x, 7));
#else
  bf128_t bf_out = bf128_from_bit(get_bit(x, 0));
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf128_add(bf_out, bf128_mul_bit(bf128_alpha[i - 1], get_bit(x, i)));
  }
  return bf_out;
#endif
}

bf128_t bf128_byte_combine_bits_sq(uint8_t x) {
  return bf128_byte_combine_bits(bits_sq(x));
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf128_and_64(lhs, rhs) ((lhs) & (rhs))
#else
ATTR_CONST
static inline bf128_t bf128_and_64(bf128_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
#define bf128_shift_right_64(v1) __builtin_shufflevector((v1), bf128_zero(), 2, 0)
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf128_t bf128_shift_right_64(bf128_t v1) {
  bf128_t ret;
  BF_VALUE(ret, 0) = 0;
  BF_VALUE(ret, 1) = BF_VALUE(v1, 0);
  return ret;
}
#endif

#define bf128_shift_left_1(value) ((value << 1) | bf128_shift_right_64(value >> 63))
#else
ATTR_CONST
static inline bf128_t bf128_shift_left_1(bf128_t value) {
  value.values[1] = (value.values[1] << 1) | (value.values[0] >> 63);
  value.values[0] = value.values[0] << 1;
  return value;
}
#endif

ATTR_CONST
static inline uint64_t bf128_bit_to_uint64_mask(bf128_t value, unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}

static void poly64_mul(uint64_t* z1, uint64_t* z0, uint64_t x0, uint64_t y0) {
  const uint64_t C0 = UINT64_C(0x5555555555555555);
  const uint64_t C1 = UINT64_C(0x3333333333333333);
  const uint64_t C2 = UINT64_C(0x0f0f0f0f0f0f0f0f);
  const uint64_t C3 = UINT64_C(0x00ff00ff00ff00ff);
  const uint64_t C4 = UINT64_C(0x0000ffff0000ffff);
  const uint64_t C5 = UINT64_C(0x00000000ffffffff);
  uint64_t x1, x2, x3, x4, x5, x6, x7;
  uint64_t y1, y2, y3, y4, y5, y6, y7;
  uint64_t f0, f1, f2, f3, f4, f5, f6, f7;
  uint64_t g0, g1, g2, g3, g4, g5, g6, g7;
  uint64_t s, t;

  x1 = x0 ^ (x0 >> 32);
  x2 = ((x0 ^ (x0 >> 16)) & C4) | ((x1 ^ (x1 << 16)) & (C4 << 16));
  x3 = ((x0 ^ (x0 >> 8)) & C3) | ((x1 ^ (x1 << 8)) & (C3 << 8));
  x4 = x2 ^ (x2 >> 8);
  x5 = ((x0 ^ (x0 >> 4)) & C2) | ((x1 ^ (x1 << 4)) & (C2 << 4));
  x6 = ((x2 ^ (x2 >> 4)) & C2) | ((x3 ^ (x3 << 4)) & (C2 << 4));
  x7 = x4 ^ (x4 >> 4);
  s = ((x0 >> 2) ^ x2) & C1;
  x0 ^= s << 2;
  x2 ^= s;
  s = ((x1 >> 2) ^ x3) & C1;
  x1 ^= s << 2;
  x3 ^= s;
  s = ((x4 >> 2) ^ x6) & C1;
  x4 ^= s << 2;
  x6 ^= s;
  s = ((x5 >> 2) ^ x7) & C1;
  x5 ^= s << 2;
  x7 ^= s;
  s = ((x0 >> 1) ^ x1) & C0;
  x0 ^= s << 1;
  x1 ^= s;
  s = ((x2 >> 1) ^ x3) & C0;
  x2 ^= s << 1;
  x3 ^= s;
  s = ((x4 >> 1) ^ x5) & C0;
  x4 ^= s << 1;
  x5 ^= s;
  s = ((x6 >> 1) ^ x7) & C0;
  x6 ^= s << 1;
  x7 ^= s;

  y1 = y0 ^ (y0 >> 32);
  y2 = ((y0 ^ (y0 >> 16)) & C4) | ((y1 ^ (y1 << 16)) & (C4 << 16));
  y3 = ((y0 ^ (y0 >> 8)) & C3) | ((y1 ^ (y1 << 8)) & (C3 << 8));
  y4 = y2 ^ (y2 >> 8);
  y5 = ((y0 ^ (y0 >> 4)) & C2) | ((y1 ^ (y1 << 4)) & (C2 << 4));
  y6 = ((y2 ^ (y2 >> 4)) & C2) | ((y3 ^ (y3 << 4)) & (C2 << 4));
  y7 = y4 ^ (y4 >> 4);
  s = ((y0 >> 2) ^ y2) & C1;
  y0 ^= s << 2;
  y2 ^= s;
  s = ((y1 >> 2) ^ y3) & C1;
  y1 ^= s << 2;
  y3 ^= s;
  s = ((y4 >> 2) ^ y6) & C1;
  y4 ^= s << 2;
  y6 ^= s;
  s = ((y5 >> 2) ^ y7) & C1;
  y5 ^= s << 2;
  y7 ^= s;
  s = ((y0 >> 1) ^ y1) & C0;
  y0 ^= s << 1;
  y1 ^= s;
  s = ((y2 >> 1) ^ y3) & C0;
  y2 ^= s << 1;
  y3 ^= s;
  s = ((y4 >> 1) ^ y5) & C0;
  y4 ^= s << 1;
  y5 ^= s;
  s = ((y6 >> 1) ^ y7) & C0;
  y6 ^= s << 1;
  y7 ^= s;

  f0 = x0 & y0;
  f1 = (x0 & y1) ^ (x1 & y0);
  f2 = (x0 & y2) ^ (x1 & y1) ^ (x2 & y0);
  f3 = (x0 & y3) ^ (x1 & y2) ^ (x2 & y1) ^ (x3 & y0);
  g0 = (x1 & y3) ^ (x2 & y2) ^ (x3 & y1);
  g1 = (x2 & y3) ^ (x3 & y2);
  g2 = x3 & y3;

  f4 = x4 & y4;
  f5 = (x4 & y5) ^ (x5 & y4);
  f6 = (x4 & y6) ^ (x5 & y5) ^ (x6 & y4);
  f7 = (x4 & y7) ^ (x5 & y6) ^ (x6 & y5) ^ (x7 & y4);
  g4 = (x5 & y7) ^ (x6 & y6) ^ (x7 & y5);
  g5 = (x6 & y7) ^ (x7 & y6);
  g6 = x7 & y7;

  s = ((f0 >> 1) ^ f1) & C0;
  f0 ^= s << 1;
  f1 ^= s;
  s = ((f2 >> 1) ^ f3) & C0;
  f2 ^= s << 1;
  f3 ^= s;
  s = ((f0 >> 2) ^ f2) & C1;
  f0 ^= s << 2;
  f2 ^= s;
  s = ((f1 >> 2) ^ f3) & C1;
  f1 ^= s << 2;
  f3 ^= s;
  s = ((g0 >> 1) ^ g1) & C0;
  g0 ^= s << 1;
  g1 ^= s;
  s = (g2 >> 1) & C0;
  g2 ^= s << 1;
  g3 = s;
  s = ((g0 >> 2) ^ g2) & C1;
  g0 ^= s << 2;
  g2 ^= s;
  s = ((g1 >> 2) ^ g3) & C1;
  g1 ^= s << 2;
  g3 ^= s;

  s = ((f4 >> 1) ^ f5) & C0;
  f4 ^= s << 1;
  f5 ^= s;
  s = ((f6 >> 1) ^ f7) & C0;
  f6 ^= s << 1;
  f7 ^= s;
  s = ((f4 >> 2) ^ f6) & C1;
  f4 ^= s << 2;
  f6 ^= s;
  s = ((f5 >> 2) ^ f7) & C1;
  f5 ^= s << 2;
  f7 ^= s;
  s = ((g4 >> 1) ^ g5) & C0;
  g4 ^= s << 1;
  g5 ^= s;
  s = (g6 >> 1) & C0;
  g6 ^= s << 1;
  g7 = s;
  s = ((g4 >> 2) ^ g6) & C1;
  g4 ^= s << 2;
  g6 ^= s;
  s = ((g5 >> 2) ^ g7) & C1;
  g5 ^= s << 2;
  g7 ^= s;

  t = f0 ^ g0;
  f0 ^= ((f5 ^ t) & C2) << 4;
  g0 ^= (g5 ^ (t >> 4)) & C2;
  t = f1 ^ g1;
  f1 ^= (f5 ^ (t << 4)) & (C2 << 4);
  g1 ^= ((g5 ^ t) >> 4) & C2;
  t = f2 ^ g2;
  f2 ^= ((f6 ^ t) & C2) << 4;
  g2 ^= (g6 ^ (t >> 4)) & C2;
  t = f3 ^ g3;
  f3 ^= (f6 ^ (t << 4)) & (C2 << 4);
  g3 ^= ((g6 ^ t) >> 4) & C2;
  t = f4 ^ g4;
  f4 ^= ((f7 ^ t) & C2) << 4;
  g4 ^= (g7 ^ (t >> 4)) & C2;

  t = f0 ^ g0;
  f0 ^= ((f3 ^ t) & C3) << 8;
  g0 ^= (g3 ^ (t >> 8)) & C3;
  t = f1 ^ g1;
  f1 ^= (f3 ^ (t << 8)) & (C3 << 8);
  g1 ^= ((g3 ^ t) >> 8) & C3;
  t = f2 ^ g2;
  f2 ^= ((f4 ^ t) & C3) << 8;
  g2 ^= (g4 ^ (t >> 8)) & C3;

  t = f0 ^ g0;
  f0 ^= ((f2 ^ t) & C4) << 16;
  g0 ^= (g2 ^ (t >> 16)) & C4;
  t = f1 ^ g1;
  f1 ^= (f2 ^ (t << 16)) & (C4 << 16);
  g1 ^= ((g2 ^ t) >> 16) & C4;

  t = f0 ^ g0;
  f0 ^= ((t ^ f1) & C5) << 32;
  g0 ^= ((t >> 32) ^ g1) & C5;

  *z0 = f0;
  *z1 = g0;
}

static bf128_t bf128_reduce_product(uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3) {
  uint64_t t0;
  bf128_t result = BF128C(0, 0);

  t0 = p2 ^ ((p3 >> 57) ^ (p3 >> 62) ^ (p3 >> 63));

  BF_VALUE(result, 1) = p1 ^ p3;
  BF_VALUE(result, 1) ^= (p3 << 7) | (t0 >> 57);
  BF_VALUE(result, 1) ^= (p3 << 2) | (t0 >> 62);
  BF_VALUE(result, 1) ^= (p3 << 1) | (t0 >> 63);

  BF_VALUE(result, 0) = p0 ^ t0;
  BF_VALUE(result, 0) ^= (t0 << 7);
  BF_VALUE(result, 0) ^= (t0 << 2);
  BF_VALUE(result, 0) ^= (t0 << 1);

  return result;
}

// Unreduced 128-bit polynomial multiplication: (a0,a1) * (b0,b1) -> r[0..3]
// Uses 3 poly64_mul calls (Karatsuba)
static void poly128_mul(uint64_t r[4], const uint64_t a[2], const uint64_t b[2]) {
  uint64_t ll_h, ll_l, hh_h, hh_l, cc_h, cc_l;
  poly64_mul(&ll_h, &ll_l, a[0], b[0]);
  poly64_mul(&hh_h, &hh_l, a[1], b[1]);
  poly64_mul(&cc_h, &cc_l, a[0] ^ a[1], b[0] ^ b[1]);
  cc_l ^= ll_l ^ hh_l;
  cc_h ^= ll_h ^ hh_h;
  r[0] = ll_l;
  r[1] = ll_h ^ cc_l;
  r[2] = hh_l ^ cc_h;
  r[3] = hh_h;
}

// Unreduced 256-bit polynomial multiplication: a[0..3] * b[0..3] -> r[0..7]
// Uses 3 poly128_mul calls (Karatsuba) = 9 poly64_mul
static void poly256_mul(uint64_t r[8], const uint64_t a[4], const uint64_t b[4]) {
  uint64_t lo[4], hi[4], mid[4];
  poly128_mul(lo, &a[0], &b[0]);      // low halves
  poly128_mul(hi, &a[2], &b[2]);      // high halves
  uint64_t ta[2] = {a[0] ^ a[2], a[1] ^ a[3]};
  uint64_t tb[2] = {b[0] ^ b[2], b[1] ^ b[3]};
  poly128_mul(mid, ta, tb);           // cross
  for (unsigned int i = 0; i < 4; ++i) mid[i] ^= lo[i] ^ hi[i];
  r[0] = lo[0]; r[1] = lo[1];
  r[2] = lo[2] ^ mid[0]; r[3] = lo[3] ^ mid[1];
  r[4] = hi[0] ^ mid[2]; r[5] = hi[1] ^ mid[3];
  r[6] = hi[2]; r[7] = hi[3];
}

// Unreduced 192-bit polynomial multiplication: a[0..2] * b[0..2] -> r[0..5]
// Uses 6 poly64_mul calls (3-way Karatsuba)
static void poly192_mul(uint64_t r[6], const uint64_t a[3], const uint64_t b[3]) {
  uint64_t t[3], temp[6];

  poly64_mul(&t[0], &temp[0], a[0], b[0]);
  poly64_mul(&t[2], &t[1], a[1], b[1]);
  t[0] ^= t[1];

  poly64_mul(&temp[5], &t[1], a[2], b[2]);
  t[1] ^= t[2];

  temp[1] = t[0] ^ temp[0];
  temp[2] = t[1] ^ temp[1];
  temp[4] = temp[5] ^ t[1];
  temp[3] = temp[4] ^ t[0];

  uint64_t u0, u1;
  poly64_mul(&u1, &u0, a[0] ^ a[1], b[0] ^ b[1]);
  temp[1] ^= u0;
  temp[2] ^= u1;

  poly64_mul(&u1, &u0, a[0] ^ a[2], b[0] ^ b[2]);
  temp[2] ^= u0;
  temp[3] ^= u1;

  poly64_mul(&u1, &u0, a[1] ^ a[2], b[1] ^ b[2]);
  temp[3] ^= u0;
  temp[4] ^= u1;

  for (unsigned int i = 0; i < 6; ++i) r[i] = temp[i];
}

bf128_t bf128_mul(bf128_t lhs, bf128_t rhs) {
  uint64_t lo_lo_hi, lo_lo_lo;
  uint64_t hi_hi_hi, hi_hi_lo;
  uint64_t cross_hi, cross_lo;
  const uint64_t lhs0 = BF_VALUE(lhs, 0);
  const uint64_t lhs1 = BF_VALUE(lhs, 1);
  const uint64_t rhs0 = BF_VALUE(rhs, 0);
  const uint64_t rhs1 = BF_VALUE(rhs, 1);

  poly64_mul(&lo_lo_hi, &lo_lo_lo, lhs0, rhs0);
  poly64_mul(&hi_hi_hi, &hi_hi_lo, lhs1, rhs1);
  poly64_mul(&cross_hi, &cross_lo, lhs0 ^ lhs1, rhs0 ^ rhs1);

  cross_lo ^= lo_lo_lo ^ hi_hi_lo;
  cross_hi ^= lo_lo_hi ^ hi_hi_hi;

  return bf128_reduce_product(lo_lo_lo, lo_lo_hi ^ cross_lo, hi_hi_lo ^ cross_hi, hi_hi_hi);
}

bf128_t bf128_mul_64(bf128_t lhs, bf64_t rhs) {
  uint64_t lo_lo_hi, lo_lo_lo;
  uint64_t hi_lo_hi, hi_lo_lo;

  poly64_mul(&lo_lo_hi, &lo_lo_lo, BF_VALUE(lhs, 0), rhs);
  poly64_mul(&hi_lo_hi, &hi_lo_lo, BF_VALUE(lhs, 1), rhs);

  return bf128_reduce_product(lo_lo_lo, lo_lo_hi ^ hi_lo_lo, hi_lo_hi, 0);
}

#if !defined(HAVE_ATTR_VECTOR_SIZE)
bf128_t bf128_mul_bit(bf128_t lhs, uint8_t rhs) {
  return bf128_and_64(lhs, -((uint64_t)rhs & 1));
}
#endif

ATTR_CONST static inline bf128_t bf128_dbl(bf128_t lhs) {
  uint64_t mask = bf128_bit_to_uint64_mask(lhs, 128 - 1);
  lhs           = bf128_shift_left_1(lhs);
  BF_VALUE(lhs, 0) ^= (mask & bf128_modulus);

  return lhs;
}

bf128_t bf128_sum_poly(const bf128_t* xs) {
  bf128_t ret = xs[128 - 1];
  for (size_t i = 1; i < 128; ++i) {
    ret = bf128_add(bf128_dbl(ret), xs[128 - 1 - i]);
  }
  return ret;
}

bf128_t bf128_sum_poly_bits(const uint8_t* xs) {
  bf128_t ret = bf128_from_bit(ptr_get_bit(xs, 128 - 1));
  for (size_t i = 1; i < 128; ++i) {
    ret = bf128_add(bf128_dbl(ret), bf128_from_bit(ptr_get_bit(xs, 128 - 1 - i)));
  }
  return ret;
}

// GF(2^160) implementation

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf160_and_64(lhs, rhs) ((lhs) & (rhs))
#else
ATTR_CONST
static inline bf160_t bf160_and_64(bf160_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

ATTR_CONST static inline bf160_t bf160_mask_top(bf160_t value) {
  BF_VALUE(value, 2) &= UINT64_C(0xffffffff);
#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(value, 3) = 0;
#endif
  return value;
}

ATTR_CONST static inline uint64_t bf160_bit_to_uint64_mask(bf160_t value, unsigned int bit) {
  return -((BF_VALUE(value, bit / 64) >> (bit % 64)) & 1);
}

ATTR_CONST static inline bf160_t bf160_shift_left_1(bf160_t value) {
  BF_VALUE(value, 2) = (BF_VALUE(value, 2) << 1) | (BF_VALUE(value, 1) >> 63);
  BF_VALUE(value, 1) = (BF_VALUE(value, 1) << 1) | (BF_VALUE(value, 0) >> 63);
  BF_VALUE(value, 0) <<= 1;
  return bf160_mask_top(value);
}

ATTR_CONST static inline bf160_t bf160_dbl(bf160_t lhs) {
  uint64_t mask = bf160_bit_to_uint64_mask(lhs, 160 - 1);
  lhs           = bf160_shift_left_1(lhs);
  BF_VALUE(lhs, 0) ^= (mask & bf160_modulus);
  return lhs;
}

bf160_t bf160_mul(bf160_t lhs, bf160_t rhs) {
  bf160_t result = bf160_mul_bit(lhs, (uint8_t)(BF_VALUE(rhs, 0) & 1));
  for (unsigned int idx = 1; idx < 160; ++idx) {
    lhs = bf160_dbl(lhs);
    result = bf160_add(result, bf160_mul_bit(lhs, (uint8_t)((BF_VALUE(rhs, idx / 64) >> (idx % 64)) & 1)));
  }
  return bf160_mask_top(result);
}

bf160_t bf160_mul_64(bf160_t lhs, bf64_t rhs) {
  bf160_t result = bf160_mul_bit(lhs, (uint8_t)(rhs & 1));
  for (unsigned int idx = 1; idx < 64; ++idx) {
    lhs = bf160_dbl(lhs);
    result = bf160_add(result, bf160_mul_bit(lhs, (uint8_t)((rhs >> idx) & 1)));
  }
  return bf160_mask_top(result);
}

#if !defined(HAVE_ATTR_VECTOR_SIZE)
bf160_t bf160_mul_bit(bf160_t lhs, uint8_t rhs) {
  return bf160_and_64(lhs, -((uint64_t)rhs & 1));
}
#endif

bf160_t bf160_sum_poly(const bf160_t* xs) {
  bf160_t ret = xs[160 - 1];
  for (size_t i = 1; i < 160; ++i) {
    ret = bf160_add(bf160_dbl(ret), xs[160 - 1 - i]);
  }
  return ret;
}

bf160_t bf160_sum_poly_bits(const uint8_t* xs) {
  bf160_t ret = bf160_from_bit(ptr_get_bit(xs, 160 - 1));
  for (size_t i = 1; i < 160; ++i) {
    ret = bf160_add(bf160_dbl(ret), bf160_from_bit(ptr_get_bit(xs, 160 - 1 - i)));
  }
  return ret;
}

// GF(2^192) implementation

static const bf192_t bf192_alpha[7] = {
    BF192C(U64C(0x63, 0x97, 0x38, 0x6f, 0xd5, 0xa3, 0xc8, 0xcc),
           U64C(0xea, 0xbd, 0x6e, 0x96, 0x6c, 0xd7, 0x65, 0xe6),
           U64C(0x62, 0x36, 0x6b, 0x0e, 0x14, 0xc8, 0x0b, 0x31)),
    BF192C(U64C(0xbb, 0x50, 0xf4, 0x7c, 0x9e, 0x61, 0x33, 0xb2),
           U64C(0x26, 0x3f, 0x63, 0xd5, 0x19, 0x1f, 0xf6, 0x7b),
           U64C(0x34, 0xdb, 0x91, 0xd4, 0x26, 0x37, 0x93, 0xda)),
    BF192C(U64C(0x0d, 0x8a, 0x39, 0xf5, 0x13, 0x2c, 0x6d, 0x9c),
           U64C(0x19, 0x8d, 0x32, 0x06, 0x77, 0xe3, 0x32, 0x82),
           U64C(0xf6, 0x4e, 0x75, 0x3c, 0x70, 0x0d, 0x3b, 0x0c)),
    BF192C(U64C(0x5d, 0xf7, 0x2b, 0xbd, 0x7c, 0x74, 0x20, 0xdd),
           U64C(0x2e, 0xd2, 0x58, 0x00, 0xab, 0x42, 0x55, 0x7a),
           U64C(0x51, 0x12, 0xbc, 0x94, 0x9c, 0x51, 0xec, 0x45)),
    BF192C(U64C(0xf8, 0x2b, 0xce, 0x8a, 0xe2, 0x0c, 0xd5, 0xd8),
           U64C(0x84, 0xbe, 0xde, 0x67, 0xb7, 0x8c, 0x16, 0x08),
           U64C(0x45, 0x70, 0xa6, 0x4b, 0x6a, 0x14, 0x7d, 0xd6)),
    BF192C(U64C(0xba, 0xe1, 0xd5, 0xee, 0x76, 0x9c, 0x0f, 0x97),
           U64C(0x48, 0x20, 0xd7, 0x5f, 0xae, 0xf7, 0xea, 0xf3),
           U64C(0x43, 0xea, 0x6c, 0x69, 0x5f, 0xbd, 0xa6, 0x29)),
    BF192C(U64C(0x71, 0x85, 0x06, 0x65, 0xc2, 0x5d, 0x94, 0xf5),
           U64C(0xd3, 0xe9, 0x06, 0x39, 0x62, 0xfd, 0x19, 0x60),
           U64C(0xb0, 0xc4, 0x87, 0x0f, 0x54, 0x56, 0x7c, 0xc7)),
};

#if defined(SIG_TESTS)
bf192_t bf192_get_alpha(unsigned int idx) {
  return bf192_alpha[idx];
}
#endif

bf192_t bf192_byte_combine(const bf192_t* x) {
  bf192_t bf_out = x[0];
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf192_add(bf_out, bf192_mul(x[i], bf192_alpha[i - 1]));
  }
  return bf_out;
}

void bf192_sq_bit(bf192_t* out_tag, const bf192_t* in_tag) {
  out_tag[0] = bf192_add(in_tag[0], bf192_add(in_tag[4], in_tag[6]));
  out_tag[1] = bf192_add(in_tag[4], bf192_add(in_tag[6], in_tag[7]));
  out_tag[2] = bf192_add(in_tag[1], in_tag[5]);
  out_tag[3] = bf192_add(bf192_add(in_tag[4], in_tag[5]), bf192_add(in_tag[6], in_tag[7]));
  out_tag[4] = bf192_add(in_tag[2], bf192_add(in_tag[4], in_tag[7]));
  out_tag[5] = bf192_add(in_tag[5], in_tag[6]);
  out_tag[6] = bf192_add(in_tag[3], in_tag[5]);
  out_tag[7] = bf192_add(in_tag[6], in_tag[7]);
}

void bf192_sq_bit_inplace(bf192_t* tag) {
  tag[0]           = bf192_add(tag[0], bf192_add(tag[4], tag[6]));
  const bf192_t i1 = tag[1];
  tag[1]           = bf192_add(tag[4], bf192_add(tag[6], tag[7]));
  const bf192_t i2 = tag[2];
  tag[2]           = bf192_add(i1, tag[5]);
  const bf192_t i3 = tag[3];
  tag[3]           = bf192_add(bf192_add(tag[4], tag[5]), bf192_add(tag[6], tag[7]));
  tag[4]           = bf192_add(i2, bf192_add(tag[4], tag[7]));
  const bf192_t i5 = tag[5];
  tag[5]           = bf192_add(tag[5], tag[6]);
  const bf192_t i6 = tag[6];
  tag[6]           = bf192_add(i3, i5);
  tag[7]           = bf192_add(i6, tag[7]);
}

bf192_t bf192_byte_combine_sq(const bf192_t* x) {
  bf192_t bf_tmp[8];
  bf192_sq_bit(bf_tmp, x);
  return bf192_byte_combine(bf_tmp);
}

bf192_t bf192_byte_combine_bits(uint8_t x) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  return bf192_from_bit(get_bit(x, 0)) ^ bf192_mul_bit(bf192_alpha[1 - 1], get_bit(x, 1)) ^
         bf192_mul_bit(bf192_alpha[2 - 1], get_bit(x, 2)) ^
         bf192_mul_bit(bf192_alpha[3 - 1], get_bit(x, 3)) ^
         bf192_mul_bit(bf192_alpha[4 - 1], get_bit(x, 4)) ^
         bf192_mul_bit(bf192_alpha[5 - 1], get_bit(x, 5)) ^
         bf192_mul_bit(bf192_alpha[6 - 1], get_bit(x, 6)) ^
         bf192_mul_bit(bf192_alpha[7 - 1], get_bit(x, 7));
#else
  bf192_t bf_out = bf192_from_bit(get_bit(x, 0));
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf192_add(bf_out, bf192_mul_bit(bf192_alpha[i - 1], get_bit(x, i)));
  }
  return bf_out;
#endif
}

bf192_t bf192_byte_combine_bits_sq(uint8_t x) {
  return bf192_byte_combine_bits(bits_sq(x));
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf192_and_64(lhs, rhs) ((lhs) & (rhs))
#else
ATTR_CONST
static inline bf192_t bf192_and_64(bf192_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
#define bf192_shift_right_64(v1) __builtin_shufflevector((v1), bf192_zero(), 4, 0, 1, 5)
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf192_t bf192_shift_right_64(bf192_t v1) {
  bf192_t ret;
  BF_VALUE(ret, 0) = 0;
  BF_VALUE(ret, 1) = BF_VALUE(v1, 0);
  BF_VALUE(ret, 2) = BF_VALUE(v1, 1);
  BF_VALUE(ret, 3) = 0;
  return ret;
}
#endif
#endif

ATTR_CONST
static inline bf192_t bf192_shift_left_1(bf192_t value) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  const bf192_t mask = BF192C(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff);
  return ((value << 1) | bf192_shift_right_64(value >> 63)) & mask;
#else
  value.values[2] = (value.values[2] << 1) | (value.values[1] >> 63);
  value.values[1] = (value.values[1] << 1) | (value.values[0] >> 63);
  value.values[0] = value.values[0] << 1;
#endif
  return value;
}

ATTR_CONST
static inline uint64_t bf192_bit_to_uint64_mask(bf192_t value, unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}

bf192_t bf192_mul(bf192_t lhs, bf192_t rhs) {
  const uint64_t a0 = BF_VALUE(lhs, 0), a1 = BF_VALUE(lhs, 1), a2 = BF_VALUE(lhs, 2);
  const uint64_t b0 = BF_VALUE(rhs, 0), b1 = BF_VALUE(rhs, 1), b2 = BF_VALUE(rhs, 2);

  uint64_t t[3] = {0};
  uint64_t temp[6] = {0};

  poly64_mul(&t[0], &temp[0], a0, b0);
  poly64_mul(&t[2], &t[1], a1, b1);
  t[0] ^= t[1];

  poly64_mul(&temp[5], &t[1], a2, b2);
  t[1] ^= t[2];

  temp[1] = t[0] ^ temp[0];
  temp[2] = t[1] ^ temp[1];
  temp[4] = temp[5] ^ t[1];
  temp[3] = temp[4] ^ t[0];

  poly64_mul(&t[1], &t[0], a0 ^ a1, b0 ^ b1);
  temp[1] ^= t[0];
  temp[2] ^= t[1];

  poly64_mul(&t[1], &t[0], a0 ^ a2, b0 ^ b2);
  temp[2] ^= t[0];
  temp[3] ^= t[1];

  poly64_mul(&t[1], &t[0], a1 ^ a2, b1 ^ b2);
  temp[3] ^= t[0];
  temp[4] ^= t[1];

  // Reduce mod x^192 + x^7 + x^2 + x + 1
  t[0] = temp[3] ^ ((temp[5] >> 57) ^ (temp[5] >> 62) ^ (temp[5] >> 63));

  bf192_t result;
  BF_VALUE(result, 2) = temp[2] ^ temp[5];
  BF_VALUE(result, 2) ^= (temp[5] << 7) | (temp[4] >> 57);
  BF_VALUE(result, 2) ^= (temp[5] << 2) | (temp[4] >> 62);
  BF_VALUE(result, 2) ^= (temp[5] << 1) | (temp[4] >> 63);

  BF_VALUE(result, 1) = temp[1] ^ temp[4];
  BF_VALUE(result, 1) ^= (temp[4] << 7) | (t[0] >> 57);
  BF_VALUE(result, 1) ^= (temp[4] << 2) | (t[0] >> 62);
  BF_VALUE(result, 1) ^= (temp[4] << 1) | (t[0] >> 63);

  BF_VALUE(result, 0) = temp[0] ^ t[0];
  BF_VALUE(result, 0) ^= (t[0] << 7);
  BF_VALUE(result, 0) ^= (t[0] << 2);
  BF_VALUE(result, 0) ^= (t[0] << 1);

#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(result, 3) = 0;
#endif
  return result;
}

bf192_t bf192_mul_64(bf192_t lhs, bf64_t rhs) {
  uint64_t h0, l0, h1, l1, h2, l2;
  poly64_mul(&h0, &l0, BF_VALUE(lhs, 0), rhs);
  poly64_mul(&h1, &l1, BF_VALUE(lhs, 1), rhs);
  poly64_mul(&h2, &l2, BF_VALUE(lhs, 2), rhs);

  // Product is 4 limbs: l0, h0^l1, h1^l2, h2 (temp[4]=temp[5]=0)
  // Reduce mod x^192 + x^7 + x^2 + x + 1: fold temp[3]=h2
  uint64_t t0 = h2;

  bf192_t result;
  BF_VALUE(result, 2) = h1 ^ l2;
  BF_VALUE(result, 1) = h0 ^ l1;
  BF_VALUE(result, 1) ^= (t0 >> 57);
  BF_VALUE(result, 1) ^= (t0 >> 62);
  BF_VALUE(result, 1) ^= (t0 >> 63);
  BF_VALUE(result, 0) = l0 ^ t0 ^ (t0 << 7) ^ (t0 << 2) ^ (t0 << 1);

#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(result, 3) = 0;
#endif
  return result;
}

#if !defined(HAVE_ATTR_VECTOR_SIZE)
bf192_t bf192_mul_bit(bf192_t lhs, uint8_t rhs) {
  return bf192_and_64(lhs, -((uint64_t)rhs & 1));
}
#endif

ATTR_CONST static inline bf192_t bf192_dbl(bf192_t lhs) {
  uint64_t mask = bf192_bit_to_uint64_mask(lhs, 192 - 1);
  lhs           = bf192_shift_left_1(lhs);
  BF_VALUE(lhs, 0) ^= (mask & bf192_modulus);

  return lhs;
}

bf192_t bf192_sum_poly(const bf192_t* xs) {
  bf192_t ret = xs[192 - 1];
  for (size_t i = 1; i < 192; ++i) {
    ret = bf192_add(bf192_dbl(ret), xs[192 - 1 - i]);
  }
  return ret;
}

bf192_t bf192_sum_poly_bits(const uint8_t* xs) {
  bf192_t ret = bf192_from_bit(ptr_get_bit(xs, 192 - 1));
  for (size_t i = 1; i < 192; ++i) {
    ret = bf192_add(bf192_dbl(ret), bf192_from_bit(ptr_get_bit(xs, 192 - 1 - i)));
  }
  return ret;
}

// GF(2^256) implementation

static const bf256_t bf256_alpha[7] = {
    BF256C(U64C(0xe7, 0xfe, 0xde, 0x0b, 0x42, 0x88, 0x97, 0x96),
           U64C(0x67, 0x4e, 0x47, 0xa0, 0x38, 0x8d, 0xd6, 0xbe),
           U64C(0x6a, 0xe1, 0xf1, 0xf8, 0x45, 0x98, 0x22, 0xdf),
           U64C(0x33, 0x58, 0xc9, 0x20, 0xcf, 0xa8, 0xc9, 0x04)),
    BF256C(U64C(0xc1, 0x89, 0x22, 0xd5, 0x2a, 0xf5, 0x5a, 0xa9),
           U64C(0x2f, 0x07, 0x42, 0x2c, 0x8d, 0xc4, 0xa5, 0x2b),
           U64C(0xea, 0xb0, 0x00, 0x6c, 0x37, 0x0d, 0x4a, 0xd1),
           U64C(0xf1, 0x4a, 0x5b, 0x9c, 0x69, 0x4d, 0x4e, 0x06)),
    BF256C(U64C(0x1d, 0x9d, 0x80, 0x3f, 0x83, 0xb3, 0xda, 0x55),
           U64C(0x57, 0x0f, 0x3b, 0x53, 0x1e, 0x83, 0x71, 0x17),
           U64C(0x10, 0xac, 0x3f, 0xad, 0x3f, 0x57, 0x96, 0xfb),
           U64C(0x8d, 0xf6, 0x11, 0x70, 0xdb, 0xe3, 0x95, 0x61)),
    BF256C(U64C(0xd5, 0xcd, 0x1b, 0xb0, 0x19, 0x05, 0x01, 0xde),
           U64C(0xf6, 0xe3, 0x30, 0x1a, 0x91, 0x58, 0x27, 0x75),
           U64C(0x3f, 0xa0, 0x9e, 0x48, 0xb6, 0x78, 0x07, 0x2a),
           U64C(0x38, 0x88, 0x76, 0x4f, 0xd6, 0x4f, 0xc2, 0x56)),
    BF256C(U64C(0xb6, 0x30, 0x8a, 0xe9, 0x29, 0xf5, 0xc2, 0x98),
           U64C(0x82, 0x84, 0xf1, 0x40, 0xd4, 0xdb, 0xc4, 0x1b),
           U64C(0x81, 0xa9, 0x49, 0x7d, 0x94, 0x09, 0xbe, 0x2f),
           U64C(0xfc, 0x4f, 0x57, 0x71, 0x6d, 0x0b, 0x27, 0x22)),
    BF256C(U64C(0x0b, 0x67, 0x44, 0xde, 0xb9, 0xaf, 0x75, 0x9e),
           U64C(0xbc, 0xaf, 0xf1, 0x66, 0xc6, 0x66, 0xed, 0xac),
           U64C(0x7e, 0x1f, 0x99, 0xf2, 0x3f, 0x25, 0x01, 0xf0),
           U64C(0xf3, 0x29, 0xfa, 0xd1, 0x2f, 0x37, 0x3d, 0xc0)),
    BF256C(U64C(0x8b, 0xe8, 0x32, 0xb3, 0x98, 0xb6, 0x43, 0xba),
           U64C(0x0d, 0x6f, 0xb8, 0x25, 0xd6, 0xc4, 0x37, 0x52),
           U64C(0x45, 0x15, 0xe8, 0xf4, 0x2a, 0x2b, 0x65, 0x2f),
           U64C(0xb8, 0x7b, 0x6b, 0xd2, 0x09, 0xea, 0x3e, 0x13)),
};

#if defined(SIG_TESTS)
bf256_t bf256_get_alpha(unsigned int idx) {
  return bf256_alpha[idx];
}
#endif

bf256_t bf256_byte_combine(const bf256_t* x) {
  bf256_t bf_out = x[0];
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf256_add(bf_out, bf256_mul(x[i], bf256_alpha[i - 1]));
  }
  return bf_out;
}

void bf256_sq_bit(bf256_t* out_tag, const bf256_t* in_tag) {
  out_tag[0] = bf256_add(in_tag[0], bf256_add(in_tag[4], in_tag[6]));
  out_tag[1] = bf256_add(in_tag[4], bf256_add(in_tag[6], in_tag[7]));
  out_tag[2] = bf256_add(in_tag[1], in_tag[5]);
  out_tag[3] = bf256_add(bf256_add(in_tag[4], in_tag[5]), bf256_add(in_tag[6], in_tag[7]));
  out_tag[4] = bf256_add(in_tag[2], bf256_add(in_tag[4], in_tag[7]));
  out_tag[5] = bf256_add(in_tag[5], in_tag[6]);
  out_tag[6] = bf256_add(in_tag[3], in_tag[5]);
  out_tag[7] = bf256_add(in_tag[6], in_tag[7]);
}

void bf256_sq_bit_inplace(bf256_t* tag) {
  tag[0]           = bf256_add(tag[0], bf256_add(tag[4], tag[6]));
  const bf256_t i1 = tag[1];
  tag[1]           = bf256_add(tag[4], bf256_add(tag[6], tag[7]));
  const bf256_t i2 = tag[2];
  tag[2]           = bf256_add(i1, tag[5]);
  const bf256_t i3 = tag[3];
  tag[3]           = bf256_add(bf256_add(tag[4], tag[5]), bf256_add(tag[6], tag[7]));
  tag[4]           = bf256_add(i2, bf256_add(tag[4], tag[7]));
  const bf256_t i5 = tag[5];
  tag[5]           = bf256_add(tag[5], tag[6]);
  const bf256_t i6 = tag[6];
  tag[6]           = bf256_add(i3, i5);
  tag[7]           = bf256_add(i6, tag[7]);
}

bf256_t bf256_byte_combine_sq(const bf256_t* x) {
  bf256_t bf_tmp[8];
  bf256_sq_bit(bf_tmp, x);
  return bf256_byte_combine(bf_tmp);
}

bf256_t bf256_byte_combine_bits(uint8_t x) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  return bf256_from_bit(get_bit(x, 0)) ^ bf256_mul_bit(bf256_alpha[1 - 1], get_bit(x, 1)) ^
         bf256_mul_bit(bf256_alpha[2 - 1], get_bit(x, 2)) ^
         bf256_mul_bit(bf256_alpha[3 - 1], get_bit(x, 3)) ^
         bf256_mul_bit(bf256_alpha[4 - 1], get_bit(x, 4)) ^
         bf256_mul_bit(bf256_alpha[5 - 1], get_bit(x, 5)) ^
         bf256_mul_bit(bf256_alpha[6 - 1], get_bit(x, 6)) ^
         bf256_mul_bit(bf256_alpha[7 - 1], get_bit(x, 7));
#else
  bf256_t bf_out = bf256_from_bit(get_bit(x, 0));
  for (unsigned int i = 1; i < 8; ++i) {
    bf_out = bf256_add(bf_out, bf256_mul_bit(bf256_alpha[i - 1], get_bit(x, i)));
  }
  return bf_out;
#endif
}

bf256_t bf256_byte_combine_bits_sq(uint8_t x) {
  return bf256_byte_combine_bits(bits_sq(x));
}

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf256_and_64(lhs, rhs) ((lhs) & (rhs))
#else
ATTR_CONST
static inline bf256_t bf256_and_64(bf256_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
#define bf256_shift_right_64(v1) __builtin_shufflevector((v1), bf256_zero(), 4, 0, 1, 2)
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf256_t bf256_shift_right_64(bf256_t v1) {
  bf256_t ret;
  BF_VALUE(ret, 0) = 0;
  BF_VALUE(ret, 1) = BF_VALUE(v1, 0);
  BF_VALUE(ret, 2) = BF_VALUE(v1, 1);
  BF_VALUE(ret, 3) = BF_VALUE(v1, 2);
  return ret;
}
#endif

#define bf256_shift_left_1(value) ((value << 1) | bf256_shift_right_64(value >> 63))
#else
ATTR_CONST
static inline bf256_t bf256_shift_left_1(bf256_t value) {
  value.values[3] = (value.values[3] << 1) | (value.values[2] >> 63);
  value.values[2] = (value.values[2] << 1) | (value.values[1] >> 63);
  value.values[1] = (value.values[1] << 1) | (value.values[0] >> 63);
  value.values[0] = value.values[0] << 1;
  return value;
}
#endif

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf256_bit_to_uint64_mask(bf256_t value,
                                                                              unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}

bf256_t bf256_mul(bf256_t lhs, bf256_t rhs) {
  const uint64_t a0 = BF_VALUE(lhs, 0), a1 = BF_VALUE(lhs, 1);
  const uint64_t a2 = BF_VALUE(lhs, 2), a3 = BF_VALUE(lhs, 3);
  const uint64_t b0 = BF_VALUE(rhs, 0), b1 = BF_VALUE(rhs, 1);
  const uint64_t b2 = BF_VALUE(rhs, 2), b3 = BF_VALUE(rhs, 3);

  uint64_t t[4] = {0};
  uint64_t add[4] = {0};
  uint64_t temp[8] = {0};

  poly64_mul(&t[0], &temp[0], a0, b0);
  poly64_mul(&t[2], &t[1], a1, b1);
  t[0] ^= t[1];

  poly64_mul(&t[3], &t[1], a2, b2);
  t[1] ^= t[2];

  poly64_mul(&temp[7], &t[2], a3, b3);
  t[2] ^= t[3];

  temp[6] = temp[7] ^ t[2];
  temp[3] = t[2] ^ t[1];
  temp[2] = t[1] ^ t[0];
  temp[1] = t[0] ^ temp[0];

  poly64_mul(&t[1], &t[0], a0 ^ a1, b0 ^ b1);
  temp[1] ^= t[0];
  temp[2] ^= t[1];

  poly64_mul(&t[1], &t[0], a2 ^ a3, b2 ^ b3);
  temp[3] ^= t[0];
  temp[6] ^= t[1];

  temp[5] = temp[7] ^ temp[3];
  temp[4] = temp[6] ^ temp[2];
  temp[3] ^= temp[1];
  temp[2] ^= temp[0];

  add[0] = a0 ^ a2;
  add[1] = a1 ^ a3;
  add[2] = b0 ^ b2;
  add[3] = b1 ^ b3;
  poly64_mul(&t[1], &t[0], add[0], add[2]);
  poly64_mul(&t[3], &t[2], add[1], add[3]);
  t[1] ^= t[2];
  t[2] = t[1] ^ t[3];
  t[1] ^= t[0];

  temp[2] ^= t[0];
  temp[3] ^= t[1];
  temp[4] ^= t[2];
  temp[5] ^= t[3];

  poly64_mul(&t[1], &t[0], add[0] ^ add[1], add[2] ^ add[3]);
  temp[3] ^= t[0];
  temp[4] ^= t[1];

  // Reduce mod x^256 + x^10 + x^5 + x^2 + 1
  t[0] = temp[4] ^ ((temp[7] >> 54) ^ (temp[7] >> 59) ^ (temp[7] >> 62));

  bf256_t result;
  BF_VALUE(result, 3) = temp[3] ^ temp[7];
  BF_VALUE(result, 3) ^= (temp[7] << 10) | (temp[6] >> 54);
  BF_VALUE(result, 3) ^= (temp[7] << 5) | (temp[6] >> 59);
  BF_VALUE(result, 3) ^= (temp[7] << 2) | (temp[6] >> 62);

  BF_VALUE(result, 2) = temp[2] ^ temp[6];
  BF_VALUE(result, 2) ^= (temp[6] << 10) | (temp[5] >> 54);
  BF_VALUE(result, 2) ^= (temp[6] << 5) | (temp[5] >> 59);
  BF_VALUE(result, 2) ^= (temp[6] << 2) | (temp[5] >> 62);

  BF_VALUE(result, 1) = temp[1] ^ temp[5];
  BF_VALUE(result, 1) ^= (temp[5] << 10) | (t[0] >> 54);
  BF_VALUE(result, 1) ^= (temp[5] << 5) | (t[0] >> 59);
  BF_VALUE(result, 1) ^= (temp[5] << 2) | (t[0] >> 62);

  BF_VALUE(result, 0) = temp[0] ^ t[0];
  BF_VALUE(result, 0) ^= (t[0] << 10);
  BF_VALUE(result, 0) ^= (t[0] << 5);
  BF_VALUE(result, 0) ^= (t[0] << 2);

  return result;
}

bf256_t bf256_mul_64(bf256_t lhs, bf64_t rhs) {
  uint64_t h0, l0, h1, l1, h2, l2, h3, l3;
  poly64_mul(&h0, &l0, BF_VALUE(lhs, 0), rhs);
  poly64_mul(&h1, &l1, BF_VALUE(lhs, 1), rhs);
  poly64_mul(&h2, &l2, BF_VALUE(lhs, 2), rhs);
  poly64_mul(&h3, &l3, BF_VALUE(lhs, 3), rhs);

  // Product: l0, h0^l1, h1^l2, h2^l3, h3, 0, 0, 0
  // Reduce mod x^256 + x^10 + x^5 + x^2 + 1
  // t0 = temp[4] = h3 (since temp[5..7]=0)
  uint64_t t0 = h3;

  bf256_t result;
  BF_VALUE(result, 3) = h2 ^ l3;
  BF_VALUE(result, 2) = h1 ^ l2;
  BF_VALUE(result, 1) = (h0 ^ l1) ^ (t0 >> 54) ^ (t0 >> 59) ^ (t0 >> 62);
  BF_VALUE(result, 0) = l0 ^ t0 ^ (t0 << 10) ^ (t0 << 5) ^ (t0 << 2);

  return result;
}

#if !defined(HAVE_ATTR_VECTOR_SIZE)
bf256_t bf256_mul_bit(bf256_t lhs, uint8_t rhs) {
  return bf256_and_64(lhs, -((uint64_t)rhs & 1));
}
#endif

ATTR_CONST static inline bf256_t bf256_dbl(bf256_t lhs) {
  uint64_t mask = bf256_bit_to_uint64_mask(lhs, 256 - 1);
  lhs           = bf256_shift_left_1(lhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
  const bf256_t mod = BF256C(bf256_modulus, 0, 0, 0);
  return lhs ^ bf256_and_64(mod, mask);
#else
  BF_VALUE(lhs, 0) ^= mask & bf256_modulus;
  return lhs;
#endif
}

bf256_t bf256_sum_poly(const bf256_t* xs) {
  bf256_t ret = xs[256 - 1];
  for (size_t i = 1; i < 256; ++i) {
    ret = bf256_add(bf256_dbl(ret), xs[256 - 1 - i]);
  }
  return ret;
}

bf256_t bf256_sum_poly_bits(const uint8_t* xs) {
  bf256_t ret = bf256_from_bit(ptr_get_bit(xs, 256 - 1));
  for (size_t i = 1; i < 256; ++i) {
    ret = bf256_add(bf256_dbl(ret), bf256_from_bit(ptr_get_bit(xs, 256 - 1 - i)));
  }
  return ret;
}

// GF(2^384)

#if defined(HAVE_ATTR_VECTOR_SIZE)
ATTR_CONST
static inline bf384_t bf384_and_64(bf384_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.inner); ++i) {
    lhs.inner[i] &= rhs;
  }
  return lhs;
}
#else
ATTR_CONST
static inline bf384_t bf384_and_64(bf384_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf384_t bf384_shift_right_64(bf384_t v1) {
  bf384_t ret;
  ret.inner[0] = __builtin_shufflevector(v1.inner[0], bf128_zero(), 2, 0);
  ret.inner[1] = __builtin_shufflevector(v1.inner[1], bf128_zero(), 2, 0) |
                 __builtin_shufflevector(v1.inner[0], bf128_zero(), 1, 3);
  ret.inner[2] = __builtin_shufflevector(v1.inner[2], bf128_zero(), 2, 0) |
                 __builtin_shufflevector(v1.inner[1], bf128_zero(), 1, 3);
  return ret;
}
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf384_t bf384_shift_right_64(bf384_t v1) {
  bf384_t ret;
  BF_VALUE(ret.inner[0], 0) = 0;
  BF_VALUE(ret.inner[0], 1) = BF_VALUE(v1.inner[0], 0);
  BF_VALUE(ret.inner[1], 0) = BF_VALUE(v1.inner[0], 1);
  BF_VALUE(ret.inner[1], 1) = BF_VALUE(v1.inner[1], 0);
  BF_VALUE(ret.inner[2], 0) = BF_VALUE(v1.inner[1], 1);
  BF_VALUE(ret.inner[2], 1) = BF_VALUE(v1.inner[2], 0);
  return ret;
}
#endif

ATTR_CONST
static inline bf384_t bf384_shift_left_1(bf384_t value) {
  const bf384_t rhs = bf384_shift_right_64(value);
  for (unsigned int i = 0; i != ARRAY_SIZE(value.inner); ++i) {
    value.inner[i] = (value.inner[i] << 1) | (rhs.inner[i] >> 63);
  }
  return value;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf384_bit_to_uint64_mask(bf384_t value,
                                                                              unsigned int bit) {
  const unsigned int inner_idx = bit / 128;
  const unsigned int inner_bit = bit % 128;
  const unsigned int byte_idx  = inner_bit / 64;
  const unsigned int bit_idx   = inner_bit % 64;

  return -((BF_VALUE(value.inner[inner_idx], byte_idx) >> bit_idx) & 1);
}
#else
ATTR_CONST
static inline bf384_t bf384_shift_left_1(bf384_t value) {
  for (unsigned int i = ARRAY_SIZE(value.values) - 1; i; --i) {
    value.values[i] = (value.values[i] << 1) | (value.values[i - 1] >> 63);
  }
  value.values[0] = value.values[0] << 1;
  return value;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf384_bit_to_uint64_mask(bf384_t value,
                                                                              unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}
#endif

// Extract 6 uint64_t limbs from bf384_t
static inline void bf384_to_limbs(uint64_t a[6], bf384_t v) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  a[0] = BF_VALUE(v.inner[0], 0); a[1] = BF_VALUE(v.inner[0], 1);
  a[2] = BF_VALUE(v.inner[1], 0); a[3] = BF_VALUE(v.inner[1], 1);
  a[4] = BF_VALUE(v.inner[2], 0); a[5] = BF_VALUE(v.inner[2], 1);
#else
  for (unsigned int i = 0; i < 6; ++i) a[i] = v.values[i];
#endif
}

// Build bf384_t from 6 uint64_t limbs
static inline bf384_t bf384_from_limbs(const uint64_t a[6]) {
  bf384_t r;
#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(r.inner[0], 0) = a[0]; BF_VALUE(r.inner[0], 1) = a[1];
  BF_VALUE(r.inner[1], 0) = a[2]; BF_VALUE(r.inner[1], 1) = a[3];
  BF_VALUE(r.inner[2], 0) = a[4]; BF_VALUE(r.inner[2], 1) = a[5];
#else
  for (unsigned int i = 0; i < 6; ++i) r.values[i] = a[i];
#endif
  return r;
}

// Reduce 12-limb product mod x^384 + x^16 + x^15 + x^6 + 1
static bf384_t bf384_reduce_product(uint64_t p[12]) {
  // Fold p[6..11] into p[0..5] by multiplying by (x^16 + x^15 + x^6 + 1)
  uint64_t c = 0;
  // * 1
  for (unsigned int i = 0; i < 6; ++i) p[i] ^= p[i + 6];
  // * x^6
  p[0] ^= (p[6] << 6);
  p[1] ^= (p[7] << 6) | (p[6] >> 58);
  p[2] ^= (p[8] << 6) | (p[7] >> 58);
  p[3] ^= (p[9] << 6) | (p[8] >> 58);
  p[4] ^= (p[10] << 6) | (p[9] >> 58);
  p[5] ^= (p[11] << 6) | (p[10] >> 58);
  c ^= p[11] >> 58;
  // * x^15
  p[0] ^= (p[6] << 15);
  p[1] ^= (p[7] << 15) | (p[6] >> 49);
  p[2] ^= (p[8] << 15) | (p[7] >> 49);
  p[3] ^= (p[9] << 15) | (p[8] >> 49);
  p[4] ^= (p[10] << 15) | (p[9] >> 49);
  p[5] ^= (p[11] << 15) | (p[10] >> 49);
  c ^= p[11] >> 49;
  // * x^16
  p[0] ^= (p[6] << 16);
  p[1] ^= (p[7] << 16) | (p[6] >> 48);
  p[2] ^= (p[8] << 16) | (p[7] >> 48);
  p[3] ^= (p[9] << 16) | (p[8] >> 48);
  p[4] ^= (p[10] << 16) | (p[9] >> 48);
  p[5] ^= (p[11] << 16) | (p[10] >> 48);
  c ^= p[11] >> 48;
  // Fold carry (max 16 bits)
  p[0] ^= c ^ (c << 6) ^ (c << 15) ^ (c << 16);

  return bf384_from_limbs(p);
}

bf384_t bf384_mul_128(bf384_t lhs, bf128_t rhs) {
  uint64_t a[6], r[2];
  bf384_to_limbs(a, lhs);
  r[0] = BF_VALUE(rhs, 0);
  r[1] = BF_VALUE(rhs, 1);

  uint64_t p0[4], p1[4], p2[4];
  poly128_mul(p0, &a[0], r);  // A0 * rhs
  poly128_mul(p1, &a[2], r);  // A1 * rhs
  poly128_mul(p2, &a[4], r);  // A2 * rhs

  // Combine: p0 at offset 0, p1 at offset 2 (128 bits), p2 at offset 4 (256 bits)
  uint64_t p[12] = {0};
  for (unsigned int i = 0; i < 4; ++i) p[i] ^= p0[i];
  for (unsigned int i = 0; i < 4; ++i) p[i + 2] ^= p1[i];
  for (unsigned int i = 0; i < 4; ++i) p[i + 4] ^= p2[i];

  return bf384_reduce_product(p);
}

bf384_t bf384_mul(bf384_t lhs, bf384_t rhs) {
  uint64_t a[6], b[6];
  bf384_to_limbs(a, lhs);
  bf384_to_limbs(b, rhs);

  // 3-way Karatsuba at 128-bit level: A=(A0,A1,A2), B=(B0,B1,B2)
  uint64_t d0[4], d1[4], d2[4];       // direct products
  uint64_t c01[4], c02[4], c12[4];    // cross products
  poly128_mul(d0, &a[0], &b[0]);      // A0*B0
  poly128_mul(d1, &a[2], &b[2]);      // A1*B1
  poly128_mul(d2, &a[4], &b[4]);      // A2*B2

  uint64_t ta[2], tb[2];
  ta[0] = a[0] ^ a[2]; ta[1] = a[1] ^ a[3];
  tb[0] = b[0] ^ b[2]; tb[1] = b[1] ^ b[3];
  poly128_mul(c01, ta, tb);           // (A0+A1)*(B0+B1)
  for (unsigned int i = 0; i < 4; ++i) c01[i] ^= d0[i] ^ d1[i]; // A0*B1 + A1*B0

  ta[0] = a[0] ^ a[4]; ta[1] = a[1] ^ a[5];
  tb[0] = b[0] ^ b[4]; tb[1] = b[1] ^ b[5];
  poly128_mul(c02, ta, tb);           // (A0+A2)*(B0+B2)
  for (unsigned int i = 0; i < 4; ++i) c02[i] ^= d0[i] ^ d2[i]; // A0*B2 + A2*B0

  ta[0] = a[2] ^ a[4]; ta[1] = a[3] ^ a[5];
  tb[0] = b[2] ^ b[4]; tb[1] = b[3] ^ b[5];
  poly128_mul(c12, ta, tb);           // (A1+A2)*(B1+B2)
  for (unsigned int i = 0; i < 4; ++i) c12[i] ^= d1[i] ^ d2[i]; // A1*B2 + A2*B1

  // Assemble 12-limb product:
  // p[0..3]  = d0
  // p[2..5]  += c01
  // p[4..7]  += d1 + c02
  // p[6..9]  += c12
  // p[8..11] += d2
  uint64_t p[12] = {0};
  for (unsigned int i = 0; i < 4; ++i) p[i] ^= d0[i];
  for (unsigned int i = 0; i < 4; ++i) p[i + 2] ^= c01[i];
  for (unsigned int i = 0; i < 4; ++i) p[i + 4] ^= d1[i] ^ c02[i];
  for (unsigned int i = 0; i < 4; ++i) p[i + 6] ^= c12[i];
  for (unsigned int i = 0; i < 4; ++i) p[i + 8] ^= d2[i];

  return bf384_reduce_product(p);
}

bf384_t bf384_mul_bit(bf384_t lhs, uint8_t rhs) {
  return bf384_and_64(lhs, -((uint64_t)rhs & 1));
}

ATTR_CONST static inline bf384_t bf384_dbl(bf384_t lhs) {
  const uint64_t mask = bf384_bit_to_uint64_mask(lhs, 384 - 1);
  lhs                 = bf384_shift_left_1(lhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
  const bf128_t mod = BF128C(bf384_modulus, 0);
  lhs.inner[0] ^= bf128_and_64(mod, mask);
#else
  BF_VALUE(lhs, 0) ^= mask & bf384_modulus;
#endif
  return lhs;
}

bf384_t bf384_sum_poly(const bf384_t* xs) {
  bf384_t ret = xs[384 - 1];
  for (size_t i = 1; i < 384; ++i) {
    ret = bf384_add(bf384_dbl(ret), xs[384 - 1 - i]);
  }
  return ret;
}

bf384_t bf384_sum_poly_bits(const uint8_t* xs) {
  bf384_t ret = bf384_from_bit(ptr_get_bit(xs, 384 - 1));
  for (size_t i = 1; i < 384; ++i) {
    ret = bf384_add(bf384_dbl(ret), bf384_from_bit(ptr_get_bit(xs, 384 - 1 - i)));
  }
  return ret;
}

// GF(2^512)

#if defined(HAVE_ATTR_VECTOR_SIZE)
#define bf512_and_64(lhs, rhs) ((lhs) & (rhs))
#else
ATTR_CONST
static inline bf512_t bf512_and_64(bf512_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
#define bf512_shift_right_64(v1) __builtin_shufflevector((v1), bf512_zero(), 8, 0, 1, 2, 3, 4, 5, 6)
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf512_t bf512_shift_right_64(bf512_t v1) {
  bf512_t ret;
  BF_VALUE(ret, 0) = 0;
  BF_VALUE(ret, 1) = BF_VALUE(v1, 0);
  BF_VALUE(ret, 2) = BF_VALUE(v1, 1);
  BF_VALUE(ret, 3) = BF_VALUE(v1, 2);
  BF_VALUE(ret, 4) = BF_VALUE(v1, 3);
  BF_VALUE(ret, 5) = BF_VALUE(v1, 4);
  BF_VALUE(ret, 6) = BF_VALUE(v1, 5);
  BF_VALUE(ret, 7) = BF_VALUE(v1, 6);
  return ret;
}
#endif

#define bf512_shift_left_1(value) ((value << 1) | bf512_shift_right_64(value >> 63))
#else
ATTR_CONST
static inline bf512_t bf512_shift_left_1(bf512_t value) {
  value.values[7] = (value.values[7] << 1) | (value.values[6] >> 63);
  value.values[6] = (value.values[6] << 1) | (value.values[5] >> 63);
  value.values[5] = (value.values[5] << 1) | (value.values[4] >> 63);
  value.values[4] = (value.values[4] << 1) | (value.values[3] >> 63);
  value.values[3] = (value.values[3] << 1) | (value.values[2] >> 63);
  value.values[2] = (value.values[2] << 1) | (value.values[1] >> 63);
  value.values[1] = (value.values[1] << 1) | (value.values[0] >> 63);
  value.values[0] = value.values[0] << 1;
  return value;
}
#endif

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf512_bit_to_uint64_mask(bf512_t value,
                                                                              unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}

// Reduce 16-limb product mod x^512 + x^8 + x^5 + x^2 + 1
static bf512_t bf512_reduce_product(uint64_t p[16]) {
  // Fold p[8..15] into p[0..7]
  uint64_t c = 0;
  // * 1
  for (unsigned int i = 0; i < 8; ++i) p[i] ^= p[i + 8];
  // * x^2
  p[0] ^= (p[8] << 2);
  p[1] ^= (p[9] << 2) | (p[8] >> 62);
  p[2] ^= (p[10] << 2) | (p[9] >> 62);
  p[3] ^= (p[11] << 2) | (p[10] >> 62);
  p[4] ^= (p[12] << 2) | (p[11] >> 62);
  p[5] ^= (p[13] << 2) | (p[12] >> 62);
  p[6] ^= (p[14] << 2) | (p[13] >> 62);
  p[7] ^= (p[15] << 2) | (p[14] >> 62);
  c ^= p[15] >> 62;
  // * x^5
  p[0] ^= (p[8] << 5);
  p[1] ^= (p[9] << 5) | (p[8] >> 59);
  p[2] ^= (p[10] << 5) | (p[9] >> 59);
  p[3] ^= (p[11] << 5) | (p[10] >> 59);
  p[4] ^= (p[12] << 5) | (p[11] >> 59);
  p[5] ^= (p[13] << 5) | (p[12] >> 59);
  p[6] ^= (p[14] << 5) | (p[13] >> 59);
  p[7] ^= (p[15] << 5) | (p[14] >> 59);
  c ^= p[15] >> 59;
  // * x^8
  p[0] ^= (p[8] << 8);
  p[1] ^= (p[9] << 8) | (p[8] >> 56);
  p[2] ^= (p[10] << 8) | (p[9] >> 56);
  p[3] ^= (p[11] << 8) | (p[10] >> 56);
  p[4] ^= (p[12] << 8) | (p[11] >> 56);
  p[5] ^= (p[13] << 8) | (p[12] >> 56);
  p[6] ^= (p[14] << 8) | (p[13] >> 56);
  p[7] ^= (p[15] << 8) | (p[14] >> 56);
  c ^= p[15] >> 56;
  // Fold carry (max 8 bits)
  p[0] ^= c ^ (c << 2) ^ (c << 5) ^ (c << 8);

  bf512_t result;
  for (unsigned int i = 0; i < 8; ++i) BF_VALUE(result, i) = p[i];
  return result;
}

bf512_t bf512_mul(bf512_t lhs, bf512_t rhs) {
  uint64_t a[8], b[8];
  for (unsigned int i = 0; i < 8; ++i) { a[i] = BF_VALUE(lhs, i); b[i] = BF_VALUE(rhs, i); }

  // 2-way Karatsuba at 256-bit level
  uint64_t lo[8], hi[8], mid[8];
  poly256_mul(lo, &a[0], &b[0]);     // low 256 * low 256
  poly256_mul(hi, &a[4], &b[4]);     // high 256 * high 256
  uint64_t ta[4], tb[4];
  for (unsigned int i = 0; i < 4; ++i) { ta[i] = a[i] ^ a[i + 4]; tb[i] = b[i] ^ b[i + 4]; }
  poly256_mul(mid, ta, tb);           // cross
  for (unsigned int i = 0; i < 8; ++i) mid[i] ^= lo[i] ^ hi[i];

  uint64_t p[16] = {0};
  for (unsigned int i = 0; i < 4; ++i) p[i] = lo[i];
  for (unsigned int i = 4; i < 8; ++i) p[i] = lo[i] ^ mid[i - 4];
  for (unsigned int i = 8; i < 12; ++i) p[i] = hi[i - 8] ^ mid[i - 4];
  for (unsigned int i = 12; i < 16; ++i) p[i] = hi[i - 8];

  return bf512_reduce_product(p);
}

bf512_t bf512_mul_64(bf512_t lhs, bf64_t rhs) {
  uint64_t h[8], l[8];
  for (unsigned int i = 0; i < 8; ++i) poly64_mul(&h[i], &l[i], BF_VALUE(lhs, i), rhs);

  uint64_t p[16] = {0};
  p[0] = l[0];
  for (unsigned int i = 1; i < 8; ++i) p[i] = h[i - 1] ^ l[i];
  p[8] = h[7];

  return bf512_reduce_product(p);
}

#if !defined(HAVE_ATTR_VECTOR_SIZE)
bf512_t bf512_mul_bit(bf512_t lhs, uint8_t rhs) {
  return bf512_and_64(lhs, -((uint64_t)rhs & 1));
}
#endif

ATTR_CONST static inline bf512_t bf512_dbl(bf512_t lhs) {
  uint64_t mask = bf512_bit_to_uint64_mask(lhs, 512 - 1);
  lhs           = bf512_shift_left_1(lhs);
#if defined(HAVE_ATTR_VECTOR_SIZE)
  const bf512_t mod = BF512C(bf512_modulus, 0, 0, 0, 0, 0, 0, 0);
  return lhs ^ bf512_and_64(mod, mask);
#else
  BF_VALUE(lhs, 0) ^= mask & bf512_modulus;
  return lhs;
#endif
}

bf512_t bf512_sum_poly(const bf512_t* xs) {
  bf512_t ret = xs[512 - 1];
  for (size_t i = 1; i < 512; ++i) {
    ret = bf512_add(bf512_dbl(ret), xs[512 - 1 - i]);
  }
  return ret;
}

bf512_t bf512_sum_poly_bits(const uint8_t* xs) {
  bf512_t ret = bf512_from_bit(ptr_get_bit(xs, 512 - 1));
  for (size_t i = 1; i < 512; ++i) {
    ret = bf512_add(bf512_dbl(ret), bf512_from_bit(ptr_get_bit(xs, 512 - 1 - i)));
  }
  return ret;
}

// GF(2^576)

#if defined(HAVE_ATTR_VECTOR_SIZE)
ATTR_CONST
static inline bf576_t bf576_and_64(bf576_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.inner); ++i) {
    lhs.inner[i] &= rhs;
  }
  return lhs;
}
#else
ATTR_CONST
static inline bf576_t bf576_and_64(bf576_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf576_t bf576_shift_right_64(bf576_t v1) {
  bf576_t ret;
  ret.inner[0] = __builtin_shufflevector(v1.inner[0], bf256_zero(), 4, 0, 1, 7);
  ret.inner[1] = __builtin_shufflevector(v1.inner[1], bf256_zero(), 4, 0, 1, 7) |
                 __builtin_shufflevector(v1.inner[0], bf256_zero(), 2, 5, 6, 7);
  ret.inner[2] = __builtin_shufflevector(v1.inner[2], bf256_zero(), 4, 0, 1, 7) |
                 __builtin_shufflevector(v1.inner[1], bf256_zero(), 2, 5, 6, 7);
  return ret;
}
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf576_t bf576_shift_right_64(bf576_t v1) {
  bf576_t ret;
  BF_VALUE(ret.inner[0], 0) = 0;
  BF_VALUE(ret.inner[0], 1) = BF_VALUE(v1.inner[0], 0);
  BF_VALUE(ret.inner[0], 2) = BF_VALUE(v1.inner[0], 1);
  BF_VALUE(ret.inner[1], 0) = BF_VALUE(v1.inner[0], 2);
  BF_VALUE(ret.inner[1], 1) = BF_VALUE(v1.inner[1], 0);
  BF_VALUE(ret.inner[1], 2) = BF_VALUE(v1.inner[1], 1);
  BF_VALUE(ret.inner[2], 0) = BF_VALUE(v1.inner[1], 2);
  BF_VALUE(ret.inner[2], 1) = BF_VALUE(v1.inner[2], 0);
  BF_VALUE(ret.inner[2], 2) = BF_VALUE(v1.inner[2], 1);
  return ret;
}
#endif

ATTR_CONST
static inline bf576_t bf576_shift_left_1(bf576_t value) {
  const bf576_t rhs = bf576_shift_right_64(value);
  for (unsigned int i = 0; i != ARRAY_SIZE(value.inner); ++i) {
    value.inner[i] = (value.inner[i] << 1) | (rhs.inner[i] >> 63);
  }
  return value;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf576_bit_to_uint64_mask(bf576_t value,
                                                                              unsigned int bit) {
  const unsigned int inner_idx = bit / 192;
  const unsigned int inner_bit = bit % 192;
  const unsigned int byte_idx  = inner_bit / 64;
  const unsigned int bit_idx   = inner_bit % 64;

  return -((BF_VALUE(value.inner[inner_idx], byte_idx) >> bit_idx) & 1);
}
#else
ATTR_CONST
static inline bf576_t bf576_shift_left_1(bf576_t value) {
  for (unsigned int i = ARRAY_SIZE(value.values) - 1; i; --i) {
    value.values[i] = (value.values[i] << 1) | (value.values[i - 1] >> 63);
  }
  value.values[0] = value.values[0] << 1;
  return value;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf576_bit_to_uint64_mask(bf576_t value,
                                                                              unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}
#endif

// Extract 9 uint64_t limbs from bf576_t
static inline void bf576_to_limbs(uint64_t a[9], bf576_t v) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  a[0] = BF_VALUE(v.inner[0], 0); a[1] = BF_VALUE(v.inner[0], 1); a[2] = BF_VALUE(v.inner[0], 2);
  a[3] = BF_VALUE(v.inner[1], 0); a[4] = BF_VALUE(v.inner[1], 1); a[5] = BF_VALUE(v.inner[1], 2);
  a[6] = BF_VALUE(v.inner[2], 0); a[7] = BF_VALUE(v.inner[2], 1); a[8] = BF_VALUE(v.inner[2], 2);
#else
  for (unsigned int i = 0; i < 9; ++i) a[i] = v.values[i];
#endif
}

// Build bf576_t from 9 uint64_t limbs
static inline bf576_t bf576_from_limbs(const uint64_t a[9]) {
  bf576_t r;
#if defined(HAVE_ATTR_VECTOR_SIZE)
  BF_VALUE(r.inner[0], 0) = a[0]; BF_VALUE(r.inner[0], 1) = a[1]; BF_VALUE(r.inner[0], 2) = a[2];
  BF_VALUE(r.inner[0], 3) = 0;
  BF_VALUE(r.inner[1], 0) = a[3]; BF_VALUE(r.inner[1], 1) = a[4]; BF_VALUE(r.inner[1], 2) = a[5];
  BF_VALUE(r.inner[1], 3) = 0;
  BF_VALUE(r.inner[2], 0) = a[6]; BF_VALUE(r.inner[2], 1) = a[7]; BF_VALUE(r.inner[2], 2) = a[8];
  BF_VALUE(r.inner[2], 3) = 0;
#else
  for (unsigned int i = 0; i < 9; ++i) r.values[i] = a[i];
#endif
  return r;
}

// Reduce 15-limb product mod x^576 + x^13 + x^4 + x^3 + 1
static bf576_t bf576_reduce_product(uint64_t p[18]) {
  // Fold p[9..17] into p[0..8] by multiplying upper half by (x^13 + x^4 + x^3 + 1)
  // Save upper half since we modify p in-place
  uint64_t u[9];
  for (unsigned int i = 0; i < 9; ++i) u[i] = p[i + 9];

  uint64_t c = 0;
  // * 1
  for (unsigned int i = 0; i < 9; ++i) p[i] ^= u[i];
  // * x^3
  p[0] ^= (u[0] << 3);
  for (unsigned int i = 1; i < 9; ++i) p[i] ^= (u[i] << 3) | (u[i - 1] >> 61);
  c ^= u[8] >> 61;
  // * x^4
  p[0] ^= (u[0] << 4);
  for (unsigned int i = 1; i < 9; ++i) p[i] ^= (u[i] << 4) | (u[i - 1] >> 60);
  c ^= u[8] >> 60;
  // * x^13
  p[0] ^= (u[0] << 13);
  for (unsigned int i = 1; i < 9; ++i) p[i] ^= (u[i] << 13) | (u[i - 1] >> 51);
  c ^= u[8] >> 51;
  // Fold carry (max 13 bits)
  p[0] ^= c ^ (c << 3) ^ (c << 4) ^ (c << 13);

  return bf576_from_limbs(p);
}

bf576_t bf576_mul_192(bf576_t lhs, bf192_t rhs) {
  uint64_t a[9];
  bf576_to_limbs(a, lhs);
  uint64_t r[3] = {BF_VALUE(rhs, 0), BF_VALUE(rhs, 1), BF_VALUE(rhs, 2)};

  uint64_t p0[6], p1[6], p2[6];
  poly192_mul(p0, &a[0], r);   // A0 * rhs at position 0
  poly192_mul(p1, &a[3], r);   // A1 * rhs at position 192
  poly192_mul(p2, &a[6], r);   // A2 * rhs at position 384

  uint64_t p[18] = {0};
  for (unsigned int i = 0; i < 6; ++i) p[i] ^= p0[i];
  for (unsigned int i = 0; i < 6; ++i) p[i + 3] ^= p1[i];
  for (unsigned int i = 0; i < 6; ++i) p[i + 6] ^= p2[i];

  return bf576_reduce_product(p);
}

// GF(2^768)

#if defined(HAVE_ATTR_VECTOR_SIZE)
ATTR_CONST
static inline bf768_t bf768_and_64(bf768_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.inner); ++i) {
    lhs.inner[i] &= rhs;
  }
  return lhs;
}
#else
ATTR_CONST
static inline bf768_t bf768_and_64(bf768_t lhs, bf64_t rhs) {
  for (unsigned int i = 0; i != ARRAY_SIZE(lhs.values); ++i) {
    lhs.values[i] &= rhs;
  }
  return lhs;
}
#endif

#if defined(HAVE_ATTR_VECTOR_SIZE)
#if __has_builtin(__builtin_shufflevector)
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf768_t bf768_shift_right_64(bf768_t v1) {
  bf768_t ret;
  ret.inner[0] = __builtin_shufflevector(v1.inner[0], bf256_zero(), 4, 0, 1, 2);
  ret.inner[1] = __builtin_shufflevector(v1.inner[1], bf256_zero(), 4, 0, 1, 2) |
                 __builtin_shufflevector(v1.inner[0], bf256_zero(), 3, 5, 6, 7);
  ret.inner[2] = __builtin_shufflevector(v1.inner[2], bf256_zero(), 4, 0, 1, 2) |
                 __builtin_shufflevector(v1.inner[1], bf256_zero(), 3, 5, 6, 7);
  return ret;
}
#else
ATTR_CONST ATTR_ALWAYS_INLINE static inline bf768_t bf768_shift_right_64(bf768_t v1) {
  bf768_t ret;
  BF_VALUE(ret.inner[0], 0) = 0;
  BF_VALUE(ret.inner[0], 1) = BF_VALUE(v1.inner[0], 0);
  BF_VALUE(ret.inner[0], 2) = BF_VALUE(v1.inner[0], 1);
  BF_VALUE(ret.inner[0], 3) = BF_VALUE(v1.inner[0], 2);
  BF_VALUE(ret.inner[1], 0) = BF_VALUE(v1.inner[0], 3);
  BF_VALUE(ret.inner[1], 1) = BF_VALUE(v1.inner[1], 0);
  BF_VALUE(ret.inner[1], 2) = BF_VALUE(v1.inner[1], 1);
  BF_VALUE(ret.inner[1], 3) = BF_VALUE(v1.inner[1], 2);
  BF_VALUE(ret.inner[2], 0) = BF_VALUE(v1.inner[1], 3);
  BF_VALUE(ret.inner[2], 1) = BF_VALUE(v1.inner[2], 0);
  BF_VALUE(ret.inner[2], 2) = BF_VALUE(v1.inner[2], 1);
  BF_VALUE(ret.inner[2], 3) = BF_VALUE(v1.inner[2], 2);
  return ret;
}
#endif

ATTR_CONST
static inline bf768_t bf768_shift_left_1(bf768_t value) {
  bf768_t rhs = bf768_shift_right_64(value);
  for (unsigned int i = 0; i != ARRAY_SIZE(value.inner); ++i) {
    value.inner[i] = (value.inner[i] << 1) | (rhs.inner[i] >> 63);
  }
  return value;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf768_bit_to_uint64_mask(bf768_t value,
                                                                              unsigned int bit) {
  const unsigned int inner_idx = bit / 256;
  const unsigned int inner_bit = bit % 256;
  const unsigned int byte_idx  = inner_bit / 64;
  const unsigned int bit_idx   = inner_bit % 64;

  return -((BF_VALUE(value.inner[inner_idx], byte_idx) >> bit_idx) & 1);
}
#else
ATTR_CONST
static inline bf768_t bf768_shift_left_1(bf768_t value) {
  for (unsigned int i = ARRAY_SIZE(value.values) - 1; i; --i) {
    value.values[i] = (value.values[i] << 1) | (value.values[i - 1] >> 63);
  }
  value.values[0] = value.values[0] << 1;
  return value;
}

ATTR_CONST ATTR_ALWAYS_INLINE static inline uint64_t bf768_bit_to_uint64_mask(bf768_t value,
                                                                              unsigned int bit) {
  const unsigned int byte_idx = bit / 64;
  const unsigned int bit_idx  = bit % 64;

  return -((BF_VALUE(value, byte_idx) >> bit_idx) & 1);
}
#endif

// Extract 12 uint64_t limbs from bf768_t
static inline void bf768_to_limbs(uint64_t a[12], bf768_t v) {
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int j = 0; j < 3; ++j)
    for (unsigned int k = 0; k < 4; ++k)
      a[j * 4 + k] = BF_VALUE(v.inner[j], k);
#else
  for (unsigned int i = 0; i < 12; ++i) a[i] = v.values[i];
#endif
}

// Build bf768_t from 12 uint64_t limbs
static inline bf768_t bf768_from_limbs(const uint64_t a[12]) {
  bf768_t r;
#if defined(HAVE_ATTR_VECTOR_SIZE)
  for (unsigned int j = 0; j < 3; ++j)
    for (unsigned int k = 0; k < 4; ++k)
      BF_VALUE(r.inner[j], k) = a[j * 4 + k];
#else
  for (unsigned int i = 0; i < 12; ++i) r.values[i] = a[i];
#endif
  return r;
}

// Reduce 20-limb product mod x^768 + x^19 + x^17 + x^4 + 1
static bf768_t bf768_reduce_product(uint64_t p[24]) {
  // Fold p[12..23] into p[0..11]
  uint64_t u[12];
  for (unsigned int i = 0; i < 12; ++i) u[i] = p[i + 12];

  uint64_t c = 0;
  // * 1
  for (unsigned int i = 0; i < 12; ++i) p[i] ^= u[i];
  // * x^4
  p[0] ^= (u[0] << 4);
  for (unsigned int i = 1; i < 12; ++i) p[i] ^= (u[i] << 4) | (u[i - 1] >> 60);
  c ^= u[11] >> 60;
  // * x^17
  p[0] ^= (u[0] << 17);
  for (unsigned int i = 1; i < 12; ++i) p[i] ^= (u[i] << 17) | (u[i - 1] >> 47);
  c ^= u[11] >> 47;
  // * x^19
  p[0] ^= (u[0] << 19);
  for (unsigned int i = 1; i < 12; ++i) p[i] ^= (u[i] << 19) | (u[i - 1] >> 45);
  c ^= u[11] >> 45;
  // Fold carry (max 19 bits)
  p[0] ^= c ^ (c << 4) ^ (c << 17) ^ (c << 19);

  return bf768_from_limbs(p);
}

bf768_t bf768_mul_256(bf768_t lhs, bf256_t rhs) {
  uint64_t a[12];
  bf768_to_limbs(a, lhs);
  uint64_t r[4] = {BF_VALUE(rhs, 0), BF_VALUE(rhs, 1), BF_VALUE(rhs, 2), BF_VALUE(rhs, 3)};

  uint64_t p0[8], p1[8], p2[8];
  poly256_mul(p0, &a[0], r);   // A0 * rhs at position 0
  poly256_mul(p1, &a[4], r);   // A1 * rhs at position 256
  poly256_mul(p2, &a[8], r);   // A2 * rhs at position 512

  uint64_t p[24] = {0};
  for (unsigned int i = 0; i < 8; ++i) p[i] ^= p0[i];
  for (unsigned int i = 0; i < 8; ++i) p[i + 4] ^= p1[i];
  for (unsigned int i = 0; i < 8; ++i) p[i + 8] ^= p2[i];

  return bf768_reduce_product(p);
}
