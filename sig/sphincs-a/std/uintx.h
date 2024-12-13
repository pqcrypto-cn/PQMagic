#ifndef UINTX_H
#define UINTX_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

typedef uint64_t uint128_t[2];

#define less_u128 SPX_NAMESPACE(less_u128)
bool less_u128(const uint128_t *x, const uint128_t *y);

#define eq_u128 SPX_NAMESPACE(eq_u128)
bool eq_u128(const uint128_t *x, const uint128_t *y);

#define add_u128 SPX_NAMESPACE(add_u128)
void add_u128(uint128_t *z, const uint128_t *x, const uint128_t *y);

#define sub_u128 SPX_NAMESPACE(sub_u128)
void sub_u128(uint128_t *z, const uint128_t *x, const uint128_t *y);

#define set0_u128 SPX_NAMESPACE(set0_u128)
void set0_u128(uint128_t *z);

#define set1_u128 SPX_NAMESPACE(set1_u128)
void set1_u128(uint128_t *z);

static const uint128_t UINT128_MAX = {~0ULL, ~0ULL};

typedef uint64_t uint256_t[4];

#define less_u256 SPX_NAMESPACE(less_u256)
bool less_u256(const uint256_t *x, const uint256_t *y);

#define set0_u256 SPX_NAMESPACE(set0_u256)
void set0_u256(uint256_t *z);
#define set1_u256 SPX_NAMESPACE(set1_u256)
void set1_u256(uint256_t *z);

#define add_u256 SPX_NAMESPACE(add_u256)
void add_u256(uint256_t *z, const uint256_t *x, const uint256_t *y);
#define sub_u256 SPX_NAMESPACE(sub_u256)
void sub_u256(uint256_t *z, const uint256_t *x, const uint256_t *y);

#endif
