#ifndef FP_H
#define FP_H

//////////////////////////////////////////////// NOTE: this is placed here for now
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <tutil.h>
#include <fp_constants.h>

#include "mp.h" // TODO this should be its own import rather than hiding in here...

typedef digit_t fp_t[NWORDS_FIELD]; // Datatype for representing field elements

extern const uint64_t ONE[NWORDS_FIELD];
extern const uint64_t ZERO[NWORDS_FIELD];

void fp_set_small(fp_t *x, const digit_t val);
void fp_set_zero(fp_t *x);
void fp_set_one(fp_t *x);
uint32_t fp_is_equal(const fp_t *a, const fp_t *b);
uint32_t fp_is_zero(const fp_t *a);
void fp_copy(fp_t *out, const fp_t *a);

void fp_encode(void *dst, const fp_t *a);
void fp_decode_reduce(fp_t *d, const void *src, size_t len);
void fp_decode(fp_t *d, const void *src);

void fp_select(fp_t *d, const fp_t *a0, const fp_t *a1, uint32_t ctl);
void fp_cswap(fp_t *a, fp_t *b, uint32_t ctl);

void fp_add(fp_t *out, const fp_t *a, const fp_t *b);
void fp_sub(fp_t *out, const fp_t *a, const fp_t *b);
void fp_neg(fp_t *out, const fp_t *a);
void fp_sqr(fp_t *out, const fp_t *a);
void fp_mul(fp_t *out, const fp_t *a, const fp_t *b);

void fp_inv(fp_t *x);
uint32_t fp_is_square(const fp_t *a);
void fp_sqrt(fp_t *a);
void fp_half(fp_t *out, const fp_t *a);
void fp_tomont(fp_t *out, const fp_t *a);
void fp_frommont(fp_t *out, const fp_t *a);
void fp_mont_setone(fp_t *out);

#endif
