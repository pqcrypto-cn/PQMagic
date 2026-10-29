#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

/* 
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1] 
 in the NTT form:
 coeffs[0] + X^t *coeffs[t] + X^{2*t} *coeffs[2*t] + ... + X^{(NTT_DIM-1)*t}*coeffs[(NTT_DIM-1)*t]
 +
 ...
 +
X^{t-1} *coeffs[t-1] + X^{2*t-1} *coeffs[2*t-1] + ... + X^{NTT_DIM*t-1}*coeffs[NTT_DIM*t-1]
 */
typedef struct{
	int16_t coeffs[PARAM_N];
} poly;

void poly_caddq(poly *r);
void poly_reduce(poly *r);
void poly_rot256(poly *r, poly*a);

void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_ntt(poly *r);
void poly_invntt(poly *r);
void poly_mont_mul(poly * r, const poly*a, const poly*b);
int poly_mont2_inverse(poly* r, const poly*a);
int poly_mont2_inverse_judge(const poly*a);

void poly_add_vinv(poly *f);
int16_t mont2_inv(int16_t a);
int16_t mont2_inv2(int16_t a);

void poly_getmontgomery(poly *r);
#endif
