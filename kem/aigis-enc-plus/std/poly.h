#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

/* 
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1] 
 */

typedef struct{
	int16_t coeffs[PARAM_N] __attribute__((aligned(32)));
} poly;

void poly_caddq(poly *r);
void poly_caddq2(poly *r);
void poly_reduce(poly *r);
void poly_compress(uint8_t *r, const poly *a); //each coefficient of a is compressed into cbits
void poly_compress10(uint8_t *r, const poly *a);
void poly_decompress10(poly *r, const unsigned char *a);
void poly_decompress(poly *r, const uint8_t *a);
void poly_tobytes(uint8_t *r, const poly *a);
void poly_frombytes(poly *r, const uint8_t *a);
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES]);
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly *r);
void poly_ss_getnoise(poly *r,const uint8_t *seed, uint8_t nonce);
void poly_ee_getnoise(poly *r, const uint8_t *seed, uint8_t nonce);
void poly_uniform_seed(uint16_t *r, int n, const uint8_t *seed, int seedbytes);
void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_getmontgomery(poly* r);
void poly_mont_mul(poly* r, const poly* a, const poly* b);
void poly_ntt(poly *r);
void poly_invntt(poly *r);
#endif
