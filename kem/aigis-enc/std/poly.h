#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "align.h"
#include "params.h"

/* 
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1] 
 */
typedef ALIGN(32) struct{
	int16_t coeffs[PARAM_N];
} poly;

#define poly_caddq AIGIS_ENC_NAMESPACE(owcpapoly_caddq_enc)
void poly_caddq(poly *r);
#define poly_caddq2 AIGIS_ENC_NAMESPACE(poly_caddq2)
void poly_caddq2(poly *r);
#define poly_reduce AIGIS_ENC_NAMESPACE(owcpa_poly_reduceenc)
void poly_reduce(poly *r);
#define poly_compress AIGIS_ENC_NAMESPACE(poly_compress)
void poly_compress(uint8_t *r, const poly *a); //each coefficient of a is compressed into cbits  
#define poly_decompress AIGIS_ENC_NAMESPACE(poly_decompress)
void poly_decompress(poly *r, const uint8_t *a);
#define poly_tobytes AIGIS_ENC_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t *r, const poly *a);
#define poly_frombytes AIGIS_ENC_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const uint8_t *a);
#define poly_frommsg AIGIS_ENC_NAMESPACE(poly_frommsg)
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES]);
#define poly_tomsg AIGIS_ENC_NAMESPACE(poly_tomsg)
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly *r);
#define poly_ss_getnoise AIGIS_ENC_NAMESPACE(poly_ss_getnoise)
void poly_ss_getnoise(poly *r,const uint8_t *seed, uint8_t nonce);
#define poly_ee_getnoise AIGIS_ENC_NAMESPACE(poly_ee_getnoise)
void poly_ee_getnoise(poly *r, const uint8_t *seed, uint8_t nonce);
#define poly_uniform_seed AIGIS_ENC_NAMESPACE(poly_uniform_seed)
void poly_uniform_seed(poly *r, const uint8_t *seed, int seedbytes);
#define poly_add AIGIS_ENC_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub AIGIS_ENC_NAMESPACE(poly_sub)
void poly_sub(poly *r, const poly *a, const poly *b);
#define poly_ntt AIGIS_ENC_NAMESPACE(poly_ntt)
void poly_ntt(poly *r);
#define poly_invntt AIGIS_ENC_NAMESPACE(poly_invntt)
void poly_invntt(poly *r);
#endif
