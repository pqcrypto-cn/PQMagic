#include <stdio.h>
#include "polyvec.h"
#include "reduce.h"
#include <string.h>

#include "cbd.h"
#include "hashkdf.h"
#include "gen_a.h"
#include "api.h"


extern const uint16_t chac[];
void polyvec_caddq(polyvec *r)
{
	int i;
	for (i = 0; i < PARAM_K; i++)
		poly_caddq(r->vec + i);
}
void polyvec_reduce(polyvec *r)
{
	int i;
	for (i = 0; i < PARAM_K; i++)
		poly_reduce(r->vec + i);
}
void polyvec_compress9(uint8_t *r, const polyvec *a)
{
	int i, j, k;
	uint16_t t[8];
	uint16_t cpbytes = ((PARAM_N * 9) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i<PARAM_K; i++)
	{
		for (j = 0; j<PARAM_N / 8; j++)
		{
			for (k = 0; k<8; k++)
				t[k] = ((((uint32_t)a->vec[i].coeffs[8 * j + k] << 9) + PARAM_Q / 2) / PARAM_Q) & 0x1ff;

			r[9 * j + 0] = t[0] & 0xff;
			r[9 * j + 1] = (t[0] >> 8) | ((t[1] & 0x7f) << 1);
			r[9 * j + 2] = (t[1] >> 7) | ((t[2] & 0x3f) << 2);
			r[9 * j + 3] = (t[2] >> 6) | ((t[3] & 0x1f) << 3);
			r[9 * j + 4] = (t[3] >> 5) | ((t[4] & 0x0f) << 4);
			r[9 * j + 5] = (t[4] >> 4) | ((t[5] & 0x07) << 5);
			r[9 * j + 6] = (t[5] >> 3) | ((t[6] & 0x03) << 6);
			r[9 * j + 7] = (t[6] >> 2) | ((t[7] & 0x01) << 7);
			r[9 * j + 8] = (t[7] >> 1);
		}
		r += cpbytes;
	}
}

void poly_compress10(uint8_t *r, const poly *a) {
	int i, j, k;
	uint16_t t[4];
	for (j = 0; j < PARAM_N / 4; j++) {
		for (k = 0; k < 4; k++) t[k] = ((((uint32_t) a->coeffs[4 * j + k] << 10) + PARAM_Q / 2) / PARAM_Q) &
		                               0x3ff;

		r[5 * j + 0] = t[0] & 0xff;
		r[5 * j + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
		r[5 * j + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
		r[5 * j + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
		r[5 * j + 4] = (t[3] >> 2);
	}
}
void polyvec_compress10(uint8_t *r, const polyvec *a)
{
	int i, j, k;
	uint16_t t[4];
	uint16_t cpbytes = ((PARAM_N * 10) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i<PARAM_K; i++)
	{
		for (j = 0; j<PARAM_N / 4; j++)
		{
			for (k = 0; k<4; k++)
				t[k] = ((((uint32_t)a->vec[i].coeffs[4 * j + k] << 10) + PARAM_Q / 2) / PARAM_Q) & 0x3ff;

			r[5 * j + 0] = t[0] & 0xff;
			r[5 * j + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
			r[5 * j + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
			r[5 * j + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
			r[5 * j + 4] = (t[3] >> 2);
		}
		r += cpbytes;
	}
}
void polyvec_decompress9(polyvec *r, const unsigned char *a)
{
	int i, j;
	uint16_t cpbytes = ((PARAM_N * 9) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i < PARAM_K; i++)
	{
		for (j = 0; j < PARAM_N / 8; j++)
		{
			r->vec[i].coeffs[8 * j + 0] = (((a[9 * j + 0] | (((uint32_t)a[9 * j + 1] & 0x01) << 8)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 1] = ((((a[9 * j + 1] >> 1) | (((uint32_t)a[9 * j + 2] & 0x03) << 7)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 2] = ((((a[9 * j + 2] >> 2) | (((uint32_t)a[9 * j + 3] & 0x07) << 6)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 3] = ((((a[9 * j + 3] >> 3) | (((uint32_t)a[9 * j + 4] & 0x0f) << 5)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 4] = ((((a[9 * j + 4] >> 4) | (((uint32_t)a[9 * j + 5] & 0x1f) << 4)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 5] = ((((a[9 * j + 5] >> 5) | (((uint32_t)a[9 * j + 6] & 0x3f) << 3)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 6] = ((((a[9 * j + 6] >> 6) | (((uint32_t)a[9 * j + 7] & 0x7f) << 2)) * PARAM_Q) + 256) >> 9;
			r->vec[i].coeffs[8 * j + 7] = ((((a[9 * j + 7] >> 7) | (((uint32_t)a[9 * j + 8]) << 1)) * PARAM_Q) + 256) >> 9;
		}
		a += cpbytes;
	}
}

void poly_decompress10(poly *r, const unsigned char *a) {
	int j;
	for (j = 0; j < PARAM_N / 4; j++) {
		r->coeffs[4 * j + 0] = (((a[5 * j + 0] | (((uint32_t) a[5 * j + 1] & 0x03) << 8)) * PARAM_Q) + 512) >>
		                       10;
		r->coeffs[4 * j + 1] = ((((a[5 * j + 1] >> 2) | (((uint32_t) a[5 * j + 2] & 0x0f) << 6)) * PARAM_Q) +
		                        512) >> 10;
		r->coeffs[4 * j + 2] = ((((a[5 * j + 2] >> 4) | (((uint32_t) a[5 * j + 3] & 0x3f) << 4)) * PARAM_Q) +
		                        512) >> 10;
		r->coeffs[4 * j + 3] = ((((a[5 * j + 3] >> 6) | (((uint32_t) a[5 * j + 4]) << 2)) * PARAM_Q) + 512) >>
		                              10;
	}
}
void polyvec_decompress10(polyvec *r, const unsigned char *a)
{
	int i, j;
	uint16_t cpbytes = ((PARAM_N * 10) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i < PARAM_K; i++)
	{
		for (j = 0; j < PARAM_N / 4; j++)
		{
			r->vec[i].coeffs[4 * j + 0] = (((a[5 * j + 0] | (((uint32_t)a[5 * j + 1] & 0x03) << 8)) * PARAM_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 1] = ((((a[5 * j + 1] >> 2) | (((uint32_t)a[5 * j + 2] & 0x0f) << 6)) * PARAM_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 2] = ((((a[5 * j + 2] >> 4) | (((uint32_t)a[5 * j + 3] & 0x3f) << 4)) * PARAM_Q) + 512) >> 10;
			r->vec[i].coeffs[4 * j + 3] = ((((a[5 * j + 3] >> 6) | (((uint32_t)a[5 * j + 4]) << 2)) * PARAM_Q) + 512) >> 10;
		}
		a += cpbytes;
	}
}

void polyvec_ct_compress(uint8_t *r, const polyvec *a)
{
//assuming the coefficients belong in [0,PARAM_Q)
polyvec_compress10(r, a);
}

void polyvec_pk_compress(uint8_t *r, const polyvec *a)
{
	//assuming the coefficients belong in [0,PARAM_Q)
	polyvec_compress10(r, a);
}

void polyvec_ct_decompress(polyvec *r, const uint8_t *a)
{
	polyvec_decompress10(r, a);
}

void polyvec_pk_decompress(polyvec *r, const uint8_t *a)
{
	polyvec_decompress10(r, a);
}
/*************************************************
* Name:        polyvec_tobytes
* 
* Description: Serialize vector of polynomials
*
* Arguments:   - uint8_t *r: pointer to output byte array 
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_tobytes(uint8_t *r, const polyvec *a)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_tobytes(r+i*POLY_BYTES, &a->vec[i]);
}

/*************************************************
* Name:        polyvec_frombytes
* 
* Description: De-serialize vector of polynomials;
*              inverse of polyvec_tobytes 
*
* Arguments:   - uint8_t *r: pointer to output byte array 
*              - const polyvec *a: pointer to input vector of polynomials
**************************************************/
void polyvec_frombytes(polyvec *r, const uint8_t *a)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_frombytes(&r->vec[i], a+i*POLY_BYTES);
}

void polyvec_ntt(polyvec *r)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_ntt(&r->vec[i]);
}

void polyvec_invntt(polyvec *r)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_invntt(&r->vec[i]);
}
 
/*************************************************
* Name:        polyvec_pointwise_acc
* 
* Description: Pointwise multiply elements of a and b and accumulate into r
*
* Arguments: - poly *r:          pointer to output polynomial
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/ 
void polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b)
{
	poly_mont_mul(r, &a->vec[0], &b->vec[0]);
	poly_getmontgomery(r);
}
/*************************************************
* Name:        polyvec_add
* 
* Description: Add vectors of polynomials
*
* Arguments: - polyvec *r:       pointer to output vector of polynomials
*            - const polyvec *a: pointer to first input vector of polynomials
*            - const polyvec *b: pointer to second input vector of polynomials
**************************************************/ 
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  int i;
  for(i=0;i<PARAM_K;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);

}
void polyvec_ss_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETAS_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	(void)nonce;

	memcpy(extseed, seed, SEED_BYTES);

	extseed[SEED_BYTES] = 0;
	KDF(buf,sizeof(buf),extseed,SEED_BYTES+1);
	cbd_etas(&r->vec[0], buf);
}
void polyvec_ee_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETAE_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	(void)nonce;

	memcpy(extseed, seed, SEED_BYTES);

	extseed[SEED_BYTES] = 1;
	KDF(buf, sizeof(buf), extseed, SEED_BYTES + 1);
	cbd_etae(&r->vec[0], buf);
}
