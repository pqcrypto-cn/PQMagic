#include <stdio.h>
#include "polyvec.h"
#include "reduce.h"
#include "cbd.h"
#include "hashkdf.h"
#include "genmatrix.h"
#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#endif

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

#if BITS_C1 == 9 || BITS_PK == 9
static void polyvec_compress9(uint8_t *r, const polyvec *a)
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
#endif

#if BITS_C1 == 10 || BITS_PK == 10
static void polyvec_compress10(uint8_t *r, const polyvec *a)
{
	int i, j, k;
	uint16_t t[4];
	uint16_t cpbytes = ((PARAM_N * 10) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i<PARAM_K; i++)
	{
		for (j = 0; j<PARAM_N / 4; j++)
		{
			for (k = 0; k<4; k++) {
				t[k] = ((((uint32_t)a->vec[i].coeffs[4 * j + k] << 10) + PARAM_Q / 2) / PARAM_Q) & 0x3ff;
			}
			r[5 * j + 0] = t[0] & 0xff;
			r[5 * j + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
			r[5 * j + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
			r[5 * j + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
			r[5 * j + 4] = (t[3] >> 2);
		}
		r += cpbytes;
	}
}
#endif

#if BITS_C1 == 11 || BITS_PK == 11
static void polyvec_compress11(uint8_t *r, const polyvec *a)
{
	int i, j, k;
	uint16_t t[8];
	uint16_t cpbytes = ((PARAM_N * 11) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i < PARAM_K; i++)
	{
		for (j = 0; j < PARAM_N / 8; j++)
		{
			for (k = 0; k < 8; k++)
				t[k] = ((((uint32_t)a->vec[i].coeffs[8 * j + k] << 11) + PARAM_Q / 2) / PARAM_Q) & 0x7ff;

			r[11 * j + 0] = t[0] & 0xff;
			r[11 * j + 1] = (t[0] >> 8) | ((t[1] & 0x1f) << 3);
			r[11 * j + 2] = (t[1] >> 5) | ((t[2] & 0x03) << 6);
			r[11 * j + 3] = (t[2] >> 2) & 0xff;
			r[11 * j + 4] = (t[2] >> 10) | ((t[3] & 0x7f) << 1);
			r[11 * j + 5] = (t[3] >> 7) | ((t[4] & 0x0f) << 4);
			r[11 * j + 6] = (t[4] >> 4) | ((t[5] & 0x01) << 7);
			r[11 * j + 7] = (t[5] >> 1) & 0xff;
			r[11 * j + 8] = (t[5] >> 9) | ((t[6] & 0x3f) << 2);
			r[11 * j + 9] = (t[6] >> 6) | ((t[7] & 0x07) << 5);
			r[11 * j + 10] = (t[7] >> 3);
		}
		r += cpbytes;
	}
}
#endif

#if BITS_C1 == 9 || BITS_PK == 9
static void polyvec_decompress9(polyvec *r, const unsigned char *a)
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
#endif

#if BITS_C1 == 10 || BITS_PK == 10
static void polyvec_decompress10(polyvec *r, const unsigned char *a)
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
#endif

#if BITS_C1 == 11 || BITS_PK == 11
static void polyvec_decompress11(polyvec *r, const unsigned char *a)
{
	int i, j;
	uint16_t cpbytes = ((PARAM_N * 11) >> 3);//the bytes for storing a polynomial in compressed form
	for (i = 0; i < PARAM_K; i++)
	{
		for (j = 0; j < PARAM_N / 8; j++)
		{
			r->vec[i].coeffs[8 * j + 0] = (((a[11 * j + 0] | (((uint32_t)a[11 * j + 1] & 0x07) << 8)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 1] = ((((a[11 * j + 1] >> 3) | (((uint32_t)a[11 * j + 2] & 0x3f) << 5)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 2] = ((((a[11 * j + 2] >> 6) | (((uint32_t)a[11 * j + 3] & 0xff) << 2) | (((uint32_t)a[11 * j + 4] & 0x01) << 10)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 3] = ((((a[11 * j + 4] >> 1) | (((uint32_t)a[11 * j + 5] & 0x0f) << 7)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 4] = ((((a[11 * j + 5] >> 4) | (((uint32_t)a[11 * j + 6] & 0x7f) << 4)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 5] = ((((a[11 * j + 6] >> 7) | (((uint32_t)a[11 * j + 7] & 0xff) << 1) | (((uint32_t)a[11 * j + 8] & 0x03) << 9)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 6] = ((((a[11 * j + 8] >> 2) | (((uint32_t)a[11 * j + 9] & 0x1f) << 6)) * PARAM_Q) + 1024) >> 11;
			r->vec[i].coeffs[8 * j + 7] = ((((a[11 * j + 9] >> 5) | (((uint32_t)a[11 * j + 10] & 0xff) << 3)) * PARAM_Q) + 1024) >> 11;
		}
		a += cpbytes;
	}
}
#endif

void polyvec_ct_compress(uint8_t *r, const polyvec *a)
{
//assuming the coefficients belong in [0,PARAM_Q)
#if BITS_C1 == 9
	polyvec_compress9(r, a);
#elif BITS_C1 == 10
	polyvec_compress10(r, a);
#elif BITS_C1 == 11
	polyvec_compress11(r, a);
#else
#error "polyvec_ct_compress() only supports BITS_C1 in {9,10,11}"
#endif
}

void polyvec_pk_compress(uint8_t *r, const polyvec *a)
{
//assuming the coefficients belong in [0,PARAM_Q)
#if BITS_PK == 9
	polyvec_compress9(r, a);
#elif BITS_PK == 10
	polyvec_compress10(r, a);
#elif BITS_PK == 11
	polyvec_compress11(r, a);
#else
#error "polyvec_pk_compress() only supports BITS_C1 in {9,10,11}"
#endif
}

void polyvec_ct_decompress(polyvec *r, const uint8_t *a)
{
#if BITS_C1 == 9
	polyvec_decompress9(r, a);
#elif BITS_C1 == 10
	polyvec_decompress10(r, a);
#elif BITS_C1 == 11
	polyvec_decompress11(r, a);
#else
#error "polyvec_ct_decompress() only supports BITS_C1 in {9,10,11}"
#endif
}

void polyvec_pk_decompress(polyvec *r, const uint8_t *a)
{
#if BITS_PK == 9
	polyvec_decompress9(r, a);
#elif BITS_PK == 10
	polyvec_decompress10(r, a);
#elif BITS_PK == 11
	polyvec_decompress11(r, a);
#else
#error "polyvec_pk_decompress() only supports BITS_C1 in {9,10,11}"
#endif
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
	int i, j;
	int16_t t;
	int16_t montR2= 5569; // 5569 = 2^{2*16} % q

	for (j = 0; j < PARAM_N; j++)
	{
		t = montgomery_reduce(montR2* (int32_t)b->vec[0].coeffs[j]);
		r->coeffs[j] = montgomery_reduce(a->vec[0].coeffs[j] * t);
		for (i = 1; i < PARAM_K; i++)
		{
			t = montgomery_reduce(montR2 * (int32_t)b->vec[i].coeffs[j]);
			r->coeffs[j] += montgomery_reduce(a->vec[i].coeffs[j] * t);
		}
		r->coeffs[j] = barrett_reduce(r->coeffs[j]);
	}
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
	uint8_t buf[ETA_S*PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	for (i = 0; i < PARAM_K; i++)
	{
		extseed[SEED_BYTES] = nonce;
		nonce++;
		kdf256(buf,sizeof(buf),extseed,SEED_BYTES+1);
		cbd_etas(&r->vec[i], buf);
	}
}
void polyvec_ee_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETA_E*PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	for (i = 0; i < PARAM_K; i++)
	{
		extseed[SEED_BYTES] = nonce;
		nonce++;
		kdf256(buf, sizeof(buf), extseed, SEED_BYTES + 1);
		cbd_etae(&r->vec[i], buf);
	}
}
