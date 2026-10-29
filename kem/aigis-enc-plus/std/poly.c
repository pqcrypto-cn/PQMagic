#include <stdio.h>
#include "poly.h"

#include <string.h>

#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "hashkdf.h"
#include "api.h"

#if PARAM_Q == 3329
const int16_t NTT_Y[PARAM_N] = {-1103, 1103, 430, -430, 555, -555, 843, -843, -1251, 1251, 871, -871, 1550, -1550, 105, -105, 422, -422, 587, -587, 177, -177, -235, 235, -291, 291, -460, 460, 1574, -1574, 1653, -1653, -246, 246, 778, -778, 1159, -1159, -147, 147, -777, 777, 1483, -1483, -602, 602, 1119, -1119, -1590, 1590, 644, -644, -872, 872, 349, -349, 418, -418, 329, -329, -156, 156, -75, 75, 817, -817, 1097, -1097, 603, -603, 610, -610, 1322, -1322, -1285, 1285, -1465, 1465, 384, -384, -1215, 1215, -136, 136, 1218, -1218, -1335, 1335, -874, 874, 220, -220, -1187, 1187, -1659, 1659, -1185, 1185, -1530, 1530, -1278, 1278, 794, -794, -1510, 1510, -854, 854, -870, 870, 478, -478, -108, 108, -308, 308, 996, -996, 991, -991, 958, -958, -1460, 1460, 1522, -1522, 1628, -1628};
#elif PARAM_Q == 641
const int16_t NTT_Y[NTT_DIM] = {29, -29, -21, 21, 268, -268, 248, -248, 305, -305, 177, -177, 122, -122, 199, -199, -210, 210, -290, 290, -84, 84, -116, 116, -153, 153, 155, -155, 67, -67, 62, -62, -31, 31, -287, 287, 244, -244, -243, 243, -105, 105, -145, 145, -42, 42, -58, 58, -306, 306, 310, -310, 134, -134, 124, -124, -168, 168, -232, 232, 61, -61, -221, 221};
#endif

void poly_caddq(poly *r)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = caddq(r->coeffs[i]);
}
void poly_caddq2(poly *r)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = caddq2(r->coeffs[i]);
}
void poly_reduce(poly *r)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

void poly_ss_getnoise(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETAS_BYTES];
	uint8_t extseed[SEED_BYTES + 1];

	memcpy(extseed, seed, SEED_BYTES);
	extseed[SEED_BYTES] = nonce;

	KDF(buf, ETAS_BYTES, extseed, SEED_BYTES + 1);

	cbd_etas(r, buf);
}

void poly_ee_getnoise(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[ETAE_BYTES];
	uint8_t extseed[SEED_BYTES + 1];

	memcpy(extseed, seed, SEED_BYTES);
	extseed[SEED_BYTES] = nonce;

	KDF(buf, ETAE_BYTES, extseed, SEED_BYTES + 1);

	cbd_etae(r, buf);
}
void poly_compress(uint8_t *r, const poly *a)
{
// assuming the coefficients belong in [0,PARAM_Q)
#if BITS_C2 == 3
	unsigned int i, j, k = 0;
	uint32_t t[8];
	for (i = 0; i < PARAM_N; i += 8)
	{
		for (j = 0; j < 8; j++)
			t[j] = ((((uint32_t)a->coeffs[i + j] << 3) + PARAM_Q / 2) / PARAM_Q) & 7;

		r[k] = t[0] | (t[1] << 3) | (t[2] << 6);
		r[k + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
#elif BITS_C2 == 4
	unsigned int i;
	uint32_t t[2];
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t[0] = ((((uint32_t)a->coeffs[2 * i] << 4) + PARAM_Q / 2) / PARAM_Q) & 0xf;
		t[1] = ((((uint32_t)a->coeffs[2 * i + 1] << 4) + PARAM_Q / 2) / PARAM_Q) & 0xf;
		r[i] = t[0] | (t[1] << 4);
	}
#elif BITS_C2 == 5
	unsigned int i, j, k = 0;
	uint32_t t[8];
	for (i = 0; i < PARAM_N; i += 8)
	{
		for (j = 0; j < 8; j++)
			t[j] = ((((uint32_t)a->coeffs[i + j] << 5) + PARAM_Q / 2) / PARAM_Q) & 0x1f;

		r[k] = t[0] | (t[1] << 5);
		r[k + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
		r[k + 2] = (t[3] >> 1) | (t[4] << 4);
		r[k + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
		r[k + 4] = (t[6] >> 2) | (t[7] << 3);
		k += 5;
	}
#else
#error "poly_compress only supports BITS_C2 in {3,4,5}"
#endif
}
void poly_decompress(poly *r, const uint8_t *a)
{
	unsigned int i;

#if BITS_C2 == 3
	for (i = 0; i < PARAM_N; i += 8)
	{
		r->coeffs[i + 0] = (((a[0] & 7) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 1] = ((((a[0] >> 3) & 7) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 2] = ((((a[0] >> 6) | ((a[1] << 2) & 4)) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 3] = ((((a[1] >> 1) & 7) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 4] = ((((a[1] >> 4) & 7) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 5] = ((((a[1] >> 7) | ((a[2] << 1) & 6)) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 6] = ((((a[2] >> 2) & 7) * PARAM_Q) + 4) >> 3;
		r->coeffs[i + 7] = ((((a[2] >> 5)) * PARAM_Q) + 4) >> 3;
		a += 3;
	}
#elif BITS_C2 == 4
	for (i = 0; i < PARAM_N / 2; i++)
	{
		r->coeffs[2 * i] = (((a[i] & 0xf) * PARAM_Q) + 8) >> 4;
		r->coeffs[2 * i + 1] = ((a[i] >> 4) * PARAM_Q + 8) >> 4;
	}
#elif BITS_C2 == 5
	for (i = 0; i < PARAM_N; i += 8)
	{
		r->coeffs[i + 0] = (((a[0] & 0x1f) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 1] = ((((a[0] >> 5) | ((a[1] & 3) << 3)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 2] = ((((a[1] >> 2) & 0x1f) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 3] = ((((a[1] >> 7) | ((a[2] & 0xf) << 1)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 4] = ((((a[2] >> 4) | ((a[3] & 0x1) << 4)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 5] = ((((a[3] >> 1) & 0x1f) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 6] = ((((a[3] >> 6) | ((a[4] & 0x7) << 2)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 7] = ((((a[4] >> 3)) * PARAM_Q) + 16) >> 5;
		a += 5;
	}
#else
#error "poly_decompress only supports BITS_C2 in {3,4,5}"
#endif
}

void poly_tobytes(uint8_t *r, const poly *a)
{
	int i;
	int16_t t[2];
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t[0] = a->coeffs[2 * i];
		t[1] = a->coeffs[2 * i + 1];

		r[3 * i + 0] = t[0];
		r[3 * i + 1] = (t[0] >> 8) | (t[1] << 4);
		r[3 * i + 2] = (t[1] >> 4);
	}

}
void poly_frombytes(poly *r, const uint8_t *a)
{
	int i;

	for (i = 0; i < PARAM_N / 2; i++)
	{
		r->coeffs[2 * i + 0] = a[3 * i + 0] | (((uint16_t)a[3 * i + 1] & 0x0F) << 8);
		r->coeffs[2 * i + 1] = (a[3 * i + 1] >> 4) | (((uint16_t)a[3 * i + 2]) << 4);
	}

}

static uint16_t flipabs(int16_t x)
{
	int16_t r, m;
	r = caddq(x);

	r = r - PARAM_Q / 2;
	m = r >> 15;
	return (r + m) ^ m;
}

#if NTT_DIM == 128
#if PARAM_N / MSG_BYTES == 16
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES])
{ // encode MSG_BYTES*8 bits in NTT form in possition (0,64) of the noise

	uint16_t i, j, k, msg_mask;

	for (i = 0; i < MSG_BYTES / 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			for (k = 0; k < 8; k++)
			{
				msg_mask = 0 - ((msg[8 * i + j] >> k) & 0x1);
				msg_mask &= (PARAM_Q + 1) / 2;
				r->coeffs[128 * i + 8 * j + k] = msg_mask;
				r->coeffs[128 * i + 8 * j + k + 64] = msg_mask;
			}
		}
	}
}
void poly_tomsg(unsigned char *msg, const poly *x)
{
	int16_t i, j, k;
	uint16_t t;
	for (i = 0; i < MSG_BYTES / 8; i++)
	{
		for (j = 0; j < 8; j++)
		{
			msg[8 * i + j] = 0;
			for (k = 0; k < 8; k++)
			{
				t = flipabs(x->coeffs[128 * i + 8 * j + k]);
				t += flipabs(x->coeffs[128 * i + 8 * j + k + 64]);
				t = t - PARAM_Q / 2;

				t >>= 15;
				msg[8 * i + j] |= t << k;
			}
		}
	}
}
#elif PARAM_N / MSG_BYTES == 32
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES])
{ // encode MSG_BYTES*8 bits in NTT form in possition (0,32,64,96) of the noise
	uint16_t i, j, k, msg_mask;

	for (i = 0; i < MSG_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				msg_mask = 0 - ((msg[4 * i + j] >> k) & 0x1);
				msg_mask &= (PARAM_Q + 1) / 2;
				r->coeffs[128 * i + 8 * j + k] = msg_mask;
				r->coeffs[128 * i + 8 * j + k + 32] = msg_mask;
				r->coeffs[128 * i + 8 * j + k + 64] = msg_mask;
				r->coeffs[128 * i + 8 * j + k + 96] = msg_mask;
			}
		}
	}
}
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly *x)
{
	int16_t i, j, k;
	uint16_t t;
	for (i = 0; i < MSG_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			msg[4 * i + j] = 0;
			for (k = 0; k < 8; k++)
			{
				t = flipabs(x->coeffs[128 * i + 8 * j + k]);
				t += flipabs(x->coeffs[128 * i + 8 * j + k + 32]);
				t += flipabs(x->coeffs[128 * i + 8 * j + k + 64]);
				t += flipabs(x->coeffs[128 * i + 8 * j + k + 96]);
				t = (t - PARAM_Q);

				t >>= 15;
				msg[4 * i + j] |= t << k;
			}
		}
	}
}
#endif
#elif NTT_DIM == 64
#if PARAM_N / MSG_BYTES == 16
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES])
{ // encode 256bits in NTT form in position (0,32) of the noise
	uint16_t i, j, k, msg_mask;

	for (i = 0; i < MSG_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				msg_mask = 0 - ((msg[4 * i + j] >> k) & 0x1);
				msg_mask &= (PARAM_Q + 1) / 2;
				r->coeffs[64 * i + 8 * j + k] = msg_mask;
				r->coeffs[64 * i + 8 * j + k + 32] = msg_mask;
			}
		}
	}
}
void poly_tomsg(unsigned char *msg, const poly *x)
{
	int16_t i, j, k;
	uint16_t t;
	for (i = 0; i < MSG_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			msg[4 * i + j] = 0;
			for (k = 0; k < 8; k++)
			{
				t = flipabs(x->coeffs[64 * i + 8 * j + k]);
				t += flipabs(x->coeffs[64 * i + 8 * j + k + 32]);
				t = t - PARAM_Q / 2;

				t >>= 15;
				msg[4 * i + j] |= t << k;
			}
		}
	}
}
#elif PARAM_N / MSG_BYTES == 32
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES])
{ // encode 256bits in NTT form in possition (0,16,32,48) of the noise
	uint16_t i, j, k, msg_mask;

	for (i = 0; i < MSG_BYTES / 2; i++)
	{
		for (j = 0; j < 2; j++)
		{
			for (k = 0; k < 8; k++)
			{
				msg_mask = 0 - ((msg[2 * i + j] >> k) & 0x1);
				msg_mask &= (PARAM_Q + 1) / 2;
				r->coeffs[64 * i + 8 * j + k] = msg_mask;
				r->coeffs[64 * i + 8 * j + k + 16] = msg_mask;
				r->coeffs[64 * i + 8 * j + k + 32] = msg_mask;
				r->coeffs[64 * i + 8 * j + k + 48] = msg_mask;
			}
		}
	}
}
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly *x)
{
	int16_t i, j, k;
	uint16_t t;
	for (i = 0; i < MSG_BYTES / 2; i++)
	{
		for (j = 0; j < 2; j++)
		{
			msg[2 * i + j] = 0;
			for (k = 0; k < 8; k++)
			{
				t = flipabs(x->coeffs[64 * i + 8 * j + k]);
				t += flipabs(x->coeffs[64 * i + 8 * j + k + 16]);
				t += flipabs(x->coeffs[64 * i + 8 * j + k + 32]);
				t += flipabs(x->coeffs[64 * i + 8 * j + k + 48]);
				t = (t - PARAM_Q);

				t >>= 15;
				msg[2 * i + j] |= t << k;
			}
		}
	}
}
#endif
#endif
void poly_add(poly *r, const poly *a, const poly *b)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}
void poly_sub(poly *r, const poly *a, const poly *b)
{
	int i;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}
void poly_ntt(poly *r)
{
	int i = 0;
	for (i = 0; i < PARAM_N / NTT_DIM; i++)
		ntt(&r->coeffs[i * NTT_DIM]);
}
void poly_invntt(poly *r)
{
	int i = 0;
	for (i = 0; i < PARAM_N / NTT_DIM; i++)
		invntt(&r->coeffs[i * NTT_DIM]);
}
void poly_getmontgomery(poly *r)
{
	int i = 0;
	for (i = 0; i < PARAM_N; i++)
		r->coeffs[i] = montgomery_reduce(1353 * (int32_t)r->coeffs[i]);

}

static inline void mont_mul4(int16_t *r, const int16_t *a, const int16_t *b) // multiplication for degree 3 polynomial/4 coefficients
{
	int32_t t[14];
	int i, j;
	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a[j * NTT_DIM + i]; // a0,a1,a2,a3
		for (j = 0; j < 4; j++)
			t[4 + j] = b[j * NTT_DIM + i]; // b0,b1,b2,b3

		t[8] = montgomery_reduce(t[0] * t[4]);
		t[9] = montgomery_reduce((t[0] + t[1]) * (t[4] + t[5]));
		t[10] = montgomery_reduce(t[1] * t[5]);
		t[9] = t[9] - t[8] - t[10]; // <= 3 *PARAM_Q

		t[11] = montgomery_reduce(t[2] * t[6]);
		t[12] = montgomery_reduce((t[2] + t[3]) * (t[6] + t[7]));
		t[13] = montgomery_reduce(t[3] * t[7]);
		t[12] = t[12] - t[11] - t[13]; // <= 3 *PARAM_Q

		t[0] = t[0] + t[2];
		t[1] = t[1] + t[3];
		t[2] = t[4] + t[6];
		t[3] = t[5] + t[7];

		t[4] = montgomery_reduce(t[0] * t[2]);
		t[5] = montgomery_reduce((t[0] + t[1]) * (t[2] + t[3]));
		t[6] = montgomery_reduce(t[1] * t[3]);
		t[5] = t[5] - t[4] - t[6]; // <= 3 *PARAM_Q

		t[4] = t[4] - t[8] - t[11];	 // <= 3 *PARAM_Q
		t[5] = t[5] - t[9] - t[12];	 // <= 7 *PARAM_Q
		t[6] = t[6] - t[10] - t[13]; // <= 3 *PARAM_Q

// lay reduction so that the coefficient will not exceed 2^15 before the next reduction
#if PARAM_Q == 3329
		r[i] = t[8];
		r[NTT_DIM + i] = barrett_reduce(t[9]);
		r[2 * NTT_DIM + i] = barrett_reduce(t[4] + t[10]);
		r[3 * NTT_DIM + i] = barrett_reduce(t[5]);
		r[4 * NTT_DIM + i] = barrett_reduce(t[6] + t[11]);
		r[5 * NTT_DIM + i] = barrett_reduce(t[12]);
		r[6 * NTT_DIM + i] = t[13];
#else
		r[i] = t[8];					   // <= PARAM_Q
		r[NTT_DIM + i] = t[9];			   // <= 3 *PARAM_Q
		r[2 * NTT_DIM + i] = t[4] + t[10]; // <= 4 *PARAM_Q
		r[3 * NTT_DIM + i] = t[5];		   // <= 7 *PARAM_Q
		r[4 * NTT_DIM + i] = t[6] + t[11]; // <= 4 *PARAM_Q
		r[5 * NTT_DIM + i] = t[12];		   // <= 3 *PARAM_Q
		r[6 * NTT_DIM + i] = t[13];		   // <= PARAM_Q
#endif
	}
}

static inline void mont_mul8(int16_t* r, const int16_t* a, const int16_t* b)
{
	int16_t t1[7 * NTT_DIM], t2[7 * NTT_DIM];
	int i;
	for (i = 0; i < 4 * NTT_DIM; i++)
	{
		t1[i] = a[i] + a[4 * NTT_DIM + i];
		t2[i] = b[i] + b[4 * NTT_DIM + i];
	}
	mont_mul4(t1, t1, t2);
	mont_mul4(&r[8 * NTT_DIM], &a[4 * NTT_DIM], &b[4 * NTT_DIM]);
	mont_mul4(r, a, b);

	for (i = 0; i < NTT_DIM; i++)
		r[7 * NTT_DIM + i] = barrett_reduce(t1[3 * NTT_DIM + i] - r[3 * NTT_DIM + i] - r[11 * NTT_DIM + i]);
	for (i = 0; i < 3 * NTT_DIM; i++)
	{
		t1[i] = barrett_reduce(r[4 * NTT_DIM + i] + t1[i] - r[i] - r[8 * NTT_DIM + i]);
		r[8 * NTT_DIM + i] = barrett_reduce(t1[4 * NTT_DIM + i] - r[4 * NTT_DIM + i] - r[12 * NTT_DIM + i] + r[8 * NTT_DIM + i]);
		r[4 * NTT_DIM + i] = t1[i];
	}
}

#if PARAM_N / NTT_DIM == 4
void poly_mont_mul(poly *r, const poly *a, const poly *b)
{
	int32_t t[14];
	int i, j;
	for (i = 0; i < NTT_DIM; i++)
	{
		for (j = 0; j < 4; j++)
			t[j] = a->coeffs[j * NTT_DIM + i]; // a0,a1,a2,a3
		for (j = 0; j < 4; j++)
			t[4 + j] = b->coeffs[j * NTT_DIM + i]; // b0,b1,b2,b3

		t[8] = montgomery_reduce(t[0] * t[4]);
		t[9] = montgomery_reduce((t[0] + t[1]) * (t[4] + t[5]));
		t[10] = montgomery_reduce(t[1] * t[5]);
		t[9] = t[9] - t[8] - t[10]; // <= 3 *PARAM_Q

		t[11] = montgomery_reduce(t[2] * t[6]);
		t[12] = montgomery_reduce((t[2] + t[3]) * (t[6] + t[7]));
		t[13] = montgomery_reduce(t[3] * t[7]);
		t[12] = t[12] - t[11] - t[13]; // <= 3 *PARAM_Q

		t[0] = t[0] + t[2];
		t[1] = t[1] + t[3];
		t[2] = t[4] + t[6];
		t[3] = t[5] + t[7];

		t[4] = montgomery_reduce(t[0] * t[2]);
		t[5] = montgomery_reduce((t[0] + t[1]) * (t[2] + t[3]));
		t[6] = montgomery_reduce(t[1] * t[3]);
		t[5] = t[5] - t[4] - t[6]; // <= 3 *PARAM_Q

		t[4] = t[4] - t[8] - t[11];			 // <= 3 *PARAM_Q
		t[5] = t[5] - t[9] - t[12];			 // <= 7 *PARAM_Q
		t[6] = t[6] - t[10] - t[13] + t[11]; // <= 4 *PARAM_Q

		t[6] = montgomery_reduce(t[6] * NTT_Y[i]);
		t[12] = montgomery_reduce(t[12] * NTT_Y[i]);
		t[13] = montgomery_reduce(t[13] * NTT_Y[i]);

// the coefficient may as large as <= 7 *PARAM_Q
// lay reduction so that the coefficient will not exceed 2^15 before the next reduction
#if PARAM_K == 1
		r->coeffs[i] = t[8] + t[6];						   // <= 2 *PARAM_Q
		r->coeffs[NTT_DIM + i] = t[9] + t[12];			   // <= 4 *PARAM_Q
		r->coeffs[2 * NTT_DIM + i] = t[4] + t[10] + t[13]; // <= 5 *PARAM_Q
		r->coeffs[3 * NTT_DIM + i] = t[5];				   // <= 7 *PARAM_Q
#elif PARAM_K == 2
		r->coeffs[i] = t[8] + t[6];
		r->coeffs[NTT_DIM + i] = t[9] + t[12];
		r->coeffs[2 * NTT_DIM + i] = barrett_reduce(t[4] + t[10] + t[13]);
		r->coeffs[3 * NTT_DIM + i] = barrett_reduce(t[5]);
#else
#error "need to do full reduction"
#endif
	}
}
#elif PARAM_N / NTT_DIM == 8
void poly_mont_mul(poly *r, const poly *a, const poly *b)
{
	int16_t t0[PARAM_N], t1[PARAM_N], t2[PARAM_N];
	int i, j;
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t0[i] = a->coeffs[i] + a->coeffs[PARAM_N / 2 + i]; // <=2* PARAM_Q
		t1[i] = b->coeffs[i] + b->coeffs[PARAM_N / 2 + i]; // <=2* PARAM_Q
	}

	mont_mul4(t1, t0, t1);
	mont_mul4(t0, a->coeffs, b->coeffs);
	mont_mul4(t2, &a->coeffs[PARAM_N / 2], &b->coeffs[PARAM_N / 2]);

	for (i = 0; i < 7 * NTT_DIM; i++)
		t1[i] -= (t0[i] + t2[i]); // <=21* PARAM_Q   or <=3* PARAM_Q

	for (i = 0; i < 3 * NTT_DIM; i++)
	{
		t0[4 * NTT_DIM + i] = (t0[4 * NTT_DIM + i] + t1[i]); // <=28* PARAM_Q   or <=4* PARAM_Q
		t2[i] = (t1[4 * NTT_DIM + i] + t2[i]);				 // <=28* PARAM_Q   or <=4* PARAM_Q
	}

	for (i = 0; i < 7; i++)
		for (j = 0; j < NTT_DIM; j++)
			t2[i * NTT_DIM + j] = montgomery_reduce(t2[i * NTT_DIM + j] * NTT_Y[j]);

// lay reduction so that the coefficient will not exceed 2^15 before the next reduction
#if PARAM_K == 1
	for (i = 0; i < 7 * NTT_DIM; i++)
		r->coeffs[i] = t0[i] + t2[i]; // <=29* PARAM_Q   or <=5* PARAM_Q
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[7 * NTT_DIM + i] = t1[3 * NTT_DIM + i]; // <=21* PARAM_Q   or <=3* PARAM_Q
#elif PARAM_K == 2
	for (i = 0; i < 7 * NTT_DIM; i++)
		r->coeffs[i] = barrett_reduce(t0[i] + t2[i]);
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[7 * NTT_DIM + i] = t1[3 * NTT_DIM + i];
#else
#error "need to do full reduction"
#endif
}
#elif PARAM_N / NTT_DIM == 16
void poly_mont_mul(poly *r, const poly *a, const poly *b)
{
	int16_t t0[PARAM_N], t1[PARAM_N], t2[PARAM_N];
	int i, j;
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t0[i] = a->coeffs[i] + a->coeffs[PARAM_N / 2 + i];
		t1[i] = b->coeffs[i] + b->coeffs[PARAM_N / 2 + i];
	}

	mont_mul8(t1, t0, t1);
	mont_mul8(t0, a->coeffs, b->coeffs);
	mont_mul8(t2, &a->coeffs[PARAM_N / 2], &b->coeffs[PARAM_N / 2]);

	for (i = 0; i < 15 * NTT_DIM; i++)
		t1[i] -= (t0[i] + t2[i]);

	for (i = 0; i < 7 * NTT_DIM; i++)
	{
		t0[8 * NTT_DIM + i] = (t0[8 * NTT_DIM + i] + t1[i]);
		t2[i] = (t1[8 * NTT_DIM + i] + t2[i]);
	}

	for (i = 0; i < 15; i++)
		for (j = 0; j < NTT_DIM; j++)
			t2[i * NTT_DIM + j] = montgomery_reduce(t2[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 15 * NTT_DIM; i++)
		r->coeffs[i] = t0[i] + t2[i];
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[15 * NTT_DIM + i] = t1[7 * NTT_DIM + i];
}
#elif PARAM_N / NTT_DIM == 32
void poly_mont_mul(poly *r, const poly *a, const poly *b)
{
	int16_t t0[PARAM_N], t1[PARAM_N], t2[PARAM_N];
	int i, j;
	for (i = 0; i < PARAM_N / 2; i++)
	{
		t0[i] = a->coeffs[i] + a->coeffs[PARAM_N / 2 + i];
		t1[i] = b->coeffs[i] + b->coeffs[PARAM_N / 2 + i];
	}

	mont_mul16(t1, t0, t1);											  //<= 4*PARAM_Q
	mont_mul16(t0, a->coeffs, b->coeffs);							  //<= 4*PARAM_Q
	mont_mul16(t2, &a->coeffs[PARAM_N / 2], &b->coeffs[PARAM_N / 2]); //<= 4*PARAM_Q

	for (i = 0; i < 31 * NTT_DIM; i++)
		t1[i] -= (t0[i] + t2[i]); //<= 12*PARAM_Q

	for (i = 0; i < 15 * NTT_DIM; i++)
	{
		t0[16 * NTT_DIM + i] = (t0[16 * NTT_DIM + i] + t1[i]); //<= 16*PARAM_Q
		t2[i] = (t1[16 * NTT_DIM + i] + t2[i]);				   //<= 16*PARAM_Q
	}

	for (i = 0; i < 31; i++)
		for (j = 0; j < NTT_DIM; j++)
			t2[i * NTT_DIM + j] = montgomery_reduce(t2[i * NTT_DIM + j] * NTT_Y[j]);

	for (i = 0; i < 31 * NTT_DIM; i++)
		r->coeffs[i] = t0[i] + t2[i]; //<= 17*PARAM_Q
	for (i = 0; i < NTT_DIM; i++)
		r->coeffs[31 * NTT_DIM + i] = t1[15 * NTT_DIM + i]; //<= 12*PARAM_Q
}
#endif

