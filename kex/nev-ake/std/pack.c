#include "pack.h"
#include "reduce.h"


#if PARAM_Q == 641
static inline void encode6(uint8_t* buf, const uint16_t x[6])
{
	uint32_t t;

	t = x[2];
	t = t * 641 + x[1];
	t = t * 641 + x[0];

	buf[0] = t;
	buf[1] = t >> 8;
	buf[2] = t >> 16;
	buf[3] = t >> 24;

	t = x[5];
	t = t * 641 + x[4];
	t = t * 641 + x[3];

	buf[3] = buf[3] | ((t & 0x0f)<<4);
	buf[4] = t >> 4;
	buf[5] = t >> 12;
	buf[6] = t >> 20;
}
static inline void decode6(uint16_t* x, const uint8_t* buf)
{
	/* useful facts:
	 *    for any x in 2^28, (6700417 * x) >> 32 = floor(x / 641)
	 */

	uint64_t t,r;
	t = (uint32_t)((buf[3] & 0x0f) << 24) | (uint32_t)(buf[2] << 16) | (uint32_t)(buf[1] << 8) | buf[0];
	r = (t * 6700417)>>32;
	x[0] = t - r * 641;

	x[2] = (r * 6700417) >> 32;
	x[1] = r - x[2] * 641;

	t = (uint32_t)(buf[6] << 20) | (uint32_t)(buf[5] << 12) | (uint32_t)(buf[4] << 4) | (buf[3] >> 4);

	r = (t * 6700417) >> 32;
	x[3] = t - r * 641;

	x[5] = (r * 6700417) >> 32;
	x[4] = r - x[5] * 641;

}

void poly_tobytes(uint8_t* r, const poly* a)
{
	int i, j;
	int16_t t[4];
	poly b;

	for (i = 0; i < PARAM_N / 6; i++)
		encode6(&r[7 * i], &a->coeffs[6 * i]);

	t[0] = a->coeffs[6 * i];
	t[1] = a->coeffs[6 * i + 1];
#if PARAM_N == 1024
	t[2] = a->coeffs[6 * i + 2];
	t[3] = a->coeffs[6 * i + 3];
#endif

	r[7 * i] = t[0] & 0xff;
	r[7 * i + 1] = (t[0] >> 8) | ((t[1] & 0x3f) << 2);
#if PARAM_N == 512 || PARAM_N == 2048
	r[7 * i + 2] = t[1] >> 6;
#elif PARAM_N == 1024
	r[7 * i + 2] = (t[1] >> 6) | ((t[2] & 0x0f) << 4);
	r[7 * i + 3] = (t[2] >> 4) | ((t[3] & 0x03) << 6);
	r[7 * i + 4] = (t[3] >> 2) & 0xff;
#endif
}
void poly_frombytes(poly* r, const uint8_t* a)
{
	int i;

	for (i = 0; i < PARAM_N / 6; i++)
		decode6(&r->coeffs[6 * i], &a[7 * i]);

	r->coeffs[6 * i] = a[7 * i] | (((uint16_t)a[7 * i + 1] & 0x03) << 8);
	r->coeffs[6 * i + 1] = (a[7 * i + 1] >> 2) | (((uint16_t)a[7 * i + 2] & 0x0f) << 6);
#if PARAM_N == 1024
	r->coeffs[6 * i + 2] = (a[7 * i + 2] >> 4) | (((uint16_t)a[7 * i + 3] & 0x3f) << 4);
	r->coeffs[6 * i + 3] = (a[7 * i + 3] >> 6) | (((uint16_t)a[7 * i + 4]) << 2);
#endif
}

#elif  PARAM_Q == 1409
static inline void encode16(uint8_t* buf, const uint16_t x[16]) {
	uint32_t t[8];

	for (int i = 0; i < 8; ++i) {
		t[i] = x[2*i+1];
		t[i] = t[i] * 1409 + x[2*i];
	}

	buf[0]  =  t[0] & 0xff;
	buf[1]  = (t[0] >> 8) & 0xff;
	buf[2]  = ((t[0] >> 16) & 0xff) | ((t[1] << 5) & 0xff);
	buf[3]  = (t[1] >> 3) & 0xff;
	buf[4]  = (t[1] >> 11) & 0xff;
	buf[5]  = ((t[1] >> 19) & 0xff) | ((t[2] << 2) & 0xff);
	buf[6]  = (t[2] >> 6) & 0xff;
	buf[7]  = ((t[2] >> 14) & 0xff) | ((t[3] << 7) & 0xff);
	buf[8]  = (t[3] >> 1) & 0xff;
	buf[9]  = (t[3] >> 9) & 0xff;
	buf[10] = ((t[3] >> 17) & 0xff) | ((t[4] << 4) & 0xff);
	buf[11] = (t[4] >> 4) & 0xff;
	buf[12] = (t[4] >> 12) & 0xff;
	buf[13] = ((t[4] >> 20) & 0xff) | ((t[5] << 1) & 0xff);
	buf[14] = (t[5] >> 7) & 0xff;
	buf[15] = ((t[5] >> 15) & 0xff) | ((t[6] << 6) & 0xff);
	buf[16] = (t[6] >> 2) & 0xff;
	buf[17] = (t[6] >> 10) & 0xff;
	buf[18] = ((t[6] >> 18) & 0xff) | ((t[7] << 3) & 0xff);
	buf[19] = (t[7] >> 5) & 0xff;
	buf[20] = (t[7] >> 13) & 0xff;
}

static inline void decode16(uint16_t* x, const uint8_t* buf) {
	uint32_t t[8];

	t[0] = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)(buf[2] & 0x1f) << 16);
	t[1] = ((uint32_t)buf[2] >> 5) | ((uint32_t)buf[3] << 3) | ((uint32_t)buf[4] << 11) | ((uint32_t)(buf[5] & 0x03) << 19);
	t[2] = ((uint32_t)buf[5] >> 2) | ((uint32_t)buf[6] << 6) | ((uint32_t)(buf[7] & 0x7f) << 14);
	t[3] = ((uint32_t)buf[7] >> 7) | ((uint32_t)buf[8] << 1) | ((uint32_t)buf[9] << 9) | ((uint32_t)(buf[10] & 0x0f) << 17);
	t[4] = ((uint32_t)buf[10] >> 4) | ((uint32_t)buf[11] << 4) | ((uint32_t)buf[12] << 12) | ((uint32_t)(buf[13] & 0x01) << 20);
	t[5] = ((uint32_t)buf[13] >> 1) | ((uint32_t)buf[14] << 7) | ((uint32_t)(buf[15] & 0x3f) << 15);
	t[6] = ((uint32_t)buf[15] >> 6) | ((uint32_t)buf[16] << 2) | ((uint32_t)buf[17] << 10) | ((uint32_t)(buf[18] & 0x07) << 18);
	t[7] = ((uint32_t)buf[18] >> 3) | ((uint32_t)buf[19] << 5) | ((uint32_t)buf[20] << 13);

	for (int i = 0; i < 8; ++i) {
		// x[2*i] = t[i] % 1409;
		// x[2*i+1] = t[i] / 1409;
		x[2*i+1] = ((uint64_t)t[i] * 3048238) >> 32;
		x[2*i] = t[i] - x[2*i+1] * 1409;
	}
}

void poly_tobytes(uint8_t* r, const poly* a)
{
	int i;

	for (i = 0; i < PARAM_N / 16; i++)
		encode16(&r[21 * i], &a->coeffs[16 * i]);

}
void poly_frombytes(poly* r, const uint8_t* a)
{
	int i;
	for (i = 0; i < PARAM_N / 16; i++)
		decode16(&r->coeffs[16 * i], &a[21 * i]);
}

#elif  PARAM_Q == 3329
static inline void encode2(uint8_t buf[3], const uint16_t x[2])
{
	buf[0] = (uint8_t)x[0];
	buf[1] = (uint8_t)((x[0] >> 8) | (x[1] << 4));
	buf[2] = (uint8_t)(x[1] >> 4);
}

static inline void decode2(uint16_t x[2], const uint8_t buf[3])
{
	x[0] = (uint16_t)buf[0]
		 | ((uint16_t)(buf[1] & 0x0f) << 8);

	x[1] = ((uint16_t)buf[1] >> 4)
		 | ((uint16_t)buf[2] << 4);
}

void poly_tobytes(uint8_t *r, const poly *a)
{
	int i;

	for (i = 0; i < PARAM_N / 2; ++i)
		encode2(&r[3 * i], &a->coeffs[2 * i]);
}

void poly_frombytes(poly *r, const uint8_t *a)
{
	int i;

	for (i = 0; i < PARAM_N / 2; ++i)
		decode2(&r->coeffs[2 * i], &a[3 * i]);
}
#elif  PARAM_Q == 769

void encode5(uint8_t *buf, const uint16_t x[5])
{
	int i;
	uint32_t wl, wh;
	uint32_t t;
	uint32_t s;

	wl = x[0] & 0x07;
	for (i = 1; i < 5; i++)
		wl |= (uint32_t)(x[i] & 0x07) << (3 * i);

	wl <<= 1;
	wh = x[4] >> 3;
	for (i = 3; i > 0; i--)
		wh = (wh * 97) + (x[i] >> 3);

	t = wh * 48;
	wl |= t >> 31;
	t <<= 1;
	wh = wh + (x[0] >> 3);
	wh = t + wh;
	wl |= ((t & ~wh) >> 31);

	buf[0] = wl;
	buf[1] = wl >> 8;
	buf[2] = wh;
	for (i = 3; i < 6; i++)
	{
		wh = wh >> 8;
		buf[i] = wh;
	}
}
void decode5(uint16_t *x, const uint8_t *buf)
{
	/*
	 * Useful facts:
	 *    512 = 27 mod 97
	 *    2^19 = 3 mod 97
	 *    for any x in 0..57519, (43241 * x) >> 22 = floor(x / 97)
	 *    97 * 1594008481 = 1 mod 2^32
	 */

	uint32_t wl, wh, z;
	int i;

	wl = (uint32_t)(buf[1] << 8) | buf[0];
	wh = buf[5];
	for (i = 4; i > 1; i--)
		wh = (wh << 8) | (uint32_t)buf[i];

	z = (((wl & 0x01) << 13) | (wh >> 19)) * 3;
	z += wh & 0x7FFFF;
	wl >>= 1;

	z = (z >> 9) * 27 + (z & 0x1FF);
	z -= ((z * 43241) >> 22) * 97;

	x[0] = (z << 3) + (wl & 0x07);
	wl >>= 3;

	wh -= z;
	wh = wh * 1594008481u;

	z = (wh >> 19) * 3 + (wh & 0x7FFFF);
	z = (z >> 9) * 27 + (z & 0x1FF);
	z -= ((z * 43241) >> 22) * 97;

	x[1] = (z << 3) + (wl & 0x07);
	wl >>= 3;

	wh -= z;
	wh = wh * 1594008481u;

	z = (wh >> 9) * 27 + (wh & 0x1FF);
	z -= ((z * 43241) >> 22) * 97;

	x[2] = (z << 3) + (wl & 0x07);
	wl >>= 3;

	wh -= z;
	z = wh * 1594008481u;

	wh = (z * 43241) >> 22;
	z -= wh * 97;

	x[3] = (z << 3) + (wl & 0x07);
	wl >>= 3;

	x[4] = (wh << 3) + wl;

}

void poly_tobytes(uint8_t *r, const poly *a)
{
	int i;
	uint16_t t[4];

	for (i = 0; i < PARAM_N / 5; ++i)
		encode5(&r[6 * i], &a->coeffs[5 * i]);

	t[0] = a->coeffs[5 * i];
	t[1] = a->coeffs[5 * i + 1];

#if PARAM_N == 512
	r[6 * i] = t[0];
	r[6 * i + 1] = (t[0] >> 8) | (t[1] << 2);
	r[6 * i + 2] = t[1] >> 6;

#elif PARAM_N == 1024
	t[2] = a->coeffs[5 * i + 2];
	t[3] = a->coeffs[5 * i + 3];

	r[6 * i] = t[0];
	r[6 * i + 1] = (t[0] >> 8) | (t[1] << 2);
	r[6 * i + 2] = (t[1] >> 6) | (t[2] << 4);
	r[6 * i + 3] = (t[2] >> 4) | (t[3] << 6);
	r[6 * i + 4] = t[3] >> 2;

#elif PARAM_N == 2048
	t[2] = a->coeffs[5 * i + 2];

	r[6 * i] = t[0];
	r[6 * i + 1] = (t[0] >> 8) | (t[1] << 2);
	r[6 * i + 2] = (t[1] >> 6) | (t[2] << 4);
	r[6 * i + 3] = t[2] >> 4;
#endif
}

void poly_frombytes(poly *r, const uint8_t *a)
{
	int i;

	for (i = 0; i < PARAM_N / 5; ++i)
		decode5(&r->coeffs[5 * i], &a[6 * i]);

	r->coeffs[5 * i] =
		(uint16_t)a[6 * i]
		| (((uint16_t)a[6 * i + 1] & 0x03) << 8);

	r->coeffs[5 * i + 1] =
		((uint16_t)a[6 * i + 1] >> 2)
		| (((uint16_t)a[6 * i + 2] & 0x0f) << 6);

#if PARAM_N == 1024
	r->coeffs[5 * i + 2] =
		((uint16_t)a[6 * i + 2] >> 4)
		| (((uint16_t)a[6 * i + 3] & 0x3f) << 4);

	r->coeffs[5 * i + 3] =
		((uint16_t)a[6 * i + 3] >> 6)
		| ((uint16_t)a[6 * i + 4] << 2);

#elif PARAM_N == 2048
	r->coeffs[5 * i + 2] =
		((uint16_t)a[6 * i + 2] >> 4)
		| (((uint16_t)a[6 * i + 3] & 0x3f) << 4);
#endif
}

#endif



static uint16_t flipabs(int16_t x)
{
	int16_t r, m;
	r = caddq(x);

	r = r - PARAM_Q / 2;
	m = r >> 15;
	return (r + m) ^ m;
}

#if NTT_DIM == 64
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly* x)
{
	int16_t i, j, k;
	uint16_t t;
	for (i = 0; i < SEED_BYTES/2; i++)
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
#elif NTT_DIM == 128
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly* x)
{
	int16_t i, j, k;
	uint16_t t;

	for (i = 0; i < SEED_BYTES / 4; i++)
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

				t = t - PARAM_Q;
				t >>= 15;

				msg[4 * i + j] |= t << k;
			}
		}
	}
}

#endif

void poly_compress(uint8_t *r, const poly *a)
{
	unsigned int i;
	uint32_t t;

	for (i = 0; i < PARAM_N; ++i) {
		t = ((uint32_t)a->coeffs[i] * 341U + 469U) >> 10;
		r[i] = (uint8_t)(t & 0xff);
	}
}

void poly_decompress(poly *r, const uint8_t *a)
{
	unsigned int i;

	for (i = 0; i < PARAM_N; ++i) {
		r->coeffs[i] = (int16_t)(((uint32_t)a[i] * PARAM_Q + (1U << 7)) >> 8);
	}
}