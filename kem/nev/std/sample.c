#include "sample.h"

#include <string.h>

#include "api.h"

static inline uint64_t load_to_64(const uint8_t *x) {
	uint64_t r = (uint64_t)x[0]
				| ((uint64_t)x[1] << 8)
				| ((uint64_t)x[2] << 16)
				| ((uint64_t)x[3] << 24)
				| ((uint64_t)x[4] << 32)
				| ((uint64_t)x[5] << 40)
				| ((uint64_t)x[6] << 48)
				| ((uint64_t)x[7] << 56);
	return r;
}

void cbd1(int16_t  *a, const uint8_t *buf)
{
	for (int i = 0; i < PARAM_N / 4; i++)
	{
        uint8_t b = buf[i];
		a[4 * i + 0] = (b & 1) - ((b >> 1) & 1);
		a[4 * i + 1] = ((b >> 2) & 1) - ((b >> 3) & 1);
		a[4 * i + 2] = ((b >> 4) & 1) - ((b >> 5) & 1);
		a[4 * i + 3] = ((b >> 6) & 1) - ((b >> 7) & 1);
	}
}

void cbd2(int16_t *r, const uint8_t *buf)
{
	int i, j;
	uint64_t d, t;
	uint64_t mask55 = 0x5555555555555555;
	int16_t a, b;
	for (i = 0; i < PARAM_N / 16; i++)
	{
		d = load_to_64(buf + 8 * i);
		t = d & mask55;
		d = (d >> 1) & mask55;
		t = t + d;
		for (j = 0; j < 16; j++)
		{
			a = t & 0x3;
			b = (t >> 2) & 0x3;
			r[16 * i + j] = a - b;
			t = t >> 4;
		}
	}
}
void cbd3(int16_t r[PARAM_N], const uint8_t* buf)
{
	int16_t t[PARAM_N];
	int i;
	cbd1(r, buf);
	cbd2(t, buf + PARAM_N/4);
	for (i = 0; i < PARAM_N; i++)
		r[i] = r[i] + t[i];
}

void cbd4(int16_t *r, const uint8_t *buf) {
	int16_t a, b;
	uint32_t x;
	const uint8_t mask1 = 0x55;
	const uint8_t mask2 = 0x33;
	const uint8_t mask3 = 0xf;
	for (int i = 0; i < PARAM_N; i++) {
		x = buf[i];
		x -= (x >> 1) & mask1;
		x = (x & mask2) + ((x >> 2) & mask2);
		a = x & mask3;
		b = (x >> 4) & mask3;
		r[i] = a - b;
	}
}

void cbd7(int16_t r[PARAM_N], const uint8_t* buf)
{
	int16_t t[PARAM_N];
	cbd4(r, buf);
	cbd3(t, buf + PARAM_N);
	for (int i = 0; i < PARAM_N; i++)
		r[i] = r[i] + t[i];
}

int ternary3(int16_t *r, const uint8_t *buf, int n, int buf_len) {
	int pos = 0;
	int8_t coeffs[5];
	uint8_t x;
	for (int i = 0; pos < n && i < buf_len; i++) {
		x = buf[i];
		if (x < 243) {
			uint32_t y = x, q;
			q = (y * 0xAAABu) >> 17; coeffs[0] = 1 - (y - 3*q); y = q;
			q = (y * 0xAAABu) >> 17; coeffs[1] = 1 - (y - 3*q); y = q;
			q = (y * 0xAAABu) >> 17; coeffs[2] = 1 - (y - 3*q); y = q;
			q = (y * 0xAAABu) >> 17; coeffs[3] = 1 - (y - 3*q); y = q;
			coeffs[4] = 1 - y;
			for (int j = 0; j < 5 && pos < n; ++j) {
				r[pos++] = coeffs[j];
			}
		}
	}
	return pos;
}

void poly_binomial_dist1(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf, PARAM_N / 4, extseed, SEED_BYTES + 1);

	cbd1(r->coeffs, buf);
}
void poly_binomial_dist2(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[PARAM_N / 2];
	uint8_t extseed[SEED_BYTES + 1];
	int16_t a;
	int i, j, pos;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf, PARAM_N / 2, extseed, SEED_BYTES + 1);
	cbd2(r->coeffs, buf);
}
void poly_binomial_dist3(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[PARAM_N / 2 + PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf, PARAM_N / 2 + PARAM_N / 4, extseed, SEED_BYTES + 1);
	cbd3(r->coeffs, buf);
}

void poly_binomial_dist4(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[PARAM_N];
	uint8_t extseed[SEED_BYTES + 1];
	int i;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf, PARAM_N, extseed, SEED_BYTES + 1);
	cbd4(r->coeffs, buf);
}
void poly_binomial_dist7(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[PARAM_N + PARAM_N / 2 + PARAM_N / 4];
	uint8_t extseed[SEED_BYTES + 1];
	int i;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf, PARAM_N + PARAM_N / 2 + PARAM_N / 4, extseed, SEED_BYTES + 1);
	cbd7(r->coeffs, buf);
}
void poly_bias8_ternary(poly *r, const uint8_t *seed, uint8_t nonce)
{
	uint8_t buf[3 * PARAM_N/8];
	uint8_t extseed[SEED_BYTES + 1];
	int16_t a;
    int16_t b;
	int pos;
	for (int i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf, 3 * PARAM_N / 8, extseed, SEED_BYTES + 1);
	cbd1(r->coeffs, buf);

	pos = 2 * PARAM_N / 8;
	for (int i = 0; i < PARAM_N / 8; i++)
	{
        b = buf[pos++];
		for (int j = 0; j < 8; j++)
		{
			a = -((b >> j) & 0x1);
			r->coeffs[8 * i + j] &= a;
		}
	}
}

void poly_bias3_ternary(poly *r, const uint8_t *seed, uint8_t nonce)
{
	const int min_bytes = (PARAM_N + 4) / 5;
	const int nblocks = (min_bytes + KDF_RATE - 1) / KDF_RATE + 1;
	uint8_t buf[nblocks * KDF_RATE];
	uint8_t block[KDF_RATE];
	uint8_t extseed[SEED_BYTES + 1];
	kdfstate state;
	int ctr;

	memcpy(extseed, seed, SEED_BYTES);
	extseed[SEED_BYTES] = nonce;

	KDF_ABSORB(&state, extseed, SEED_BYTES + 1);
	KDF_SQUEEZEBLOCK(buf, nblocks, &state);
	ctr = ternary3(r->coeffs, buf, PARAM_N, nblocks * KDF_RATE);

	while (ctr < PARAM_N) {
		KDF_SQUEEZEBLOCK(block, 1, &state);
		ctr += ternary3(r->coeffs + ctr, block, PARAM_N - ctr, KDF_RATE);
	}
}

#if NTT_DIM == 64

static void get_noisem_cbd1(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[8 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 7 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 8; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES/2; i++)
	{
		for (j = 0; j < 2; j++)
			for (k = 0; k < 8; k++)
			{
				a = (buf[2 * i + j] >> k) & 0x01;
				b = (buf[SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 8 * j + k] = a - b;

				a = (buf[2* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b = (buf[3* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 16 + 8 * j + k] = a - b;

				a = (buf[4* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b = (buf[5* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 32 + 8 * j + k] = a - b;

				a = (buf[6* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b = (buf[7* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 48 + 8 * j + k] = a - b;
			}
	}
}
static void get_noisem_cbd2(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[16 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 15 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 16; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES/2; i++)
	{
		for (j = 0; j < 2; j++)
			for (k = 0; k < 8; k++)
			{
				a =  (buf[2 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 2 * i + j] >> k) & 0x01;
				b =  (buf[2 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[3 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 8 * j + k] = a - b;

				a =  (buf[4* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[5* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[6* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[7* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 16 + 8 * j + k] = a - b;

				a =  (buf[8* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[9* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[10* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[11* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[12* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[13* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[14* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[15* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 48 + 8 * j + k] = a - b;
			}
	}
}
static void get_noisem_cbd3(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[24 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 23 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 24; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES/2; i++)
	{
		for (j = 0; j < 2; j++)
			for (k = 0; k < 8; k++)
			{
				a =  (buf[2 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 2 * i + j] >> k) & 0x01;
				a += (buf[2 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[3 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[4* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[5* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 8 * j + k] = a - b;


				a =  (buf[6* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[7* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[8* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[9* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[10* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[11* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 16 + 8 * j + k] = a - b;

				a =  (buf[12* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[13* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[14* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[15* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[16* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[17* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[18* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[19* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[20* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[21* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[22* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[23* SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 48 + 8 * j + k] = a - b;
			}
	}
}

static void get_noisem_cbd4(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[32 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 31 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 32; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES/2; i++)
	{
		for (j = 0; j < 2; j++)
			for (k = 0; k < 8; k++)
			{
				a =  (buf[2 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 2 * i + j] >> k) & 0x01;
				a += (buf[2 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[3 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[4 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[5 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[6 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[7 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 8 * j + k] = a - b;


				a =  (buf[8 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[9 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[10 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[11 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[12 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[13 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[14 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[15 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 16 + 8 * j + k] = a - b;

				a =  (buf[16 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[17 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[18 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[19 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[20 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[21 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[22 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[23 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[24 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[25 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[26 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[27 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[28 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[29 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[30 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[31 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 48 + 8 * j + k] = a - b;
			}
	}
}

static void get_noisem_cbd7(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[56 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 55 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 56; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES/2; i++)
	{
		for (j = 0; j < 2; j++)
			for (k = 0; k < 8; k++)
			{
				a =  (buf[2 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 2 * i + j] >> k) & 0x01;
				a += (buf[2 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[3 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[4 * SEED_BYTES + 2 * i + j] >> k) & 0x01;
				a += (buf[5 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[6 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[7 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[8 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[9 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[10 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[11 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[12 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[13 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 8 * j + k] = a - b;


				a =  (buf[14 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[15 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[16 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[17 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[18 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[19 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[20 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[21 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[22 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[23 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[24 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[25 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[26 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[27 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 16 + 8 * j + k] = a - b;

				a =  (buf[28 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[29 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[30 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[31 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[32 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[33 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[34 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[35 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[36 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[37 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[38 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[39 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[40 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[41 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[42 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[43 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[44 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[45 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[46 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[47 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				a += (buf[48 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b =  (buf[49 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[50 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[51 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[52 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[53 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[54 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				b += (buf[55 * SEED_BYTES + 2 * i + j] >> k) & 0x1;
				r->coeffs[64 * i + 48 + 8 * j + k] = a - b;
			}
	}
}
#elif NTT_DIM == 128
static void get_noisem_cbd1(poly *r,
							const uint8_t msg[SEED_BYTES],
							const uint8_t *seed,
							uint8_t nonce)
{
	uint8_t buf[8 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES,
		7 * SEED_BYTES,
		extseed,
		SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 8; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}

	for (i = 0; i < SEED_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				a = (buf[4 * i + j] >> k) & 0x01;
				b = (buf[SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 8 * j + k] = a - b;

				a = (buf[2 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b = (buf[3 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 32 + 8 * j + k] = a - b;

				a = (buf[4 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b = (buf[5 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 64 + 8 * j + k] = a - b;

				a = (buf[6 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b = (buf[7 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 96 + 8 * j + k] = a - b;
			}
		}
	}
}

static void get_noisem_cbd2(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[16 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 15 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 16; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				a =  (buf[4 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[2 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[3 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 8 * j + k] = a - b;

				a =  (buf[4 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[5 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[6 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[7 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[8 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[9 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[10 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[11 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 64 + 8 * j + k] = a - b;

				a =  (buf[12 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[13 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[14 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[15 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 96 + 8 * j + k] = a - b;
			}
		}
	}
}
static void get_noisem_cbd3(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[24 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 23 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 24; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				a =  (buf[4 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[2 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[3 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[4 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[5 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 8 * j + k] = a - b;

				a =  (buf[6 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[7 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[8 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[9 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[10 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[11 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[12 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[13 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[14 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[15 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[16 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[17 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 64 + 8 * j + k] = a - b;

				a =  (buf[18 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[19 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[20 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[21 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[22 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[23 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 96 + 8 * j + k] = a - b;
			}
		}
	}
}
static void get_noisem_cbd4(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[32 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 31 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 32; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				a =  (buf[4 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[2 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[3 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[4 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[5 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[6 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[7 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 8 * j + k] = a - b;

				a =  (buf[8 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[9 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[10 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[11 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[12 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[13 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[14 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[15 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[16 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[17 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[18 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[19 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[20 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[21 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[22 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[23 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 64 + 8 * j + k] = a - b;

				a =  (buf[24 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[25 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[26 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[27 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[28 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[29 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[30 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[31 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 96 + 8 * j + k] = a - b;
			}
		}
	}
}
static void get_noisem_cbd7(poly *r, const uint8_t msg[SEED_BYTES], const uint8_t *seed, uint8_t nonce) {
	uint8_t buf[56 * SEED_BYTES];
	uint8_t extseed[SEED_BYTES + 1];
	int i, j, k;
	int16_t a, b;
	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	KDF(buf + SEED_BYTES, 55 * SEED_BYTES, extseed, SEED_BYTES + 1);

	for (i = 0; i < SEED_BYTES; i++)
	{
		buf[i] = msg[i];
		for (j = 1; j < 56; j++)
			buf[i] ^= buf[SEED_BYTES * j + i];
	}
	for (i = 0; i < SEED_BYTES / 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 8; k++)
			{
				a =  (buf[4 * i + j] >> k) & 0x01;
				a += (buf[SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[2 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[3 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[4 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[5 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[6 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[7 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[8 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[9 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[10 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[11 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[12 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[13 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 8 * j + k] = a - b;

				a =  (buf[14 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[15 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[16 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[17 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[18 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[19 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[20 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[21 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[22 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[23 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[24 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[25 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[26 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[27 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 32 + 8 * j + k] = a - b;

				a =  (buf[28 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[29 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[30 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[31 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[32 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[33 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[34 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[35 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[36 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[37 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[38 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[39 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[40 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[41 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 64 + 8 * j + k] = a - b;

				a =  (buf[42 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[43 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[44 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[45 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[46 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[47 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				a += (buf[48 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b =  (buf[49 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[50 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[51 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[52 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[53 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[54 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				b += (buf[55 * SEED_BYTES + 4 * i + j] >> k) & 0x01;
				r->coeffs[128 * i + 96 + 8 * j + k] = a - b;
			}
		}
	}
}
#endif

void poly_sample_f(poly *f, uint8_t *seed, uint8_t nonce)
{
#if ETA_F == 1
    poly_binomial_dist1(f, seed, nonce);
#elif ETA_F == 2
	poly_binomial_dist2(f, seed, nonce);
#elif ETA_F == 3
	poly_binomial_dist3(f, seed, nonce);
#elif ETA_F == 4
	poly_binomial_dist4(f, seed, nonce);
#elif ETA_F == 7
	poly_binomial_dist7(f, seed, nonce);
#elif ETA_F == 8
    poly_bias8_ternary(f, seed, nonce);
#elif ETA_F == 9
    poly_bias3_ternary(f, seed, nonce);
#endif
}

void poly_sample_g(poly *g, uint8_t *seed, uint8_t nonce)
{
#if ETA_G == 1
	poly_binomial_dist1(g, seed, nonce);
#elif ETA_G == 2
	poly_binomial_dist2(g, seed, nonce);
#elif ETA_G == 3
	poly_binomial_dist3(g, seed, nonce);
#elif ETA_G == 4
	poly_binomial_dist4(g, seed, nonce);
#elif ETA_G == 7
	poly_binomial_dist7(g, seed, nonce);
#elif ETA_G == 8
	poly_bias8_ternary(g, seed, nonce);
#elif ETA_G == 9
	poly_bias3_ternary(g, seed, nonce);
#endif
}

void poly_sample_r(poly *r, uint8_t *coins, uint8_t nonce)
{
#if ETA_R == 1
	poly_binomial_dist1(r, coins, nonce);
#elif ETA_R == 2
	poly_binomial_dist2(r, coins, nonce);
#elif ETA_R == 3
	poly_binomial_dist3(r, coins, nonce);
#elif ETA_R == 4
	poly_binomial_dist4(r, coins, nonce);
#elif ETA_R == 7
	poly_binomial_dist7(r, coins, nonce);
#elif ETA_R == 8
	poly_bias8_ternary(r, coins, nonce);
#elif ETA_R == 9
	poly_bias3_ternary(r, coins, nonce);
#endif
}

void poly_get_noisem(poly* r, const uint8_t msg[SEED_BYTES], const uint8_t* seed, uint8_t nonce)
{
#if ETA_E == 1
	get_noisem_cbd1(r,msg,seed,nonce);
#elif ETA_E == 2
	get_noisem_cbd2(r,msg,seed,nonce);
#elif ETA_E == 3
	get_noisem_cbd3(r,msg,seed,nonce);
#elif ETA_E == 4
	get_noisem_cbd4(r,msg,seed,nonce);
#elif ETA_E == 7
	get_noisem_cbd7(r,msg,seed,nonce);
#endif
}