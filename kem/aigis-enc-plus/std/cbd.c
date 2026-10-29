#include "cbd.h"
#include<stdio.h>

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
static inline uint64_t load64_littleedian(const uint8_t *x) {
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
void cbd2(int16_t  *r, const uint8_t *buf)
{
	int i, j;
	uint64_t d, t;
	uint64_t mask55 = 0x5555555555555555;
	int16_t a, b;
	for (i = 0; i < PARAM_N / 16; i++)
	{
		d = load64_littleedian(buf + 8 * i);
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

void cbd3(int16_t  r[PARAM_N], const uint8_t* buf)
{
	int16_t t[PARAM_N];
	int i;
	cbd1(r, buf);
	cbd2(t, buf + PARAM_N/4);
	for (i = 0; i < PARAM_N; i++)
		r[i] = r[i] + t[i];
}

void cbd4(int16_t  r[PARAM_N], const uint8_t *buf)
{
	int i,j;
	uint64_t d, t;
	uint64_t mask33 = 0x3333333333333333;
	uint64_t mask55 = 0x5555555555555555;
	int16_t a,b;
	for (i = 0; i < PARAM_N / 8; i++)
	{
		d = *(uint64_t*)&buf[8*i];
		t = d & mask55;
		d = (d >> 1) & mask55;
		t = t + d;
		
		d = t & mask33;
		t = (t >> 2) & mask33;
		t = t + d;
		for (j = 0; j < 8; j++)
		{
			a = t & 0xf;
			b = (t>>4) & 0xf;
			r[8 * i + j] = a - b;
			t = t >> 8;
		}
	}
}

void cbd5(int16_t  r[PARAM_N], const uint8_t* buf)
{
	int16_t  t[PARAM_N];
	int i;
	cbd4(r, buf);
	cbd1(t, buf + PARAM_N);
	for (i = 0; i < PARAM_N; i++)
		r[i] = r[i] + t[i];
}

void cbd6(int16_t  r[PARAM_N], const uint8_t* buf)
{
	int16_t  t[PARAM_N];
	int i;
	cbd4(r, buf);
	cbd2(t, buf + PARAM_N);
	for (i = 0; i < PARAM_N; i++)
		r[i] = r[i] + t[i];
}

void cbd_etas(poly  *r, const uint8_t *buf)
{
#if ETA_S == 1
	cbd1(r->coeffs, buf);
#elif ETA_S == 2
	cbd2(r->coeffs, buf);
#elif ETA_S == 3
	cbd3(r->coeffs, buf);
#elif ETA_S == 5
	cbd5(r->coeffs, buf);
#elif ETA_S == 6
	cbd6(r->coeffs, buf);
#else
#error "polyvec_etas_getnoise() only supports ETA_S in {1,2,3,6}!\n"
#endif
}

void cbd_etae(poly  *r, const uint8_t *buf)
{
#if ETA_E == 1
	cbd1(r->coeffs, buf);
#elif ETA_E == 2
	cbd2(r->coeffs, buf);
#elif ETA_E == 3
	cbd3(r->coeffs, buf);
#elif ETA_E == 5
	cbd5(r->coeffs, buf);
#elif ETA_E == 6
	cbd6(r->coeffs, buf);
#else
#error "polyvec_etae_getnoise() only supports ETA_E in {1,2,3,6}!\n"
#endif
}
