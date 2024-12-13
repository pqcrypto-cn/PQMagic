#include "cbd.h"
#include <immintrin.h>
#include<stdio.h>

#if ETA_S == 1 || ETA_E == 1
static void cbd1(int16_t  *r, const uint8_t *buf)
{
	int i;
	const int16_t tb[4] = {0, 1, -1, 0};
	for (i = 0; i < PARAM_N / 4; i++)
	{
		r[4 * i + 0] = tb[buf[i] & 0x3];
		r[4 * i + 1] = tb[(buf[i] >> 2) & 0x3];
		r[4 * i + 2] = tb[(buf[i] >> 4) & 0x3];
		r[4 * i + 3] = tb[buf[i] >> 6];
	}
}
#endif

#if ETA_S == 2 || ETA_E == 2
static void cbd2(int16_t  *r, const uint8_t *buf)
{
	int i, j;
	uint64_t d, t;
	uint64_t mask55 = 0x5555555555555555;
	int16_t a, b;
	for (i = 0; i < PARAM_N / 16; i++)
	{
		d = *(uint64_t*)&buf[8 * i];
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
#endif

#if ETA_S == 3 || ETA_E == 3
static void cbd3(int16_t  *r, const uint8_t *buf)
{
	unsigned int i,j;
	uint32_t t,d;
	int16_t a,b;

	for(i=0;i<PARAM_N/4;i++) {
		t  = *((uint32_t*)(buf + 3 * i));
		d  = t & 0x00249249;
		d += (t>>1) & 0x00249249;
		d += (t>>2) & 0x00249249;

		for(j=0;j<4;j++) {
            a = (d >> (6*j+0)) & 0x7;
            b = (d >> (6*j+3)) & 0x7;
            r[4*i+j] = a - b;
		}
	}
}
#endif

#if ETA_S == 4 || ETA_E == 4 || ETA_S == 12 || ETA_E == 12
static void cbd4(int16_t  r[PARAM_N], const uint8_t *buf)
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
#endif

#if ETA_S == 8 || ETA_E == 8 || ETA_S == 12 || ETA_E == 12
static void cbd8(int16_t  *r, const uint8_t *buf)
{
	int i, j;
	uint64_t d, t;
	uint64_t mask55 = 0x5555555555555555;
	uint64_t mask33 = 0x3333333333333333;
	uint64_t mask0f = 0x0f0f0f0f0f0f0f0f;
	int16_t a, b;
	for (i = 0; i < PARAM_N / 4; i++)
	{
		d = *(uint64_t*)&buf[8 * i];
		t = d & mask55;
		d = (d >> 1) & mask55;
		t = t + d;

		d = t & mask33;
		t = (t >> 2) & mask33;
		t = t + d;

		d = t & mask0f;
		t = (t >> 4) & mask0f;
		t = t + d;

		for (j = 0; j < 4; j++)
		{
			a = t & 0xff;
			b = (t >> 8) & 0xff;
			r[4 * i + j] = a - b;
			t = t >> 16;
		}

	}
}
#endif

void cbd_etas(poly  *r, const uint8_t *buf)
{
#if ETA_S == 1
	cbd1(r->coeffs, buf);
#elif ETA_S == 2
	cbd2(r->coeffs, buf);
#elif ETA_S == 3
	cbd3(r->coeffs, buf);
#elif ETA_S == 4
	cbd4(r->coeffs, buf);
#elif ETA_S == 8
	cbd8(r->coeffs, buf);
#else
#error "polyvec_etas_getnoise() only supports ETA_S in {1,2,3,4,8}!\n"
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
#elif ETA_E == 4
	cbd4(r->coeffs, buf);
#elif ETA_E == 8
	cbd8(r->coeffs, buf);
#else
#error "polyvec_etae_getnoise() only supports ETA_E in {1,2,3,4,8}!\n"
#endif
}
