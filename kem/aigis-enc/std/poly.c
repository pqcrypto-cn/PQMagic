#include <stdio.h>
#include "align.h"
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "hashkdf.h"

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
static int rej_uniform(int16_t *r, int *cur, int n, const uint8_t *buf, int buflen)
{
	int ctr, pos;
	int16_t val[8];
	ctr = *cur;
	pos = 0;

	while (ctr + 8 <= n && pos + QBITS <= buflen)
	{
#if PARAM_Q == 7681
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		val[1] = ((buf[pos+1]>>5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		val[7] = ((buf[pos + 11] >> 3)| ((uint16_t)buf[pos + 12] << 5));
#elif PARAM_Q == 12289
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		val[1] = ((buf[pos + 1] >> 6) | ((uint16_t)buf[pos + 2] << 2) | ((uint16_t)buf[pos + 3] << 10)) & 0x3fff;
		val[2] = ((buf[pos + 3] >> 4) | ((uint16_t)buf[pos + 4] << 4) | ((uint16_t)buf[pos + 5] << 12)) & 0x3fff;
		val[3] = ((buf[pos + 5] >> 2) | ((uint16_t)buf[pos + 6] << 6));
		val[4] = (buf[pos + 7] | ((uint16_t)buf[pos + 8] << 8)) & 0x3fff;
		val[5] = ((buf[pos + 8] >> 6) | ((uint16_t)buf[pos + 9] << 2) | ((uint16_t)buf[pos + 10] << 10)) & 0x3fff;
		val[6] = ((buf[pos + 10] >> 4) | ((uint16_t)buf[pos + 11] << 4) | ((uint16_t)buf[pos + 12] << 12)) & 0x3fff;
		val[7] = ((buf[pos + 12] >> 2) | ((uint16_t)buf[pos + 13] << 6));
#endif

		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];
		if (val[4] < PARAM_Q)
			r[ctr++] = val[4];
		if (val[5] < PARAM_Q)
			r[ctr++] = val[5];
		if (val[6] < PARAM_Q)
			r[ctr++] = val[6];
		if (val[7] < PARAM_Q)
			r[ctr++] = val[7];
		pos += QBITS;
	}
	if (ctr + 8 <= n)//the random bits are enough, request more bits
	{
		*cur = ctr;
		return pos;
	}
	while (ctr < n && pos + 2 <= buflen)
	{
#if PARAM_Q == 7681
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x1fff;
		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}

		val[1] = ((buf[pos + 1] >> 5) | ((uint16_t)buf[pos + 2] << 3) | ((uint16_t)buf[pos + 3] << 11)) & 0x1fff;
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 4 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 2) | ((uint16_t)buf[pos + 4] << 6)) & 0x1fff;
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];

		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 5;
			break;
		}
		val[3] = ((buf[pos + 4] >> 7) | ((uint16_t)buf[pos + 5] << 1) | ((uint16_t)buf[pos + 6] << 9)) & 0x1fff;
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];

		if (ctr >= n || pos + 8 >= buflen)
		{
			pos += 7;
			break;
		}
		val[4] = ((buf[pos + 6] >> 4) | ((uint16_t)buf[pos + 7] << 4) | ((uint16_t)buf[pos + 8] << 12)) & 0x1fff;
		if (val[4] < PARAM_Q)
			r[ctr++] = val[4];

		if (ctr >= n || pos + 9 >= buflen)
		{
			pos += 9;
			break;
		}
		val[5] = ((buf[pos + 8] >> 1) | ((uint16_t)buf[pos + 9] << 7)) & 0x1fff;
		if (val[5] < PARAM_Q)
			r[ctr++] = val[5];

		if (ctr >= n || pos + 11 >= buflen)
		{
			pos += 10;
			break;
		}
		val[6] = ((buf[pos + 9] >> 6) | ((uint16_t)buf[pos + 10] << 2) | ((uint16_t)buf[pos + 11] << 10)) & 0x1fff;
		if (val[6] < PARAM_Q)
			r[ctr++] = val[6];

		if (ctr >= n || pos + 12 >= buflen)
		{
			pos += 12;
			break;
		}
		val[7] = ((buf[pos + 11] >> 3) | ((uint16_t)buf[pos + 12] << 5));
		if (val[7] < PARAM_Q)
			r[ctr++] = val[7];
		pos += 13;
#elif PARAM_Q == 12289
		val[0] = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0x3fff;
		if (val[0] < PARAM_Q)
			r[ctr++] = val[0];
		if (ctr >= n || pos + 3 >= buflen)
		{
			pos += 2;
			break;
		}
		val[1] = ((buf[pos + 1] >> 6) | ((uint16_t)buf[pos + 2] << 2) | ((uint16_t)buf[pos + 3] << 10)) & 0x3fff;
		if (val[1] < PARAM_Q)
			r[ctr++] = val[1];
		if (ctr >= n || pos + 5 >= buflen)
		{
			pos += 4;
			break;
		}
		val[2] = ((buf[pos + 3] >> 4) | ((uint16_t)buf[pos + 4] << 4) | ((uint16_t)buf[pos + 5] << 12)) & 0x3fff;
		if (val[2] < PARAM_Q)
			r[ctr++] = val[2];
		if (ctr >= n || pos + 6 >= buflen)
		{
			pos += 6;
			break;
		}
		val[3] = ((buf[pos + 5] >> 2) | ((uint16_t)buf[pos + 6] << 6));
		if (val[3] < PARAM_Q)
			r[ctr++] = val[3];
		pos += 7;
#endif
	}
	*cur = ctr;
	return pos;
}
void poly_uniform_seed(poly *r, const uint8_t *seed, int seedbytes)
{
	int cur = 0, pos, step;
	uint8_t buf[REJ_UNIFORM_BYTES + KDF128RATE];
	int nblock = (REJ_UNIFORM_BYTES + KDF128RATE - 1) / KDF128RATE;

	int len;
	kdfstate state;
	kdf128_absorb(&state, seed, seedbytes);
	kdf128_squeezeblocks(buf, nblock, &state);
	len = nblock * KDF128RATE;
	pos = rej_uniform(r->coeffs, &cur, PARAM_N, buf, len);
	len -= pos;
	while (cur < PARAM_N)
	{
		pos -= KDF128RATE;
		len += KDF128RATE;
		kdf128_squeezeblocks(&buf[pos], 1, &state);
		step = rej_uniform(r->coeffs, &cur, PARAM_N, &buf[pos], len);
		pos += step;
		len -= step;
	}
}
void poly_ss_getnoise(poly *r,const uint8_t *seed, uint8_t nonce)
{
  ALIGN(32) uint8_t buf[ETA_S * PARAM_N];
  uint8_t extseed[SEED_BYTES+1];
  int i;

  for(i=0;i<SEED_BYTES;i++)
    extseed[i] = seed[i];
  extseed[SEED_BYTES] = nonce;

  kdf256(buf, ETA_S*PARAM_N / 4, extseed, SEED_BYTES + 1);

  cbd_etas(r, buf);
}
void poly_ee_getnoise(poly *r, const uint8_t *seed, uint8_t nonce)
{
	ALIGN(32) uint8_t buf[ETA_E * PARAM_N];
	uint8_t extseed[SEED_BYTES + 1];
	int i;

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];
	extseed[SEED_BYTES] = nonce;

	kdf256(buf, sizeof(buf), extseed, SEED_BYTES + 1);

	cbd_etae(r, buf);
}
void poly_compress(uint8_t *r, const poly *a)
{
//assuming the coefficients belong in [0,PARAM_Q)
#if BITS_C2 == 3
	unsigned int i, j, k = 0;
	uint32_t t[8];
	for(i=0;i<PARAM_N;i+=8)
	{
		for(j=0;j<8;j++)
			t[j] = ((((uint32_t)a->coeffs[i+j] << 3) + PARAM_Q/2)/PARAM_Q) & 7;

		r[k]   =  t[0]       | (t[1] << 3) | (t[2] << 6);
		r[k+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
		r[k+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
		k += 3;
	}
#elif BITS_C2 == 4
	unsigned int i;
	uint32_t t[2];
	for (i = 0; i<PARAM_N / 2; i++)
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
#elif BITS_C2 == 7
	unsigned int i, j, k = 0;
	uint32_t t[8];
	for (i = 0; i < PARAM_N; i += 8)
	{
		for (j = 0; j < 8; j++)
			t[j] = ((((uint32_t)a->coeffs[i + j] << 7) + PARAM_Q / 2) / PARAM_Q) & 0x7f;

		r[k] = t[0] | (t[1] << 7);
		r[k + 1] = (t[1] >> 1) | (t[2] << 6);
		r[k + 2] = (t[2] >> 2) | (t[3] << 5);
		r[k + 3] = (t[3] >> 3) | (t[4] << 4);
		r[k + 4] = (t[4] >> 4) | (t[5] << 3);
		r[k + 5] = (t[5] >> 5) | (t[6] << 2);
		r[k + 6] = (t[6] >> 6) | (t[7] << 1);
		k += 7;
	}
#else
#error "poly_compress only supports BITS_C2 in {3,4}"
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
		r->coeffs[2 * i + 1] = ((a[i] >> 4)* PARAM_Q + 8) >> 4;
	}
#elif BITS_C2 == 5
	for (i = 0; i < PARAM_N; i += 8)
	{
		r->coeffs[i + 0] = (((a[0] & 0x1f) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 1] = ((((a[0] >> 5) | ((a[1] & 3) << 3)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 2] = ((((a[1] >> 2) & 0x1f) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 3] = ((((a[1] >> 7) | ((a[2] & 0xf)<<1)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 4] = ((((a[2] >> 4) | ((a[3] & 0x1)<<4)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 5] = ((((a[3] >> 1) & 0x1f) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 6] = ((((a[3] >> 6) | ((a[4] & 0x7)<<2)) * PARAM_Q) + 16) >> 5;
		r->coeffs[i + 7] = ((((a[4] >> 3)) * PARAM_Q) + 16) >> 5;
		a += 5;
	}
#elif BITS_C2 == 7
	for (i = 0; i < PARAM_N; i += 8)
	{
		r->coeffs[i + 0] = (((a[0] & 0x7f) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 1] = ((((a[0] >> 7) | ((a[1] & 0x3f) << 1)) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 2] = ((((a[1] >> 6) | ((a[2] & 0x1f) << 2)) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 3] = ((((a[2] >> 5) | ((a[3] & 0xf) << 3)) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 4] = ((((a[3] >> 4) | ((a[4] & 0x7) << 4)) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 5] = ((((a[4] >> 3) | ((a[5] & 0x3) << 5)) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 6] = ((((a[5] >> 2) | ((a[6] & 0x1) << 6)) * PARAM_Q) + 64) >> 7;
		r->coeffs[i + 7] = ((((a[6] >> 1)) * PARAM_Q) + 64) >> 7;
		a += 7;
	}
#else
#error "poly_decompress only supports BITS_C2 in {3,4,5,7}"
#endif
}
void poly_tobytes(uint8_t *r, const poly *a)
{
  
#if PARAM_Q == 7681
  int i,j;
  int16_t t[8];
  for(i=0;i<PARAM_N/8;i++)
  {
    for(j=0;j<8;j++)
      t[j] = a->coeffs[8*i+j];

    r[13*i+ 0] =  t[0]        & 0xff;
    r[13*i+ 1] = (t[0] >>  8) | ((t[1] & 0x07) << 5);
    r[13*i+ 2] = (t[1] >>  3) & 0xff;
    r[13*i+ 3] = (t[1] >> 11) | ((t[2] & 0x3f) << 2);
    r[13*i+ 4] = (t[2] >>  6) | ((t[3] & 0x01) << 7);
    r[13*i+ 5] = (t[3] >>  1) & 0xff;
    r[13*i+ 6] = (t[3] >>  9) | ((t[4] & 0x0f) << 4);
    r[13*i+ 7] = (t[4] >>  4) & 0xff;
    r[13*i+ 8] = (t[4] >> 12) | ((t[5] & 0x7f) << 1);
    r[13*i+ 9] = (t[5] >>  7) | ((t[6] & 0x03) << 6);
    r[13*i+10] = (t[6] >>  2) & 0xff;
    r[13*i+11] = (t[6] >> 10) | ((t[7] & 0x1f) << 3);
    r[13*i+12] = (t[7] >>  5);
  }
#elif PARAM_Q == 12289
  int i,j;
  uint16_t t[4];
  for(i=0;i<PARAM_N/4;i++)
  {
	  for(j=0;j<4;j++)
		  t[j] = amodq(a->coeffs[4*i+j]);

	  r[7*i+ 0] =  t[0]        & 0xff;
	  r[7*i+ 1] = (t[0] >>  8) | ((t[1] & 0x03) << 6);
	  r[7*i+ 2] = (t[1] >>  2) & 0xff;
	  r[7*i+ 3] = (t[1] >> 10) | ((t[2] & 0x0f) << 4);
	  r[7*i+ 4] = (t[2] >>  4) & 0xff;
	  r[7*i+ 5] = (t[2] >>  12) | ((t[3]& 0x3f) <<2);
	  r[7*i+ 6] = (t[3] >>  6);
  }
#endif
}
void poly_frombytes(poly *r, const uint8_t *a)
{
  int i;

#if PARAM_Q == 3329
  for(i=0;i<PARAM_N/2;i++)
  {
	  r->coeffs[2*i+ 0] =  a[3*i+ 0]       | (((uint16_t)a[3*i+ 1] & 0x0f) << 8);
	  r->coeffs[2*i+ 1] = (a[3*i+ 1] >> 4) | (((uint16_t)a[3*i+ 2]      ) << 4);
  }
#elif PARAM_Q == 7681
  for(i=0;i<PARAM_N/8;i++)
  {
    r->coeffs[8*i+0] =  a[13*i+ 0]       | (((uint16_t)a[13*i+ 1] & 0x1f) << 8);
    r->coeffs[8*i+1] = (a[13*i+ 1] >> 5) | (((uint16_t)a[13*i+ 2]       ) << 3) | (((uint16_t)a[13*i+ 3] & 0x03) << 11);
    r->coeffs[8*i+2] = (a[13*i+ 3] >> 2) | (((uint16_t)a[13*i+ 4] & 0x7f) << 6);
    r->coeffs[8*i+3] = (a[13*i+ 4] >> 7) | (((uint16_t)a[13*i+ 5]       ) << 1) | (((uint16_t)a[13*i+ 6] & 0x0f) <<  9);
    r->coeffs[8*i+4] = (a[13*i+ 6] >> 4) | (((uint16_t)a[13*i+ 7]       ) << 4) | (((uint16_t)a[13*i+ 8] & 0x01) << 12);
    r->coeffs[8*i+5] = (a[13*i+ 8] >> 1) | (((uint16_t)a[13*i+ 9] & 0x3f) << 7);
    r->coeffs[8*i+6] = (a[13*i+ 9] >> 6) | (((uint16_t)a[13*i+10]       ) << 2) | (((uint16_t)a[13*i+11] & 0x07) << 10);
    r->coeffs[8*i+7] = (a[13*i+11] >> 3) | (((uint16_t)a[13*i+12]       ) << 5);
  }
#elif PARAM_Q == 12289
  for(i=0;i<PARAM_N/4;i++)
  {
	  r->coeffs[4*i+0] =  a[7*i+ 0]       | (((uint16_t)a[7*i+ 1] & 0x3f) << 8);
	  r->coeffs[4*i+1] = (a[7*i+ 1] >> 6) | (((uint16_t)a[7*i+ 2]       ) << 2) | (((uint16_t)a[7*i+ 3] & 0x0f) << 10);
	  r->coeffs[4*i+2] = (a[7*i+ 3] >> 4) | (((uint16_t)a[7*i+ 4]       ) << 4) | (((uint16_t)a[7*i+ 5] & 0x03) << 12);
	  r->coeffs[4*i+3] = (a[7*i+ 5] >> 2) | (((uint16_t)a[7*i+ 6]       ) << 6);
  }
#endif
}
void poly_frommsg(poly *r, const uint8_t msg[SEED_BYTES])
{
	uint16_t i, j, mask;

	for (i = 0; i < SEED_BYTES; i++)
	{
		for (j = 0; j < 8; j++)
		{
			mask = -((msg[i] >> j) & 1);
			r->coeffs[8 * i + j] = mask & ((PARAM_Q + 1) / 2);
		}
	}
}
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly *a)
{
	uint16_t t;
	int i, j;

	for (i = 0; i < SEED_BYTES; i++)
	{
		msg[i] = 0;
		for (j = 0; j < 8; j++)
		{
			t = (((a->coeffs[8 * i + j] << 1) + PARAM_Q / 2) / PARAM_Q) & 1;
			msg[i] |= t << j;
		}
	}
}
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
  ntt(r->coeffs); 
}
void poly_invntt(poly *r)
{
  invntt(r->coeffs);
}
