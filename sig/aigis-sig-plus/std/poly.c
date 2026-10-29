#include <stdint.h>
#include <string.h>
#include "hashkdf.h"
#include "params.h"
#include "reduce.h"
#include "ntt.h"
#include "poly.h"
#include "api.h"
#include "drng.h"

void poly_amodq(poly *a) {
	int i;
	for (i = 0; i < PARAM_N; ++i)
		a->coeffs[i] = amodq(a->coeffs[i]);
}

void poly_cmodq(poly *a) {
	int i;
	for (i = 0; i < PARAM_N; ++i)
		a->coeffs[i] = cmodq(a->coeffs[i]);
}

void poly_reduce(poly *a) {
	int i;
	for (i = 0; i < PARAM_N; ++i)
		a->coeffs[i] = barrat_reduce(a->coeffs[i]);
}
void poly_g_reduce(poly *a) {
	int i;
	for (i = 0; i < PARAM_N; ++i)
		a->coeffs[i] = general_reduce(a->coeffs[i]);
}
void poly_add(poly *c, const poly *a, const poly *b)  {
  int i;

  for(i = 0; i < PARAM_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *c, const poly *a, const poly *b) {
  int i;

  for(i = 0; i < PARAM_N; ++i)
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
      
}

void poly_subw(poly *c, const poly *a, const poly *w) {
	int i;
	for (i = 0; i < PARAM_N; ++i)
		c->coeffs[i] = a->coeffs[i] - w->coeffs[i]*ALPHA;
}
void poly_shiftl(poly *a, unsigned int k) {
  int i;

  for(i = 0; i < PARAM_N; ++i)
    a->coeffs[i] <<= k;
}

void poly_ntt(poly *a) {
  ntt(a->coeffs);
}


void poly_invntt_montgomery(poly *a)
{
  invntt_frominvmont(a->coeffs);
}

void poly_pointwise_invmontgomery(poly *c, const poly *a, const poly *b) {
  int i;

  for(i = 0; i < PARAM_N; ++i)
      c->coeffs[i] = montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
}

//return 1, if  x is not in [-bound+1,bound]
int poly_chknorm(const poly *a, int32_t bound) {
  int i;
  int32_t t, r;
  r = 0;
  
  for(i = 0; i < PARAM_N; ++i) 
  {
	t = a->coeffs[i] >> 31;
	t = a->coeffs[i] - (t & (2 * a->coeffs[i] - 1));
	r |= ((bound - t) >> 31) & 1;
  }

  return r;
}

static int32_t rej_eta_1(int32_t *a, int32_t *cur, int32_t n, const uint8_t *buf, int32_t blen)
{
	const int32_t eta = 1;
	int32_t ctr, pos;
	int32_t t[8];

	ctr = *cur;
	pos = 0;

	while (pos + 2 <= blen && ctr + 8 <= n)
	{
		t[0] = buf[pos] & 0x03;
		t[1] = (buf[pos] >> 2) & 0x03;
		t[2] = (buf[pos] >> 4) & 0x03;
		t[3] = (buf[pos++] >> 6) & 0x03;
		t[4] = buf[pos] & 0x03;
		t[5] = (buf[pos] >> 2) & 0x03;
		t[6] = (buf[pos] >> 4) & 0x03;
		t[7] = (buf[pos++] >> 6) & 0x03;

		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
		if (t[2] <= 2 * eta)
			a[ctr++] = eta - t[2];
		if (t[3] <= 2 * eta)
			a[ctr++] = eta - t[3];
		if (t[4] <= 2 * eta)
			a[ctr++] = eta - t[4];
		if (t[5] <= 2 * eta)
			a[ctr++] = eta - t[5];
		if (t[6] <= 2 * eta)
			a[ctr++] = eta - t[6];
		if (t[7] <= 2 * eta)
			a[ctr++] = eta - t[7];
	}

	while (pos < blen && ctr < n)
	{
		t[0] = buf[pos] & 0x03;
		t[1] = (buf[pos] >> 2) & 0x03;
		t[2] = (buf[pos] >> 4) & 0x03;
		t[3] = (buf[pos++] >> 6) & 0x03;

		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (t[1] <= 2 * eta && ctr < n)
			a[ctr++] = eta - t[1];
		if (t[2] <= 2 * eta && ctr < n)
			a[ctr++] = eta - t[2];
		if (t[3] <= 2 * eta && ctr < n)
			a[ctr++] = eta - t[3];
	}
	*cur = ctr;
	return pos;
}

static int32_t rej_eta_2(int32_t *a, int32_t *cur, int32_t n, const uint8_t *buf, int32_t blen)
{
	const int32_t eta = 2;
	int32_t ctr, pos;
	int32_t t[8];

	ctr = *cur;
	pos = 0;

	while (pos + 3 < blen && ctr + 8 <= n)
	{
		t[0] = buf[pos] & 0x07;
		t[1] = (buf[pos] >> 3) & 0x07;
		t[2] = (buf[pos] >> 6) | ((buf[pos + 1] & 0x1) << 2);
		t[3] = (buf[++pos] >> 1) & 0x07;
		t[4] = (buf[pos] >> 4) & 0x07;
		t[5] = (buf[pos] >> 7) | ((buf[pos + 1] & 0x3) << 1);
		t[6] = (buf[++pos] >> 2) & 0x07;
		t[7] = buf[pos++] >> 5;

		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
		if (t[2] <= 2 * eta)
			a[ctr++] = eta - t[2];
		if (t[3] <= 2 * eta)
			a[ctr++] = eta - t[3];
		if (t[4] <= 2 * eta)
			a[ctr++] = eta - t[4];
		if (t[5] <= 2 * eta)
			a[ctr++] = eta - t[5];
		if (t[6] <= 2 * eta)
			a[ctr++] = eta - t[6];
		if (t[7] <= 2 * eta)
			a[ctr++] = eta - t[7];

	}

	while (ctr < n && pos + 1 < blen)
	{
		t[0] = buf[pos] & 0x07;
		t[1] = (buf[pos] >> 3) & 0x07;
		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (ctr < n  &&  t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
		if (ctr >= n || pos + 2 > blen)
		{
			*cur = ctr;
			return pos + 1;
		}

		t[0] = (buf[pos] >> 6) | ((buf[pos + 1] & 0x1) << 2);
		t[1] = (buf[++pos] >> 1) & 0x07;
		t[2] = (buf[pos] >> 4) & 0x07;

		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (ctr < n && t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
		if (ctr < n && t[2] <= 2 * eta)
			a[ctr++] = eta - t[2];
		if (ctr >= n || pos + 2 > blen)
		{
			*cur = ctr;
			return pos + 1;
		}

		t[0] = (buf[pos] >> 7) | ((buf[pos + 1] & 0x3) << 1);
		t[1] = (buf[++pos] >> 2) & 0x07;
		t[2] = buf[pos++] >> 5;

		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (ctr < n && t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
		if (ctr < n && t[2] <= 2 * eta)
			a[ctr++] = eta - t[2];
	}

	* cur = ctr;
	return pos;
}

static int32_t rej_eta_5(int32_t* a, int32_t* cur, int32_t n, const uint8_t* buf, int32_t blen)
{
	const int32_t eta = 5;
	int32_t ctr, pos;
	int32_t t[8];

	ctr = *cur;
	pos = 0;

	while (pos < blen && ctr + 2 <= n)
	{

		t[0] = buf[pos] & 0x0F;
		t[1] = (buf[pos++] >> 4) & 0x0F;

		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
	}
	while (pos < blen && ctr < n)
	{
		t[0] = buf[pos] & 0x0F;
		t[1] = (buf[pos++] >> 4) & 0x0F;
		if (t[0] <= 2 * eta)
			a[ctr++] = eta - t[0];
		if (ctr < n && t[1] <= 2 * eta)
			a[ctr++] = eta - t[1];
	}

	* cur = ctr;
	return pos;
}

static int32_t reject_uniform(int32_t * a, int32_t *cur, int32_t n, uint8_t *buf, int32_t buflen)
{
	int32_t ctr, pos;
	uint32_t t[4];
	ctr = *cur;
	pos = 0;

	while (ctr + 4 <= n && pos + 11 <= buflen)
	{
        t[0] = buf[pos] | ((uint32_t)buf[pos + 1] << 8) | ((uint32_t)buf[pos + 2] << 16);
        t[0] &= 0x3FFFFF;

        t[1] = (buf[pos + 2] >> 6) | ((uint32_t)buf[pos + 3] << 2) | ((uint32_t)buf[pos + 4] << 10) | ((uint32_t)buf[pos + 5] << 18);
        t[1] &= 0x3FFFFF;

        t[2] = (buf[pos + 5] >> 4) | ((uint32_t)buf[pos + 6] << 4) | ((uint32_t)buf[pos + 7] << 12) | ((uint32_t)buf[pos + 8] << 20);
        t[2] &= 0x3FFFFF;

        t[3] = (buf[pos + 8] >> 2) | ((uint32_t)buf[pos + 9] << 6) | ((uint32_t)buf[pos + 10] << 14);
        t[3] &= 0x3FFFFF;

        pos += 11;

		if (t[0] < PARAM_Q)
			a[ctr++] = t[0];
		if (t[1] < PARAM_Q)
			a[ctr++] = t[1];
		if (t[2] < PARAM_Q)
			a[ctr++] = t[2];
		if (t[3] < PARAM_Q)
			a[ctr++] = t[3];
	}
	while ( ctr < n && pos + 11 <= buflen)
	{

        t[0] = buf[pos] | ((uint32_t)buf[pos + 1] << 8) | ((uint32_t)buf[pos + 2] << 16);
        t[0] &= 0x3FFFFF;

        t[1] = (buf[pos + 2] >> 6) | ((uint32_t)buf[pos + 3] << 2) | ((uint32_t)buf[pos + 4] << 10) | ((uint32_t)buf[pos + 5] << 18);
        t[1] &= 0x3FFFFF;

        t[2] = (buf[pos + 5] >> 4) | ((uint32_t)buf[pos + 6] << 4) | ((uint32_t)buf[pos + 7] << 12) | ((uint32_t)buf[pos + 8] << 20);
        t[2] &= 0x3FFFFF;

        t[3] = (buf[pos + 8] >> 2) | ((uint32_t)buf[pos + 9] << 6) | ((uint32_t)buf[pos + 10] << 14);
        t[3] &= 0x3FFFFF;

		t[0] = buf[pos++];
		t[0] |= (uint32_t)buf[pos++] << 8;
		t[0] |= (uint32_t)buf[pos] << 16;
		t[0] &= 0x3FFFFF;

        pos += 11;

		if (t[0] < PARAM_Q)
			a[ctr++] = t[0];
		if (ctr == n)
			break;

		if (t[1] < PARAM_Q)
			a[ctr++] = t[1];
		if (ctr == n)
			break;

		if (t[2] < PARAM_Q)
			a[ctr++] = t[2];
		if (ctr== n)
			break;

		if (t[3] < PARAM_Q)
			a[ctr++] = t[3];
		if (ctr == n)
			break;
	}
	*cur = ctr;
	return pos;

}



#ifdef USE_ICCS

void poly_uniform(poly *a, uint8_t *seed, uint32_t seedbytes)
{
	int cur = 0, pos, step, off;
	uint8_t buf[352];//32 * 11 bytes
	kdfstate ctx;
	kdf_init(&ctx, seed, seedbytes);

	int len;
	len = 352;

	kdf_squeezeblocks(buf, 11, &ctx);
	reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);

	kdf_squeezeblocks(buf, 11, &ctx);
	reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);

	kdf_squeezeblocks(buf, 11, &ctx);
	reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);

	kdf_squeezeblocks(buf, 11, &ctx);
	pos = reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);
	while (cur < PARAM_N)
	{	
		len = len - pos;
		memcpy(buf, buf + pos, len);
		kdf_squeezeblocks(buf + len, 1, &ctx);
		len += KDF128RATE;
		pos = reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);

	}
}

#else

#define REJ_UNIFORM_BYTES 1440   //fail with prob. less than 2^-14

void poly_uniform(poly *a, uint8_t *seed, uint32_t seedbytes)
{
	int cur = 0, pos, step;
	uint8_t buf[REJ_UNIFORM_BYTES + KDF128RATE];
	int nblock = (REJ_UNIFORM_BYTES + KDF128RATE - 1) / KDF128RATE;

	int len;
	kdfstate state;
	kdf128_absorb(&state, seed, seedbytes);
	kdf128_squeezeblocks(buf, nblock, &state);
	len = nblock * KDF128RATE;
	pos = reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);
	while (cur < PARAM_N)
	{
		len -= pos;
		memmove(buf, buf + pos, len);
		kdf128_squeezeblocks(buf + len, 1, &state);
		len += KDF128RATE;
		pos = reject_uniform(a->coeffs, &cur, PARAM_N, buf, len);
	}
}

#endif


#define REJ_ETA1_BYTES 192 // fail with prob. less than 2^-23

#ifdef USE_ICCS

void poly_uniform_eta_1(poly *a, const uint8_t seed[SEEDBYTES], uint8_t nonce)
{
	uint8_t i;
	int32_t cur = 0, pos, step;
	uint8_t inbuf[SEEDBYTES + 1];
	int32_t nblock = (REJ_ETA1_BYTES + KDF_RATE - 1) / KDF_RATE;
	uint8_t outbuf[nblock * KDF_RATE];
	int32_t len;

	memcpy(inbuf,seed,SEEDBYTES);
	inbuf[SEEDBYTES] = nonce;

	kdfstate ctx;
	kdf_init(&ctx, inbuf, SEEDBYTES + 1);
	kdf_squeezeblocks(outbuf, nblock, &ctx);

	len = nblock * KDF_RATE;

	rej_eta_1(a->coeffs, &cur, PARAM_N, outbuf, len);

	while (cur < PARAM_N)
	{
		kdf_squeezeblocks(outbuf, 1, &ctx);
		rej_eta_1(a->coeffs, &cur, PARAM_N, outbuf, KDF_RATE);
	}
}
#else 
void poly_uniform_eta_1(poly *a, const uint8_t seed[SEEDBYTES], uint8_t nonce)
{
	uint8_t i;
	int32_t cur = 0, pos, step;
	uint8_t inbuf[SEEDBYTES + 1];
	int32_t nblock = (REJ_ETA1_BYTES + KDF_RATE - 1) / KDF_RATE;
	uint8_t outbuf[nblock * KDF_RATE];
	int32_t len;

	memcpy(inbuf,seed,SEEDBYTES);
	inbuf[SEEDBYTES] = nonce;

	kdfstate ctx;
	KDF_ABSORB(&ctx, inbuf, SEEDBYTES + 1);
	KDF_SQUEEZEBLOCK(outbuf, nblock, &ctx);
	len = nblock * KDF_RATE;

	rej_eta_1(a->coeffs, &cur, PARAM_N, outbuf, len);

	while (cur < PARAM_N)
	{
		KDF_SQUEEZEBLOCK(outbuf, 1, &ctx);
		rej_eta_1(a->coeffs, &cur, PARAM_N, outbuf, KDF_RATE);
	}
}
#endif

#define REJ_ETA_2_BYTES 307

#ifdef USE_ICCS

void poly_uniform_eta_2(poly *a,
	const uint8_t seed[SEEDBYTES],
	uint8_t nonce)
{

	int i;
	int cur = 0;
	uint8_t inbuf[SEEDBYTES + 1];
	int nblock = (REJ_ETA_2_BYTES + KDF_RATE - 1) / KDF_RATE;
	uint8_t outbuf[nblock * KDF_RATE];
	int len;

	memcpy(inbuf,seed,SEEDBYTES);
	inbuf[SEEDBYTES] = nonce;

	kdfstate  ctx;
	kdf_init(&ctx, inbuf, SEEDBYTES + 1);
	kdf_squeezeblocks(outbuf, nblock, &ctx);
	len = nblock * KDF_RATE;

	rej_eta_2(a->coeffs, &cur, PARAM_N, outbuf, len);

	while (cur < PARAM_N)
	{
		kdf_squeezeblocks(outbuf, 1, &ctx);
		rej_eta_2(a->coeffs, &cur, PARAM_N, outbuf, KDF_RATE);
	}
}

#else

void poly_uniform_eta_2(poly *a,
					   const uint8_t seed[SEEDBYTES],
					   uint8_t nonce)
{
	int cur = 0;
	uint8_t inbuf[SEEDBYTES + 1];
	int nblock = (REJ_ETA_2_BYTES + KDF_RATE - 1) / KDF_RATE;
	uint8_t outbuf[nblock * KDF_RATE];
	int len;

	memcpy(inbuf,seed,SEEDBYTES);
	inbuf[SEEDBYTES] = nonce;

	kdfstate  ctx;
	KDF_ABSORB(&ctx, inbuf, SEEDBYTES + 1);
	KDF_SQUEEZEBLOCK(outbuf, nblock, &ctx);
	len = nblock * KDF_RATE;

	rej_eta_2(a->coeffs, &cur, PARAM_N, outbuf, len);

	while (cur < PARAM_N)
	{
		KDF_SQUEEZEBLOCK(outbuf, 1, &ctx);
		rej_eta_2(a->coeffs, &cur, PARAM_N, outbuf, KDF_RATE);
	}
}

#endif

#define REJ_ETA_5_BYTES 384


#ifdef USE_ICCS

void poly_uniform_eta_5(poly *a,
	const uint8_t seed[SEEDBYTES],
	uint8_t nonce)
{

	int i;
	int cur = 0;
	uint8_t inbuf[SEEDBYTES + 1];
	int nblock = (REJ_ETA_5_BYTES + KDF_RATE - 1) / KDF_RATE;
	uint8_t outbuf[nblock * KDF_RATE];
	int len;

	memcpy(inbuf,seed,SEEDBYTES);
	inbuf[SEEDBYTES] = nonce;

	kdfstate  ctx;
	kdf_init(&ctx, inbuf, SEEDBYTES + 1);
	kdf_squeezeblocks(outbuf, nblock, &ctx);
	len = nblock * KDF_RATE;

	rej_eta_5(a->coeffs, &cur, PARAM_N, outbuf, len);

	while (cur < PARAM_N)
	{
		kdf_squeezeblocks(outbuf, 1, &ctx);
		rej_eta_5(a->coeffs, &cur, PARAM_N, outbuf, KDF_RATE);
	}
}

#else

void poly_uniform_eta_5(poly *a,
					   const uint8_t seed[SEEDBYTES],
					   uint8_t nonce)
{
	int cur = 0;
	uint8_t inbuf[SEEDBYTES + 1];
	int nblock = (REJ_ETA_5_BYTES + KDF_RATE - 1) / KDF_RATE;
	uint8_t outbuf[nblock * KDF_RATE];
	int len;

	memcpy(inbuf,seed,SEEDBYTES);
	inbuf[SEEDBYTES] = nonce;

	kdfstate  ctx;
	KDF_ABSORB(&ctx, inbuf, SEEDBYTES + 1);
	KDF_SQUEEZEBLOCK(outbuf, nblock, &ctx);
	len = nblock * KDF_RATE;

	rej_eta_5(a->coeffs, &cur, PARAM_N, outbuf, len);

	while (cur < PARAM_N)
	{
		KDF_SQUEEZEBLOCK(outbuf, 1, &ctx);
		rej_eta_5(a->coeffs, &cur, PARAM_N, outbuf, KDF_RATE);
	}
}

#endif

void poly_uniform_gamma1(poly *a, const uint8_t seed[SEEDBYTES + CRHBYTES], uint16_t nonce)
{
#if GAMMA1 != 16384 && GAMMA1 != 65536 && GAMMA1 != 524288
#error "poly_uniform_gamma1() assumes GAMMA1 == 16384, 65536, or 524288"
#endif
	int32_t i;
	uint8_t inbuf[SEEDBYTES + CRHBYTES + 2];
	uint8_t outbuf[SZBITS * PARAM_N / 8];

	for (i = 0; i < SEEDBYTES + CRHBYTES; ++i)
		inbuf[i] = seed[i];
	inbuf[SEEDBYTES + CRHBYTES] = nonce & 0xFF;
	inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >> 8;

	KDF(outbuf, sizeof(outbuf), inbuf, SEEDBYTES + CRHBYTES + 2);

	polyz_unpack(a, outbuf);
}

void polyeta1_pack(uint8_t *r, const poly *a) {

	int32_t i;
	uint8_t t[8];
#if ETA1 == 1
	for (i = 0; i < PARAM_N / 4; ++i) {
		t[0] = ETA1 - a->coeffs[4 * i + 0];
		t[1] = ETA1 - a->coeffs[4 * i + 1];
		t[2] = ETA1 - a->coeffs[4 * i + 2];
		t[3] = ETA1 - a->coeffs[4 * i + 3];
		r[i] = t[0] | (t[1] << 2) | (t[2] << 4) | (t[3] << 6);
	}
#elif ETA1 == 2
	for (i = 0; i < PARAM_N / 8; ++i) {
		t[0] = ETA1 - a->coeffs[8 * i + 0];
		t[1] = ETA1 - a->coeffs[8 * i + 1];
		t[2] = ETA1 - a->coeffs[8 * i + 2];
		t[3] = ETA1 - a->coeffs[8 * i + 3];
		t[4] = ETA1 - a->coeffs[8 * i + 4];
		t[5] = ETA1 - a->coeffs[8 * i + 5];
		t[6] = ETA1 - a->coeffs[8 * i + 6];
		t[7] = ETA1 - a->coeffs[8 * i + 7];

		r[3 * i + 0] = t[0];
		r[3 * i + 0] |= t[1] << 3;
		r[3 * i + 0] |= t[2] << 6;
		r[3 * i + 1] = t[2] >> 2;
		r[3 * i + 1] |= t[3] << 1;
		r[3 * i + 1] |= t[4] << 4;
		r[3 * i + 1] |= t[5] << 7;
		r[3 * i + 2] = t[5] >> 1;
		r[3 * i + 2] |= t[6] << 2;
		r[3 * i + 2] |= t[7] << 5;
	}
#endif

}
void polyeta2_pack(uint8_t *r, const poly *a) {

	int32_t i;
	uint8_t t[8];

#if SETA2BITS == 2
	for (i = 0; i < PARAM_N / 4; ++i) {
		t[0] = ETA2 - a->coeffs[4 * i + 0];
		t[1] = ETA2 - a->coeffs[4 * i + 1];
		t[2] = ETA2 - a->coeffs[4 * i + 2];
		t[3] = ETA2 - a->coeffs[4 * i + 3];
		r[i] = t[0] | (t[1] << 2) | (t[2] << 4) | (t[3] << 6);
	}
#elif SETA2BITS == 3
	for (i = 0; i < PARAM_N / 8; ++i) {
		t[0] = ETA2 - a->coeffs[8 * i + 0];
		t[1] = ETA2 - a->coeffs[8 * i + 1];
		t[2] = ETA2 - a->coeffs[8 * i + 2];
		t[3] = ETA2 - a->coeffs[8 * i + 3];
		t[4] = ETA2 - a->coeffs[8 * i + 4];
		t[5] = ETA2 - a->coeffs[8 * i + 5];
		t[6] = ETA2 - a->coeffs[8 * i + 6];
		t[7] = ETA2 - a->coeffs[8 * i + 7];

		r[3 * i + 0] = t[0];
		r[3 * i + 0] |= t[1] << 3;
		r[3 * i + 0] |= t[2] << 6;
		r[3 * i + 1] = t[2] >> 2;
		r[3 * i + 1] |= t[3] << 1;
		r[3 * i + 1] |= t[4] << 4;
		r[3 * i + 1] |= t[5] << 7;
		r[3 * i + 2] = t[5] >> 1;
		r[3 * i + 2] |= t[6] << 2;
		r[3 * i + 2] |= t[7] << 5;
	}
#elif SETA2BITS == 4
	for (i = 0; i < PARAM_N / 2; ++i) {
		t[0] = ETA2 - a->coeffs[2 * i + 0];
		t[1] = ETA2 - a->coeffs[2 * i + 1];
		r[i] = t[0] | (t[1] << 4);
	}
#endif
}
void polyt1_pack(uint8_t *r, const poly *a) {
#if QBITS - PARAM_D == 7
	unsigned int i, j;
	for (i = 0, j = 0; i < PARAM_N; i += 8, j += 7)
	{
		r[j] = a->coeffs[i];
		r[j] |= a->coeffs[i + 1] << 7;

		r[j + 1] = a->coeffs[i + 1] >> 1;
		r[j + 1] |= a->coeffs[i + 2] << 6;

		r[j + 2] = a->coeffs[i + 2] >> 2;
		r[j + 2] |= a->coeffs[i + 3] << 5;

		r[j + 3] = a->coeffs[i + 3] >> 3;
		r[j + 3] |= a->coeffs[i + 4] << 4;

		r[j + 4] = a->coeffs[i + 4] >> 4;
		r[j + 4] |= a->coeffs[i + 5] << 3;

		r[j + 5] = a->coeffs[i + 5] >> 5;
		r[j + 5] |= a->coeffs[i + 6] << 2;

		r[j + 6] = a->coeffs[i + 6] >> 6;
		r[j + 6] |= a->coeffs[i + 7] << 1;
	}
#elif QBITS - PARAM_D == 8
	int i;
	for(i = 0; i < PARAM_N; ++i)
		r[i]  =  a->coeffs[i];
#elif QBITS - PARAM_D == 9
  unsigned int i,j;
  for (i = 0, j = 0; i < PARAM_N; i += 8, j += 9)
  {
	  r[j] = a->coeffs[i];
	  r[j + 1] = (a->coeffs[i] >> 8) | (a->coeffs[i + 1] << 1);
	  r[j + 2] = (a->coeffs[i + 1] >> 7) | (a->coeffs[i + 2] << 2);
	  r[j + 3] = (a->coeffs[i + 2] >> 6) | (a->coeffs[i + 3] << 3);
	  r[j + 4] = (a->coeffs[i + 3] >> 5) | (a->coeffs[i + 4] << 4);
	  r[j + 5] = (a->coeffs[i + 4] >> 4) | (a->coeffs[i + 5] << 5);
	  r[j + 6] = (a->coeffs[i + 5] >> 3) | (a->coeffs[i + 6] << 6);
	  r[j + 7] = (a->coeffs[i + 6] >> 2) | (a->coeffs[i + 7] << 7);
	  r[j + 8] = a->coeffs[i + 7] >> 1;
  }
#else
#error "polyt1_pack() assumes QBITS - PARAM_D == 7, 9 "
#endif
}

void polyt1_unpack(poly *r, const uint8_t *a) 
{
#if QBITS - PARAM_D == 7
	unsigned int i, j;
	for (i = 0, j = 0; i < PARAM_N; i += 8, j += 7)
	{
		r->coeffs[i] = a[j] & 0x7f;
		r->coeffs[i + 1] = ((a[j + 1] & 0x3f) << 1) | (a[j] >> 7);
		r->coeffs[i + 2] = ((a[j + 2] & 0x1f) << 2) | (a[j + 1] >> 6);
		r->coeffs[i + 3] = ((a[j + 3] & 0xf) << 3) | (a[j + 2] >> 5);
		r->coeffs[i + 4] = ((a[j + 4] & 0x7) << 4) | (a[j + 3] >> 4);
		r->coeffs[i + 5] = ((a[j + 5] & 0x3) << 5) | (a[j + 4] >> 3);
		r->coeffs[i + 6] = ((a[j + 6] & 0x1) << 6) | (a[j + 5] >> 2);
		r->coeffs[i + 7] = a[j + 6] >> 1;
	}
#elif QBITS - PARAM_D == 8
  int i;
  for(i = 0; i < PARAM_N; ++i)
	  r->coeffs[i]  =  a[i];
#elif QBITS - PARAM_D == 9
	unsigned int i,j;
	for (i = 0, j = 0; i < PARAM_N; i += 8, j += 9)
	{
		r->coeffs[i] = a[j];
		r->coeffs[i] |= (uint32_t)(a[j + 1] & 0x1) << 8;

		r->coeffs[i + 1] = a[j + 1] >> 1;
		r->coeffs[i + 1] |= (uint32_t)(a[j + 2] & 0x3) << 7;

		r->coeffs[i + 2] = a[j + 2] >> 2;
		r->coeffs[i + 2] |= (uint32_t)(a[j + 3] & 0x7) << 6;

		r->coeffs[i + 3] = a[j + 3] >> 3;
		r->coeffs[i + 3] |= (uint32_t)(a[j + 4] & 0xf) << 5;

		r->coeffs[i + 4] = a[j + 4] >> 4;
		r->coeffs[i + 4] |= (uint32_t)(a[j + 5] & 0x1f) << 4;

		r->coeffs[i + 5] = a[j + 5] >> 5;
		r->coeffs[i + 5] |= (uint32_t)(a[j + 6] & 0x3f) << 3;

		r->coeffs[i + 6] = a[j + 6] >> 6;
		r->coeffs[i + 6] |= (uint32_t)(a[j + 7] & 0x7f) << 2;

		r->coeffs[i + 7] = a[j + 7] >> 7;
		r->coeffs[i + 7] |= (uint32_t)a[j + 8] << 1;
	}
#else
#error "polyt1_unpack() assumes QBITS - PARAM_D == 7, 8 or 9"
#endif
}

void polyt0_pack(uint8_t *r, const poly *a) 
{
	int i;
#if PARAM_D == 13
  int32_t t[8];
  for(i = 0; i < PARAM_N/8; ++i) {
	  t[0] = (1 << (PARAM_D-1)) - a->coeffs[8*i+0];
	  t[1] = (1 << (PARAM_D-1)) - a->coeffs[8*i+1];
	  t[2] = (1 << (PARAM_D-1)) - a->coeffs[8*i+2];
	  t[3] = (1 << (PARAM_D-1)) - a->coeffs[8*i+3];
	  t[4] = (1 << (PARAM_D-1)) - a->coeffs[8*i+4];
	  t[5] = (1 << (PARAM_D-1)) - a->coeffs[8*i+5];
	  t[6] = (1 << (PARAM_D-1)) - a->coeffs[8*i+6];
	  t[7] = (1 << (PARAM_D-1)) - a->coeffs[8*i+7];

	  r[13*i+0]   =  t[0];
	  r[13*i+1]   =  t[0] >> 8;
	  r[13*i+1]  |=  t[1] << 5;
	  r[13*i+2]   =  t[1] >> 3;
	  r[13*i+3]   =  t[1] >> 11;
	  r[13*i+3]  |=  t[2] << 2;
	  r[13*i+4]   =  t[2] >> 6;
	  r[13*i+4]  |=  t[3] << 7;
	  r[13*i+5]   =  t[3] >> 1;
	  r[13*i+6]   =  t[3] >> 9;
	  r[13*i+6]  |=  t[4] << 4;
	  r[13*i+7]   =  t[4] >> 4;
	  r[13*i+8]   =  t[4] >> 12;
	  r[13*i+8]  |=  t[5] << 1;
	  r[13*i+9]   =  t[5] >> 7;
	  r[13*i+9]  |=  t[6] << 6;
	  r[13*i+10]  =  t[6] >> 2;
	  r[13*i+11]  =  t[6] >> 10;
	  r[13*i+11] |=  t[7] << 3;
	  r[13*i+12]  =  t[7] >> 5;
  }
#elif PARAM_D==14
  int32_t t[4];
  for(i = 0; i < PARAM_N/4; ++i) {
    t[0] = (1 << (PARAM_D-1)) - a->coeffs[4*i+0];
    t[1] = (1 << (PARAM_D-1)) - a->coeffs[4*i+1];
    t[2] = (1 << (PARAM_D-1)) - a->coeffs[4*i+2];
    t[3] = (1 << (PARAM_D-1)) - a->coeffs[4*i+3];

    r[7*i+0]  =  t[0];
    r[7*i+1]  =  t[0] >> 8;
    r[7*i+1] |=  t[1] << 6;
    r[7*i+2]  =  t[1] >> 2;
    r[7*i+3]  =  t[1] >> 10;
    r[7*i+3] |=  t[2] << 4;
    r[7*i+4]  =  t[2] >> 4;
    r[7*i+5]  =  t[2] >> 12;
    r[7*i+5] |=  t[3] << 2;
    r[7*i+6]  =  t[3] >> 6;
  }
#elif PARAM_D==15
	int32_t t[8];
	for (i = 0; i < PARAM_N / 8; ++i) {
		t[0] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 0];
		t[1] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 1];
		t[2] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 2];
		t[3] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 3];
		t[4] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 4];
		t[5] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 5];
		t[6] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 6];
		t[7] = (1 << (PARAM_D - 1)) - a->coeffs[8 * i + 7];

		r[15 * i + 0] = t[0];
		r[15 * i + 1] = t[0] >> 8;
		r[15 * i + 1] |= t[1] << 7;
		r[15 * i + 2] = t[1] >> 1;
		r[15 * i + 3] = t[1] >> 9;
		r[15 * i + 3] |= t[2] << 6;
		r[15 * i + 4] = t[2] >> 2;
		r[15 * i + 5] = t[2] >> 10;
		r[15 * i + 5] |= t[3] << 5;
		r[15 * i + 6] = t[3] >> 3;
		r[15 * i + 7] = t[3] >> 11;
		r[15 * i + 7] |= t[4] << 4;
		r[15 * i + 8] = t[4] >> 4;
		r[15 * i + 9] = t[4] >> 12;
		r[15 * i + 9] |= t[5] << 3;
		r[15 * i + 10] = t[5] >> 5;
		r[15 * i + 11] = t[5] >> 13;
		r[15 * i + 11] |= t[6] << 2;
		r[15 * i + 12] = t[6] >> 6;
		r[15 * i + 13] = t[6] >> 14;
		r[15 * i + 13] |= t[7] << 1;
		r[15 * i + 14] = t[7] >> 7;
	}
#else
#error "polyt0_unpack() assumes PARAM_D== 13, 14 or 15"
#endif
}

void polyt0_unpack(poly *r, const uint8_t *a) 
{ 
	int i;
#if PARAM_D==13
  for(i = 0; i < PARAM_N/8; ++i) {

	  r->coeffs[8*i+0]  = a[13*i+0];
	  r->coeffs[8*i+0] |= (uint32_t)(a[13*i+1] & 0x1F)<<8;

	  r->coeffs[8*i+1]  = a[13*i+1]>>5;
	  r->coeffs[8*i+1] |= (uint32_t)a[13*i+2]<< 3;
	  r->coeffs[8*i+1] |= (uint32_t)(a[13*i+3] & 0x3)<< 11;

	  r->coeffs[8*i+2]  = a[13*i+3]>>2;
	  r->coeffs[8*i+2] |= (uint32_t)(a[13*i+4] & 0x7F)<< 6;

	  r->coeffs[8*i+3]  = a[13*i+4]>>7;
	  r->coeffs[8*i+3] |= (uint32_t)a[13*i+5]<< 1;
	  r->coeffs[8*i+3] |= (uint32_t)(a[13*i+6] & 0x0F)<< 9;

	  r->coeffs[8*i+4]  = a[13*i+ 6]>>4;
	  r->coeffs[8*i+4] |= (uint32_t)a[13*i+ 7]<< 4;
	  r->coeffs[8*i+4] |= (uint32_t)(a[13*i+8] & 0x01)<< 12;

	  r->coeffs[8*i+5]  = a[13*i+8]>>1;
	  r->coeffs[8*i+5] |= (uint32_t)(a[13*i+9] & 0x3F)<< 7;

	  r->coeffs[8*i+6]  = a[13*i+9]>>6;
	  r->coeffs[8*i+6] |= (uint32_t)a[13*i+10]<< 2;
	  r->coeffs[8*i+6] |= (uint32_t)(a[13*i+11] & 0x07)<< 10;

	  r->coeffs[8*i+7]  = a[13*i+11]>>3;
	  r->coeffs[8*i+7] |= (uint32_t)a[13*i+12]<< 5;


	  r->coeffs[8*i+0] = (1 << (PARAM_D-1)) - r->coeffs[8*i+0];
      r->coeffs[8*i+1] = (1 << (PARAM_D-1)) - r->coeffs[8*i+1];
      r->coeffs[8*i+2] = (1 << (PARAM_D-1)) - r->coeffs[8*i+2];
      r->coeffs[8*i+3] = (1 << (PARAM_D-1)) - r->coeffs[8*i+3];
	  r->coeffs[8*i+4] = (1 << (PARAM_D-1)) - r->coeffs[8*i+4];
      r->coeffs[8*i+5] = (1 << (PARAM_D-1)) - r->coeffs[8*i+5];
      r->coeffs[8*i+6] = (1 << (PARAM_D-1)) - r->coeffs[8*i+6];
      r->coeffs[8*i+7] = (1 << (PARAM_D-1)) - r->coeffs[8*i+7];

  }
#elif PARAM_D==14
  for(i = 0; i < PARAM_N/4; ++i) {
    r->coeffs[4*i+0]  = a[7*i+0];
    r->coeffs[4*i+0] |= (uint32_t)(a[7*i+1] & 0x3F) << 8;

    r->coeffs[4*i+1]  = a[7*i+1] >> 6;
    r->coeffs[4*i+1] |= (uint32_t)a[7*i+2] << 2;
    r->coeffs[4*i+1] |= (uint32_t)(a[7*i+3] & 0x0F) << 10;
    
    r->coeffs[4*i+2]  = a[7*i+3] >> 4;
    r->coeffs[4*i+2] |= (uint32_t)a[7*i+4] << 4;
    r->coeffs[4*i+2] |= (uint32_t)(a[7*i+5] & 0x03) << 12;

    r->coeffs[4*i+3]  = a[7*i+5] >> 2;
    r->coeffs[4*i+3] |= (uint32_t)a[7*i+6] << 6;

    r->coeffs[4*i+0] = (1 << (PARAM_D-1)) - r->coeffs[4*i+0];
    r->coeffs[4*i+1] = (1 << (PARAM_D-1)) - r->coeffs[4*i+1];
    r->coeffs[4*i+2] = (1 << (PARAM_D-1)) - r->coeffs[4*i+2];
    r->coeffs[4*i+3] = (1 << (PARAM_D-1)) - r->coeffs[4*i+3];
  }
#elif PARAM_D==15
	for (i = 0; i < PARAM_N / 8; ++i) {
		r->coeffs[8 * i + 0] = a[15 * i + 0];
		r->coeffs[8 * i + 0] |= (uint32_t)(a[15 * i + 1] & 0x7F) << 8;

		r->coeffs[8 * i + 1] = a[15 * i + 1] >> 7;
		r->coeffs[8 * i + 1] |= (uint32_t)a[15 * i + 2] << 1;
		r->coeffs[8 * i + 1] |= (uint32_t)(a[15 * i + 3] & 0x3F) << 9;

		r->coeffs[8 * i + 2] = a[15 * i + 3] >> 6;
		r->coeffs[8 * i + 2] |= (uint32_t)a[15 * i + 4] << 2;
		r->coeffs[8 * i + 2] |= (uint32_t)(a[15 * i + 5] & 0x1F) << 10;

		r->coeffs[8 * i + 3] = a[15 * i + 5] >> 5;
		r->coeffs[8 * i + 3] |= (uint32_t)a[15 * i + 6] << 3;
		r->coeffs[8 * i + 3] |= ((uint32_t)a[15 * i + 7] & 0x0F) << 11;

		r->coeffs[8 * i + 4] = a[15 * i + 7] >> 4;
		r->coeffs[8 * i + 4] |= (uint32_t)a[15 * i + 8] << 4;
		r->coeffs[8 * i + 4] |= ((uint32_t)a[15 * i + 9] & 0x07) << 12;

		r->coeffs[8 * i + 5] = a[15 * i + 9] >> 3;
		r->coeffs[8 * i + 5] |= (uint32_t)a[15 * i + 10] << 5;
		r->coeffs[8 * i + 5] |= ((uint32_t)a[15 * i + 11] & 0x03) << 13;

		r->coeffs[8 * i + 6] = a[15 * i + 11] >> 2;
		r->coeffs[8 * i + 6] |= (uint32_t)a[15 * i + 12] << 6;
		r->coeffs[8 * i + 6] |= (uint32_t)(a[15 * i + 13] & 0x01) << 14;

		r->coeffs[8 * i + 7] = a[15 * i + 13] >> 1;
		r->coeffs[8 * i + 7] |= (uint32_t)a[15 * i + 14] << 7;

		r->coeffs[8 * i + 0] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 0];
		r->coeffs[8 * i + 1] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 1];
		r->coeffs[8 * i + 2] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 2];
		r->coeffs[8 * i + 3] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 3];
		r->coeffs[8 * i + 4] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 4];
		r->coeffs[8 * i + 5] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 5];
		r->coeffs[8 * i + 6] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 6];
		r->coeffs[8 * i + 7] = (1 << (PARAM_D - 1)) - r->coeffs[8 * i + 7];
	}
#else
#error "polyt0_unpack() assumes PARAM_D== 13, 14, 15"
#endif
}

void polyz_pack(uint8_t* r, const poly* a)
{
	int32_t i;
#if GAMMA1 == 16384
	int32_t t[8];
	for (i = 0; i < PARAM_N / 8; ++i) {
		/* Map to {0,...,2*GAMMA1} */ // 15-bit
		t[0] = GAMMA1 - a->coeffs[8 * i + 0];
		t[1] = GAMMA1 - a->coeffs[8 * i + 1];
		t[2] = GAMMA1 - a->coeffs[8 * i + 2];
		t[3] = GAMMA1 - a->coeffs[8 * i + 3];
		t[4] = GAMMA1 - a->coeffs[8 * i + 4];
		t[5] = GAMMA1 - a->coeffs[8 * i + 5];
		t[6] = GAMMA1 - a->coeffs[8 * i + 6];
		t[7] = GAMMA1 - a->coeffs[8 * i + 7];

		r[15 * i + 0] = t[0];

		r[15 * i + 1] = t[0] >> 8;
		r[15 * i + 1] |= t[1] << 7;

		r[15 * i + 2] = t[1] >> 1;

		r[15 * i + 3] = t[1] >> 9;
		r[15 * i + 3] |= t[2] << 6;

		r[15 * i + 4] = t[2] >> 2;

		r[15 * i + 5] = t[2] >> 10;
		r[15 * i + 5] |= t[3] << 5;

		r[15 * i + 6] = t[3] >> 3;

		r[15 * i + 7] = t[3] >> 11;
		r[15 * i + 7] |= t[4] << 4;

		r[15 * i + 8] = t[4] >> 4;

		r[15 * i + 9] = t[4] >> 12;
		r[15 * i + 9] |= t[5] << 3;

		r[15 * i + 10] = t[5] >> 5;

		r[15 * i + 11] = t[5] >> 13;
		r[15 * i + 11] |= t[6] << 2;

		r[15 * i + 12] = t[6] >> 6;

		r[15 * i + 13] = t[6] >> 14;
		r[15 * i + 13] |= t[7] << 1;

		r[15 * i + 14] = t[7] >> 7;
	}
#elif GAMMA1 == 65536
	int32_t t[8];
	for (i = 0; i < PARAM_N / 8; ++i) {
		/* Map to {0,...,2*GAMMA1} */ // 17-bit
		t[0] = GAMMA1 - a->coeffs[8 * i + 0];
		t[1] = GAMMA1 - a->coeffs[8 * i + 1];
		t[2] = GAMMA1 - a->coeffs[8 * i + 2];
		t[3] = GAMMA1 - a->coeffs[8 * i + 3];
		t[4] = GAMMA1 - a->coeffs[8 * i + 4];
		t[5] = GAMMA1 - a->coeffs[8 * i + 5];
		t[6] = GAMMA1 - a->coeffs[8 * i + 6];
		t[7] = GAMMA1 - a->coeffs[8 * i + 7];

		r[17 * i + 0] = t[0];
		r[17 * i + 1] = t[0] >> 8;

		r[17 * i + 2] = t[0] >> 16;
		r[17 * i + 2] |= t[1] << 1;

		r[17 * i + 3] = t[1] >> 7;

		r[17 * i + 4] = t[1] >> 15;
		r[17 * i + 4] |= t[2] << 2;

		r[17 * i + 5] = t[2] >> 6;

		r[17 * i + 6] = t[2] >> 14;
		r[17 * i + 6] |= t[3] << 3;

		r[17 * i + 7] = t[3] >> 5;

		r[17 * i + 8] = t[3] >> 13;
		r[17 * i + 8] |= t[4] << 4;

		r[17 * i + 9] = t[4] >> 4;

		r[17 * i + 10] = t[4] >> 12;
		r[17 * i + 10] |= t[5] << 5;

		r[17 * i + 11] = t[5] >> 3;

		r[17 * i + 12] = t[5] >> 11;
		r[17 * i + 12] |= t[6] << 6;

		r[17 * i + 13] = t[6] >> 2;

		r[17 * i + 14] = t[6] >> 10;
		r[17 * i + 14] |= t[7] << 7;

		r[17 * i + 15] = t[7] >> 1;
		r[17 * i + 16] = t[7] >> 9;
	}
#elif GAMMA1 == 524288
	int32_t t[2];
	int32_t j;
	for (i = 0; i < PARAM_N / 2; ++i)
	{
		/* Map to {0,...,2*GAMMA1} */ // 20-bit
		for (j = 0; j < 2; ++j)
			t[j] = GAMMA1 - a->coeffs[2 * i + j];

		r[5 * i + 0] = t[0];
		r[5 * i + 1] = t[0] >> 8;
		r[5 * i + 2] = t[0] >> 16;

		r[5 * i + 2] |= t[1] << 4;
		r[5 * i + 3] = t[1] >> 4;
		r[5 * i + 4] = t[1] >> 12;
	}
#else
#error "polyz_pack() error"
#endif
}

void polyz_unpack(poly* r, const uint8_t* a) {

#if GAMMA1 == 16384
	int32_t i;
	for (i = 0; i < PARAM_N / 8; ++i) {
		r->coeffs[8 * i + 0] = a[15 * i + 0];
		r->coeffs[8 * i + 0] |= (uint32_t)(a[15 * i + 1] & 0x7F) << 8;
		r->coeffs[8 * i + 0] = GAMMA1 - r->coeffs[8 * i + 0];

		r->coeffs[8 * i + 1] = a[15 * i + 1] >> 7;
		r->coeffs[8 * i + 1] |= (uint32_t)a[15 * i + 2] << 1;
		r->coeffs[8 * i + 1] |= (uint32_t)(a[15 * i + 3] & 0x3F) << 9;
		r->coeffs[8 * i + 1] = GAMMA1 - r->coeffs[8 * i + 1];

		r->coeffs[8 * i + 2] = a[15 * i + 3] >> 6;
		r->coeffs[8 * i + 2] |= (uint32_t)a[15 * i + 4] << 2;
		r->coeffs[8 * i + 2] |= (uint32_t)(a[15 * i + 5] & 0x1F) << 10;
		r->coeffs[8 * i + 2] = GAMMA1 - r->coeffs[8 * i + 2];


		r->coeffs[8 * i + 3] = a[15 * i + 5] >> 5;
		r->coeffs[8 * i + 3] |= (uint32_t)a[15 * i + 6] << 3;
		r->coeffs[8 * i + 3] |= (uint32_t)(a[15 * i + 7] & 0x0F) << 11;
		r->coeffs[8 * i + 3] = GAMMA1 - r->coeffs[8 * i + 3];

		r->coeffs[8 * i + 4] = a[15 * i + 7] >> 4;
		r->coeffs[8 * i + 4] |= (uint32_t)a[15 * i + 8] << 4;
		r->coeffs[8 * i + 4] |= (uint32_t)(a[15 * i + 9] & 0x07) << 12;
		r->coeffs[8 * i + 4] = GAMMA1 - r->coeffs[8 * i + 4];

		r->coeffs[8 * i + 5] = a[15 * i + 9] >> 3;
		r->coeffs[8 * i + 5] |= (uint32_t)a[15 * i + 10] << 5;
		r->coeffs[8 * i + 5] |= (uint32_t)(a[15 * i + 11] & 0x03) << 13;
		r->coeffs[8 * i + 5] = GAMMA1 - r->coeffs[8 * i + 5];

		r->coeffs[8 * i + 6] = a[15 * i + 11] >> 2;
		r->coeffs[8 * i + 6] |= (uint32_t)a[15 * i + 12] << 6;
		r->coeffs[8 * i + 6] |= (uint32_t)(a[15 * i + 13] & 0x01) << 14;
		r->coeffs[8 * i + 6] = GAMMA1 - r->coeffs[8 * i + 6];


		r->coeffs[8 * i + 7] = a[15 * i + 13] >> 1;
		r->coeffs[8 * i + 7] |= (uint32_t)a[15 * i + 14] << 7;
		r->coeffs[8 * i + 7] = GAMMA1 - r->coeffs[8 * i + 7];
	}

#elif GAMMA1 == 65536
	int32_t i;
	for (i = 0; i < PARAM_N / 8; ++i) {
		r->coeffs[8 * i + 0] = a[17 * i + 0];
		r->coeffs[8 * i + 0] |= (uint32_t)a[17 * i + 1] << 8;
		r->coeffs[8 * i + 0] |= (uint32_t)(a[17 * i + 2] & 0x01) << 16;
		r->coeffs[8 * i + 0] = GAMMA1 - r->coeffs[8 * i + 0];

		r->coeffs[8 * i + 1] = a[17 * i + 2] >> 1;
		r->coeffs[8 * i + 1] |= (uint32_t)a[17 * i + 3] << 7;
		r->coeffs[8 * i + 1] |= (uint32_t)(a[17 * i + 4] & 0x03) << 15;
		r->coeffs[8 * i + 1] = GAMMA1 - r->coeffs[8 * i + 1];

		r->coeffs[8 * i + 2] = a[17 * i + 4] >> 2;
		r->coeffs[8 * i + 2] |= (uint32_t)a[17 * i + 5] << 6;
		r->coeffs[8 * i + 2] |= (uint32_t)(a[17 * i + 6] & 0x07) << 14;
		r->coeffs[8 * i + 2] = GAMMA1 - r->coeffs[8 * i + 2];


		r->coeffs[8 * i + 3] = a[17 * i + 6] >> 3;
		r->coeffs[8 * i + 3] |= (uint32_t)a[17 * i + 7] << 5;
		r->coeffs[8 * i + 3] |= (uint32_t)(a[17 * i + 8] & 0x0F) << 13;
		r->coeffs[8 * i + 3] = GAMMA1 - r->coeffs[8 * i + 3];

		r->coeffs[8 * i + 4] = a[17 * i + 8] >> 4;
		r->coeffs[8 * i + 4] |= (uint32_t)a[17 * i + 9] << 4;
		r->coeffs[8 * i + 4] |= (uint32_t)(a[17 * i + 10] & 0x1F) << 12;
		r->coeffs[8 * i + 4] = GAMMA1 - r->coeffs[8 * i + 4];

		r->coeffs[8 * i + 5] = a[17 * i + 10] >> 5;
		r->coeffs[8 * i + 5] |= (uint32_t)a[17 * i + 11] << 3;
		r->coeffs[8 * i + 5] |= (uint32_t)(a[17 * i + 12] & 0x3F) << 11;
		r->coeffs[8 * i + 5] = GAMMA1 - r->coeffs[8 * i + 5];

		r->coeffs[8 * i + 6] = a[17 * i + 12] >> 6;
		r->coeffs[8 * i + 6] |= (uint32_t)a[17 * i + 13] << 2;
		r->coeffs[8 * i + 6] |= (uint32_t)(a[17 * i + 14] & 0x7F) << 10;
		r->coeffs[8 * i + 6] = GAMMA1 - r->coeffs[8 * i + 6];


		r->coeffs[8 * i + 7] = a[17 * i + 14] >> 7;
		r->coeffs[8 * i + 7] |= (uint32_t)a[17 * i + 15] << 1;
		r->coeffs[8 * i + 7] |= (uint32_t)a[17 * i + 16] << 9;
		r->coeffs[8 * i + 7] = GAMMA1 - r->coeffs[8 * i + 7];
	}
#elif GAMMA1 == 524288
	int32_t i;
	for (i = 0; i < PARAM_N / 2; ++i)
	{
		r->coeffs[2 * i + 0] = a[5 * i + 0];
		r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
		r->coeffs[2 * i + 0] |= (uint32_t)(a[5 * i + 2] & 0x0F) << 16;
		r->coeffs[2 * i + 0] = GAMMA1 - r->coeffs[2 * i + 0];

		r->coeffs[2 * i + 1] = a[5 * i + 2] >> 4;
		r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
		r->coeffs[2 * i + 1] |= (uint32_t)(a[5 * i + 4]) << 12;
		r->coeffs[2 * i + 1] = GAMMA1 - r->coeffs[2 * i + 1];
	}
#else
#error "polyz_pack() error"
#endif
}

void polyw1_pack(uint8_t *r, const poly *a) 
{ 
#if PARAM_Q/ALPHA > 64 || PARAM_Q/ALPHA < 3
#error "polyw1_pack() assumes 2 < PARAM_Q/ALPHA -1 <= 64"
#endif
  int i;
#if PARAM_Q/ALPHA == 48
  for (i = 0; i < PARAM_N / 4; ++i) {
	  r[3 * i + 0] = (a->coeffs[4 * i + 0] | (a->coeffs[4 * i + 1] << 6)) & 0xff;
	  r[3 * i + 1] = ((a->coeffs[4 * i + 1] >> 2) | (a->coeffs[4 * i + 2] << 4)) & 0xff;
	  r[3 * i + 2] = ((a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 2)) & 0xff;
  }
#elif PARAM_Q/ALPHA > 8
	for (i = 0; i < PARAM_N / 2; ++i)
	{
		r[i] = a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4);
	}
#elif	PARAM_Q/ALPHA > 4
  for(i = 0; i < PARAM_N/8; ++i)
  {
    r[3*i+0] = a->coeffs[8*i+0]      | (a->coeffs[8*i+1] << 3) | (a->coeffs[8*i+ 2] << 6);
	r[3*i+1] = (a->coeffs[8*i+2]>>2) | (a->coeffs[8*i+3] << 1) | (a->coeffs[8*i+ 4] << 4) | (a->coeffs[8*i+ 5] << 7);
	r[3*i+2] = (a->coeffs[8*i+5]>>1) | (a->coeffs[8*i+6] << 2) | (a->coeffs[8*i+ 7] << 5);
 }
#elif PARAM_Q/ALPHA <= 4
  for (i = 0; i < PARAM_N / 4; ++i)
  {
	  r[i] = a->coeffs[4 * i + 0] | (a->coeffs[4 * i + 1] << 2) | (a->coeffs[4 * i + 2] << 4) | (a->coeffs[4 * i + 3] << 6);  
  }
#endif
}

