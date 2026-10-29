#include <string.h>
#include "gen_a.h"
#include "polyvec.h"
#include "hashkdf.h"

static int rej_uniform(uint16_t *r, int *cur, int n, const uint8_t *buf, int buflen)
{
	int ctr, pos;
	int16_t val0, val1;
	ctr = *cur;
	pos = 0;

	while (((ctr + 2) < n) && (pos + 3 <= buflen))
	{
		val0 = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0xfff;
		val1 = (buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4);
		pos += 3;

		if (val0 < PARAM_Q)
			r[ctr++] = val0;
		if (val1 < PARAM_Q)
			r[ctr++] = val1;
	}
	while ((ctr < n) && (pos + 3 <= buflen))
	{
		val0 = (buf[pos] | ((uint16_t)buf[pos + 1] << 8)) & 0xfff;
		val1 = (buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4);
		pos += 3;

		if (val0 < PARAM_Q && ctr < n)
			r[ctr++] = val0;
		if (val1 < PARAM_Q && ctr < n)
			r[ctr++] = val1;
	}
	*cur = ctr;
	return pos;
}

#ifdef USE_NICCS_API

void poly_uniform_seed(uint16_t *r,int n, const uint8_t *seed, int seedbytes)
{
	int cur = 0, off;
	int buflen = 3 * KDF128RATE;
	uint8_t buf[buflen];

	int len = buflen;
	kdfstate ctx;
	kdf_init(&ctx, seed, seedbytes);

	while (cur + 21 < n)
	{
		kdf_squeezeblocks(buf, 3, &ctx);
		rej_uniform(r, &cur, n, buf, len);
	}

	while (cur < n)
	{
		off = len & 0x3;
		for (int i = 0; i < off; i++)
			buf[i] = buf[len - off + 1];
		kdf_squeezeblocks(&buf[off], 1, &ctx);
		len = off + KDF128RATE;
		rej_uniform(r, &cur, n, buf, len);
	}
}

#elif defined(USE_SM3)

void poly_uniform_seed(uint16_t *r,int n, const uint8_t *seed, int seedbytes)
{
	int cur = 0, off;
	int buflen = 3 * KDF128RATE;
	uint8_t buf[buflen];

	int len = buflen;
	kdfstate ctx;
	kdf128_absorb(&ctx, seed, seedbytes);

	while (cur + 21 < n)
	{
		kdf128_squeezeblocks(buf, 3, &ctx);
		rej_uniform(r, &cur, n, buf, len);
	}

	while (cur < n)
	{
		off = len & 0x3;
		for (int i = 0; i < off; i++)
			buf[i] = buf[len - off + 1];
		kdf128_squeezeblocks(&buf[off], 1, &ctx);
		len = off + KDF128RATE;
		rej_uniform(r, &cur, n, buf, len);
	}
}

#elif defined(USE_SHA3)

void poly_uniform_seed(uint16_t *r, int n, const uint8_t *seed, int seedbytes)
{
	int cur = 0;
	uint8_t buf[KDF128RATE];
	int len;
	kdfstate state;
	kdf128_absorb(&state, seed, seedbytes);

	while (cur < n)
	{
		kdf128_squeezeblocks(buf, 1, &state);
		len = KDF128RATE;
		rej_uniform(r, &cur, n, buf, len);
	}
}

#endif


void gen_a(poly *a, const uint8_t *seed)
{
	int quarter_n = PARAM_N/4;
	uint8_t buf[SEED_BYTES + 1];
	memcpy(buf, seed, SEED_BYTES);
	for (int i = 0; i < 4; ++i) {
		buf[SEED_BYTES] = i;
		poly_uniform_seed(a->coeffs + i * quarter_n, quarter_n, buf, SEED_BYTES + 1);
	}
}
