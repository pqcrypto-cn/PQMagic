#include <stdint.h>
#include "params.h"
#include "reduce.h"
#include "rounding.h"
#include "poly.h"
#include "polyvec.h"

#include <string.h>

#include "hashkdf.h"
#include "api.h"

/*generate the public matrix from a seed*/
void expand_mat(polyvecl mat[PARAM_K], const unsigned char rho[SEEDBYTES])
{
	unsigned int i, j;
	unsigned char inbuf[SEEDBYTES + 1];
	for (i = 0; i < SEEDBYTES; ++i)
		inbuf[i] = rho[i];

	for (i = 0; i < PARAM_K; i++)
	{
		for (j = 0; j < PARAM_L; j++)
		{
			inbuf[SEEDBYTES] = (i<<4) | j;
			poly_uniform(&mat[i].vec[j], inbuf, SEEDBYTES + 1);

		}
	}
}


/*generate the the challenge c*/
#if PARAM_C <= 64
void challenge(uint8_t *seed, const unsigned char mu[CRHBYTES],
	const polyveck *w1)
{
	int i;
	uint8_t buf[CRHBYTES + PARAM_K * POLW1_SIZE_PACKED];
	for (i = 0; i < CRHBYTES; ++i)
		buf[i] = mu[i];
	for (i = 0; i < PARAM_K; ++i)
		polyw1_pack(buf + CRHBYTES + i * POLW1_SIZE_PACKED, w1->vec + i);
	Hash(seed, buf, sizeof(buf));
}

void unpack_c(poly *c, const uint8_t seed[SEEDBYTES])
{
	int32_t b;
	unsigned char outbuf[128 + KDF_RATE];
	int i, j, pos, buflen = 128;
	int nblocks = buflen / KDF_RATE;
	if (buflen % KDF_RATE != 0)
		nblocks++;
	kdfstate state;
	uint64_t signs;

	unsigned char	extmask[8] = { 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff };

#ifdef USE_ICCS 
  kdf_init(&state, seed, 32);
  kdf_squeezeblocks(outbuf, nblocks, &state);
#else
	KDF_ABSORB(&state, seed, 32);
	KDF_SQUEEZEBLOCK(outbuf, nblocks, &state);
#endif

	signs = 0;
	for (i = 0; i < (PARAM_C + 7) / 8; ++i)
		signs |= (uint64_t)outbuf[i] << 8 * i;

	pos = (PARAM_C + 7) / 8;

	for (i = 0; i < PARAM_N; ++i)
		c->coeffs[i] = 0;

	j = 0;
	for (i = PARAM_N - PARAM_C; i < PARAM_N; ++i) {
		do {
			if (pos >= buflen - 2) {
        #ifdef USE_ICCS 
				kdf_squeezeblocks(outbuf, 1, &state);
        #else 
				KDF_SQUEEZEBLOCK(outbuf, 1, &state);
        #endif
				pos = 0;
				buflen = KDF_RATE;
			}

			b = outbuf[pos++] >> j;
			b |= (uint32_t)(outbuf[pos] & extmask[j]) << (8 - j);
			j = (j + 1) % 8;
			if (j == 0)
				pos++;
		} while (b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (signs & 1);
		signs = 0;
	}
}

#elif PARAM_C > 64
void challenge(uint8_t* seed, const unsigned char mu[CRHBYTES],
	const polyveck* w1)
{
	int i;
	uint8_t buf[CRHBYTES + PARAM_K * POLW1_SIZE_PACKED];
	for (i = 0; i < CRHBYTES; ++i)
		buf[i] = mu[i];
	for (i = 0; i < PARAM_K; ++i)
		polyw1_pack(buf + CRHBYTES + i * POLW1_SIZE_PACKED, w1->vec + i);

	hash512(seed, buf, sizeof(buf));

}
void unpack_c(poly* c, const uint8_t seed[64])
{
	int32_t b;
	unsigned char outbuf[256 + KDF_RATE];
	int i, j, k, pos, buflen = 256;
	int nblocks = buflen / KDF_RATE;
	if (buflen % KDF_RATE != 0)
		nblocks++;
	kdfstate state;
	unsigned char signs[(PARAM_C + 7) / 8];

	unsigned char extmask[8] = { 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff };

  #ifdef USE_ICCS 
  kdf_init(&state, seed, 64);
  kdf_squeezeblocks(outbuf, nblocks, &state);
#else
	KDF_ABSORB(&state, seed, 64);
	KDF_SQUEEZEBLOCK(outbuf, nblocks, &state);
#endif

	pos = (PARAM_C + 7) / 8;
	memcpy(signs, outbuf, pos);

	for (i = 0; i < PARAM_N; ++i)
		c->coeffs[i] = 0;

	j = 0;
	i = PARAM_N - PARAM_C;
	for (k = 0; k < PARAM_C; k++)
	{
		do {
			if (pos >= buflen - 2) {
        #ifdef USE_ICCS 
        kdf_squeezeblocks(outbuf, 1, &state);
        #else 
				KDF_SQUEEZEBLOCK(outbuf, 1, &state);
        #endif
				pos = 0;
				buflen = KDF_RATE;
			}

			b = outbuf[pos++] >> j;
			b |= (uint32_t)(outbuf[pos] & extmask[j]) << (8 - j);
			j = (j + 1) % 8;
			if (j == 0)
				pos++;
		} while (b > i);
		c->coeffs[i++] = c->coeffs[b];
		c->coeffs[b] = 1 - 2 * (((uint32_t)signs[k / 8] >> (k % 8)) & 1);
	}
}
#endif

void polyvecl_reduce(polyvecl *v) {
	for (int i = 0; i < PARAM_L; ++i)
		poly_reduce(v->vec + i);
}

void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v) {
  for(int i = 0; i < PARAM_L; ++i)
      poly_add(w->vec+i, u->vec+i, v->vec+i);
}

void polyvecl_sub(polyvecl *w, const polyvecl *u, const polyvecl *v) {
  for(int i = 0; i < PARAM_L; ++i)
      poly_sub(w->vec+i, u->vec+i, v->vec+i);
}

void polyvecl_uniform_eta1(polyvecl *v, unsigned char* seed, unsigned int nonce)
{
	int i;
	for (i = 0; i < PARAM_L; i++)
	{
#if ETA1 == 1
		poly_uniform_eta_1(v->vec + i, seed, nonce++);
#else
		poly_uniform_eta_2(v->vec + i, seed, nonce++);
#endif

	}
}
int polyvecl_uniform_gamma1(polyvecl *v, unsigned char* seed, unsigned int nonce)
{
	int i;
	unsigned char inbuf[SEEDBYTES + CRHBYTES + 2];
	unsigned char outbuf[SZBITS * PARAM_N / 8 + 1];
	for (i = 0; i < SEEDBYTES + CRHBYTES; ++i)
		inbuf[i] = seed[i];
	for (i = 0; i < PARAM_L ; i++)
	{
		inbuf[SEEDBYTES + CRHBYTES] = nonce & 0xFF;
		inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >> 8;
		KDF(outbuf, SZBITS * PARAM_N / 8, inbuf, SEEDBYTES + CRHBYTES + 2);
		polyz_unpack(v->vec + i, outbuf);
		nonce++;
	}
  polyz_unpack(v->vec + i, outbuf);
  return 0;
}
void polyvecl_ntt(polyvecl *v) {
  int i;

  for(i = 0; i < PARAM_L; ++i)
    poly_ntt(v->vec+i);
}

void polyvecl_invntt_montgomery(polyvecl *v) {
	int i;

	for (i = 0; i < PARAM_L; ++i)
		poly_invntt_montgomery(v->vec + i);
}

void polyvecl_pointwise_acc_invmontgomery(poly *w,
                                          const polyvecl *u,
                                          const polyvecl *v) 
{
  int i;
  poly t;

  poly_pointwise_invmontgomery(w, u->vec+0, v->vec+0);

  for(i = 1; i < PARAM_L; ++i) {
    poly_pointwise_invmontgomery(&t, u->vec+i, v->vec+i);
    poly_add(w, w, &t);
  }
}

int polyvecl_chknorm(const polyvecl *v, uint32_t bound)  {
  int i;
  int ret = 0;

  for(i = 0; i < PARAM_L; ++i)
    ret |= poly_chknorm(v->vec+i, bound);

  return ret;
}
void polyveck_amodq(polyveck *v) {
	int i;
	for (i = 0; i < PARAM_K; ++i)
		poly_amodq(v->vec + i);
}
void polyveck_cmodq(polyveck *v) {
	int i;
	for (i = 0; i < PARAM_K; ++i)
		poly_cmodq(v->vec + i);
}
void polyveck_reduce(polyveck *v) {
	int i;
	for (i = 0; i < PARAM_K; ++i)
		poly_reduce(v->vec + i);
}
void polyveck_g_reduce(polyveck *v) {
	int i;
	for (i = 0; i < PARAM_K; ++i)
		poly_g_reduce(v->vec + i);
}

void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v) {
  int i;

  for(i = 0; i < PARAM_K; ++i)
      poly_add(w->vec+i, u->vec+i, v->vec+i);
}

void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v) {
  int i;

  for(i = 0; i < PARAM_K; ++i)
      poly_sub(w->vec+i, u->vec+i, v->vec+i);
}
void polyveck_subw(polyveck *v, const polyveck *u, const polyveck *w)
{
	int i;

	for (i = 0; i < PARAM_K; ++i)
		poly_subw(v->vec + i, u->vec + i, w->vec + i);
}
void polyveck_shiftl(polyveck *v, unsigned int k) { 
  int i;

  for(i = 0; i < PARAM_K; ++i)
    poly_shiftl(v->vec+i, k);
}

void polyveck_uniform_eta2(polyveck *v, unsigned char* seed, unsigned int nonce)
{
	int i;
	for (i = 0; i < PARAM_K; i++)
	{
    #if ETA2 == 5
		  poly_uniform_eta_5(v->vec + i, seed, nonce++);
    #elif ETA2 == 1
		poly_uniform_eta_1(v->vec + i, seed, nonce++);
#elif ETA2 == 2
		poly_uniform_eta_2(v->vec + i, seed, nonce++);
    #endif
	}
}

void polyveck_ntt(polyveck *v) {
  int i;

  for(i = 0; i < PARAM_K; ++i)
    poly_ntt(v->vec+i);
}

void polyveck_invntt_montgomery(polyveck *v) {
  int i;

  for(i = 0; i < PARAM_K; ++i)
    poly_invntt_montgomery(v->vec+i);
}

int polyveck_chknorm(const polyveck *v, uint32_t bound) {
  int i;
  int ret = 0;

  for(i = 0; i < PARAM_K; ++i)
    ret |= poly_chknorm(v->vec+i, bound);

  return ret;
}

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v) {
  int i, j;

  for(i = 0; i < PARAM_K; ++i)
    for(j = 0; j < PARAM_N; ++j)
      v1->vec[i].coeffs[j] = power2round(v->vec[i].coeffs[j],
                                         &v0->vec[i].coeffs[j]);
}

void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v) {
 int i, j;

  for(i = 0; i < PARAM_K; ++i)
    for(j = 0; j < PARAM_N; ++j)
        v1->vec[i].coeffs[j] = decompose(v->vec[i].coeffs[j],
                                       &v0->vec[i].coeffs[j]);
}

unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *u,
                                const polyveck *v)
{
  unsigned int i, j, k, s = 0, t = 0;

  for (i = 0; i < PARAM_K; ++i)
  {
    for (j = 0; j < PARAM_N / SEC; ++j)
    {
      s = 0;
      for (k = 0; k < SEC; ++k)
      {
        h->vec[i].coeffs[SEC * j + k] = make_hint(u->vec[i].coeffs[SEC * j + k], v->vec[i].coeffs[SEC * j + k]);
        s += h->vec[i].coeffs[SEC * j + k];
      }
	  if (s > NHW)
	  	return -1;
      t += s;
    }
  }
  return t;
}
void polyveck_use_hint(polyveck *w, const polyveck *u, const polyveck *h) {
  int i, j;

  for(i = 0; i < PARAM_K; ++i)
    for(j = 0; j < PARAM_N; ++j)
      w->vec[i].coeffs[j] = use_hint(u->vec[i].coeffs[j], h->vec[i].coeffs[j]);
}
