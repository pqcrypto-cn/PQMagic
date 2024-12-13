#include <stdint.h>
#include <string.h>
#include "ntt.h"
#include "poly.h"
#include "params.h"
#include "reduce.h"

#ifdef USE_SHAKE
#include "hash/keccak/fips202.h"
#else
#include "fips202.h"
#include "include/sm3_extended.h"
#endif

void poly_freeze2q(poly *a) {
    unsigned int i;
    for(i = 0; i < PARAM_N; ++i)
        a->coeffs[i] = freeze4q(a->coeffs[i]);
}
void poly_freeze4q(poly *a) {
    unsigned int i;
    for(i = 0; i < PARAM_N; ++i)
        a->coeffs[i] = freeze4q(a->coeffs[i]);
}

void poly_add(poly *c, const poly *a, const poly *b)  {
  unsigned int i;

  for(i = 0; i < PARAM_N; ++i)
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;

  for(i = 0; i < PARAM_N; ++i)
    c->coeffs[i] = a->coeffs[i] + 2*PARAM_Q - b->coeffs[i];
      
}

void poly_neg(poly *a) {
  unsigned int i;

  for(i = 0; i < PARAM_N; ++i)
    a->coeffs[i] = 2*PARAM_Q - a->coeffs[i];
}

void poly_shiftl(poly *a, unsigned int k) {
  unsigned int i;

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
  unsigned int i;

  for(i = 0; i < PARAM_N; ++i)
      c->coeffs[i] = montgomery_reduce((uint64_t)a->coeffs[i] * b->coeffs[i]);
}

int poly_chknorm(const poly *a, uint32_t B) {
  unsigned int i;
  int32_t t;
  
  for(i = 0; i < PARAM_N; ++i) {
    t = (PARAM_Q-1)/2 - a->coeffs[i];
    t ^= (t >> 31);
    t = (PARAM_Q-1)/2 - t;

    if((uint32_t)t >= B)
      return 1;
  }

  return 0;
}

static void rej_eta1(uint32_t *a, const unsigned char *buf)
{
#if ETA1 > 3
#error "rej_eta1() assumes ETA1 <= 3"
#endif
	unsigned int ctr, pos;
	unsigned char t[8];

	ctr = pos = 0;

#if ETA1 == 1
	do {
		t[0] = buf[pos] & 0x03;
		t[1] = (buf[pos] >> 2) & 0x03;
		t[2] = (buf[pos] >> 4) & 0x03;
		t[3] = (buf[pos++] >> 6) & 0x03;

		if (t[0] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[0];
		if (t[1] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[1];
		if (t[2] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[2];
		if (t[3] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[3];
	} while (ctr < PARAM_N - 4);

	do {
		t[0] = buf[pos] & 0x03;
		t[1] = (buf[pos] >> 2) & 0x03;
		t[2] = (buf[pos] >> 4) & 0x03;
		t[3] = (buf[pos++] >> 6) & 0x03;

		if (t[0] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[0];
		if (t[1] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[1];
		if (t[2] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[2];
		if (t[3] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[3];
	} while (ctr < PARAM_N);
#else
	do {

		t[0] = buf[pos] & 0x07;
		t[1] = (buf[pos] >> 3) & 0x07;
		t[2] = (buf[pos] >> 6) | ((buf[pos + 1] & 0x1) << 2);
		t[3] = (buf[++pos] >> 1) & 0x07;
		t[4] = (buf[pos] >> 4) & 0x07;
		t[5] = (buf[pos] >> 7) | ((buf[pos + 1] & 0x3) << 1);
		t[6] = (buf[++pos] >> 2) & 0x07;
		t[7] = buf[pos++] >> 5;


		if (t[0] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[0];
		if (t[1] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[1];
		if (t[2] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[2];
		if (t[3] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[3];
		if (t[4] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[4];
		if (t[5] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[5];
		if (t[6] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[6];
		if (t[7] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[7];

	} while (ctr < PARAM_N - 8);


	do {

		t[0] = buf[pos] & 0x07;
		t[1] = (buf[pos] >> 3) & 0x07;
		t[2] = (buf[pos] >> 6) | ((buf[pos + 1] & 0x1) << 2);
		t[3] = (buf[++pos] >> 1) & 0x07;
		t[4] = (buf[pos] >> 4) & 0x07;
		t[5] = (buf[pos] >> 7) | ((buf[pos + 1] & 0x3) << 1);
		t[6] = (buf[++pos] >> 2) & 0x07;
		t[7] = buf[pos++] >> 5;


		if (t[0] <= 2 * ETA1)
			a[ctr++] = PARAM_Q + ETA1 - t[0];
		if (t[1] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[1];
		if (t[2] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[2];
		if (t[3] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[3];
		if (t[4] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[4];
		if (t[5] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[5];
		if (t[6] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[6];
		if (t[7] <= 2 * ETA1 && ctr < PARAM_N)
			a[ctr++] = PARAM_Q + ETA1 - t[7];

	} while (ctr < PARAM_N);
#endif
}

static unsigned int rej_eta2(uint32_t *a, unsigned int len, const unsigned char *buf)
{
#if ETA2 >7 || ETA2 < 3
#error "rej_eta2() assumes 3 <= ETA2 <=7"
#endif

	unsigned int ctr = 0, pos = 0;
	unsigned char t0, t1;

	do {
#if ETA2 == 3
		t0 = buf[pos] & 0x07;
		t1 = buf[pos++] >> 5;
#else
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;
#endif
		if (t0 <= 2 * ETA2)
			a[ctr++] = PARAM_Q + ETA2 - t0;
		if (t1 <= 2 * ETA2)
			a[ctr++] = PARAM_Q + ETA2 - t1;
	} while (ctr < len - 2);


	do {
#if ETA2 == 3
		t0 = buf[pos] & 0x07;
		t1 = buf[pos++] >> 5;
#else
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;
#endif

		if (t0 <= 2 * ETA2)
			a[ctr++] = PARAM_Q + ETA2 - t0;
		if (t1 <= 2 * ETA2 && ctr<len)
			a[ctr++] = PARAM_Q + ETA2 - t1;
	} while (ctr < len);

	return pos;
}


void poly_uniform_eta1(poly *a,
                      const unsigned char seed[SEEDBYTES], 
                      unsigned char nonce)
{
#if ETA1>3 
#error "rej_eta1() assumes ETA1 <=3"
#endif
 
  unsigned int i;
  unsigned char inbuf[SEEDBYTES + 2];
  unsigned char outbuf[2*SHAKE256_RATE];

  for(i= 0; i < SEEDBYTES; ++i)
    inbuf[i] = seed[i];
  inbuf[SEEDBYTES] = nonce;

#ifdef USE_SHAKE
  shake256(outbuf, 2*SHAKE256_RATE, inbuf, SEEDBYTES + 1);
#else
  inbuf[SEEDBYTES + 1] = 0; // Keep consistency with adv version.
  sm3_extended(outbuf, 2*SHAKE256_RATE, inbuf, SEEDBYTES + 2);
#endif

  rej_eta1(a->coeffs,outbuf);
}


void poly_uniform_eta2(poly *a,
                      const unsigned char seed[SEEDBYTES], 
                      unsigned char nonce)
{
#if ETA2!=3 && ETA2!=5 
#error "rej_eta2() assumes ETA2 == 3 or 5"
#endif

  unsigned int i;
  unsigned char inbuf[SEEDBYTES + 2];

#if ETA2==3
  unsigned char outbuf[2*SHAKE256_RATE];
#elif ETA2==5
  unsigned int pos;
  unsigned char outbuf[3*SHAKE256_RATE];
#endif

  for(i= 0; i < SEEDBYTES; ++i)
    inbuf[i] = seed[i];
  inbuf[SEEDBYTES] = nonce;

#ifdef USE_SHAKE
  keccak_state state;
  shake256_absorb_once(&state, inbuf, SEEDBYTES + 1);
  shake256_squeezeblocks(outbuf, 2, &state);
#else
  inbuf[SEEDBYTES + 1] = 0; // Keep consistency with adv version.
  sm3_extended(outbuf, 2*SHAKE256_RATE, inbuf, SEEDBYTES + 2);
#endif

#if ETA2 ==3
  rej_eta2(a->coeffs, PARAM_N, outbuf);
  /* Probability we need more than 2 blocks to generate 223 elements: < 2^{-378}.*/

#elif ETA2==5
  pos = rej_eta2(a->coeffs, 223, outbuf);

  /* Probability we need more than 2 blocks to generate 223 elements: < 2^{-133}.*/
  /* Probability we need more than 85 bytes to generate 33 elements: < 2^{-133}.*/

  if(2*SHAKE256_RATE - pos < 85) {
  #ifdef USE_SHAKE
	  shake256_squeezeblocks(outbuf + 2 * SHAKE256_RATE, 1, &state);
  #else
	  inbuf[SEEDBYTES + 1] = 1;
	  sm3_extended(&outbuf[2*SHAKE256_RATE], SHAKE256_RATE, inbuf, SEEDBYTES + 2);
  #endif
  }

  rej_eta2(&a->coeffs[223], 33, &outbuf[pos]);
#endif
}

void poly_uniform_gamma1m1(poly *a,
                           const unsigned char seed[SEEDBYTES + CRHBYTES],
                           uint16_t nonce)
{
#if GAMMA1 != 131072
#error "poly_uniform_gamma1m1() assumes GAMMA1 == 131072"
#endif

  unsigned int i, ctr=0, pos=0;
  uint32_t t0, t1;
  unsigned char inbuf[SEEDBYTES + CRHBYTES + 2];
  unsigned char outbuf[5*SHAKE256_RATE];

  for(i = 0; i < SEEDBYTES + CRHBYTES; ++i)
    inbuf[i] = seed[i];
  inbuf[SEEDBYTES + CRHBYTES] = nonce & 0xFF;
  inbuf[SEEDBYTES + CRHBYTES + 1] = nonce >> 8;

#ifdef USE_SHAKE
  shake256(outbuf,5*SHAKE256_RATE,inbuf, SEEDBYTES + CRHBYTES + 2);
#else
  sm3_extended(outbuf,5*SHAKE256_RATE,inbuf, SEEDBYTES + CRHBYTES + 2);
#endif
  
  do{
    t0  = outbuf[pos];
    t0 |= (uint32_t)outbuf[pos + 1] << 8;
    t0 |= (uint32_t)outbuf[pos + 2] << 16;

	t1  = outbuf[pos + 2] >> 4;
    t1 |= (uint32_t)outbuf[pos + 3] << 4;
    t1 |= (uint32_t)outbuf[pos + 4] << 12;

	t0 &= 0x3FFFF;
	t1 &= 0x3FFFF;

    if(t0 <= 2*GAMMA1)
    		a->coeffs[ctr++] = PARAM_Q + GAMMA1 - 1  - t0;
    if(t1 <= 2*GAMMA1)
		a->coeffs[ctr++] = PARAM_Q + GAMMA1 - 1  - t1;
     
    pos += 5;
  }while(ctr < PARAM_N-2);
  
  
  do{
    t0  = outbuf[pos];
    t0 |= (uint32_t)outbuf[pos + 1] << 8;
    t0 |= (uint32_t)outbuf[pos + 2] << 16;

	t1  = outbuf[pos + 2] >> 4;
    t1 |= (uint32_t)outbuf[pos + 3] << 4;
    t1 |= (uint32_t)outbuf[pos + 4] << 12;

	t0 &= 0x3FFFF;
	t1 &= 0x3FFFF;

    if(t0 <= 2*GAMMA1)
    		a->coeffs[ctr++] = PARAM_Q + GAMMA1 - 1 - t0;
    if(t1 <= 2*GAMMA1 && ctr< PARAM_N)
		a->coeffs[ctr++] = PARAM_Q + GAMMA1 - 1 - t1;
      
    pos += 5;
  }while(ctr < PARAM_N);

}

void polyeta1_pack(unsigned char *r, const poly *a) {
#if ETA1 > 3
#error "polyeta1_pack() assumes ETA1 <= 3"
#endif
	unsigned int i;
	unsigned char t[8];

#if ETA1 == 1
	for (i = 0; i < PARAM_N / 4; ++i) {
		t[0] = PARAM_Q + ETA1 - a->coeffs[4 * i + 0];
		t[1] = PARAM_Q + ETA1 - a->coeffs[4 * i + 1];
		t[2] = PARAM_Q + ETA1 - a->coeffs[4 * i + 2];
		t[3] = PARAM_Q + ETA1 - a->coeffs[4 * i + 3];
		r[i] = t[0] | (t[1] << 2) | (t[2] << 4) | (t[3] << 6);
	}
#else
	for (i = 0; i < PARAM_N / 8; ++i) {
		t[0] = PARAM_Q + ETA1 - a->coeffs[8 * i + 0];
		t[1] = PARAM_Q + ETA1 - a->coeffs[8 * i + 1];
		t[2] = PARAM_Q + ETA1 - a->coeffs[8 * i + 2];
		t[3] = PARAM_Q + ETA1 - a->coeffs[8 * i + 3];
		t[4] = PARAM_Q + ETA1 - a->coeffs[8 * i + 4];
		t[5] = PARAM_Q + ETA1 - a->coeffs[8 * i + 5];
		t[6] = PARAM_Q + ETA1 - a->coeffs[8 * i + 6];
		t[7] = PARAM_Q + ETA1 - a->coeffs[8 * i + 7];

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
void polyeta2_pack(unsigned char *r, const poly *a) {
#if ETA2 > 7
#error "polyeta2_pack() assumes ETA2 <= 7"
#endif
  unsigned int i;
  unsigned char t[8];

#if ETA2 <= 3
  for(i = 0; i < PARAM_N/8; ++i) {
    t[0] = PARAM_Q + ETA2 - a->coeffs[8*i+0];
    t[1] = PARAM_Q + ETA2 - a->coeffs[8*i+1];
    t[2] = PARAM_Q + ETA2 - a->coeffs[8*i+2];
    t[3] = PARAM_Q + ETA2 - a->coeffs[8*i+3];
    t[4] = PARAM_Q + ETA2 - a->coeffs[8*i+4];
    t[5] = PARAM_Q + ETA2 - a->coeffs[8*i+5];
    t[6] = PARAM_Q + ETA2 - a->coeffs[8*i+6];
    t[7] = PARAM_Q + ETA2 - a->coeffs[8*i+7];

    r[3*i+0]  = t[0];
    r[3*i+0] |= t[1] << 3;
    r[3*i+0] |= t[2] << 6;
    r[3*i+1]  = t[2] >> 2;
    r[3*i+1] |= t[3] << 1;
    r[3*i+1] |= t[4] << 4;
    r[3*i+1] |= t[5] << 7;
    r[3*i+2]  = t[5] >> 1;
    r[3*i+2] |= t[6] << 2;
    r[3*i+2] |= t[7] << 5;
  }
#else
  for(i = 0; i < PARAM_N/2; ++i) {
    t[0] = PARAM_Q + ETA2 - a->coeffs[2*i+0];
    t[1] = PARAM_Q + ETA2 - a->coeffs[2*i+1];
    r[i] = t[0] | (t[1] << 4);
  }
#endif
}

void polyeta1_unpack(poly *r, const unsigned char *a)
{
#if ETA1 > 3
#error "polyeta1_unpack() assumes ETA1 <= 3"
#endif

	unsigned int i;
#if ETA1 == 1
	for (i = 0; i < PARAM_N / 4; ++i) {
		r->coeffs[4 * i + 0] = a[i] & 0x03;
		r->coeffs[4 * i + 1] = (a[i] >> 2) & 0x03;
		r->coeffs[4 * i + 2] = (a[i] >> 4) & 0x03;
		r->coeffs[4 * i + 3] = (a[i] >> 6) & 0x03;

		r->coeffs[4 * i + 0] = PARAM_Q + ETA1 - r->coeffs[4 * i + 0];
		r->coeffs[4 * i + 1] = PARAM_Q + ETA1 - r->coeffs[4 * i + 1];
		r->coeffs[4 * i + 2] = PARAM_Q + ETA1 - r->coeffs[4 * i + 2];
		r->coeffs[4 * i + 3] = PARAM_Q + ETA1 - r->coeffs[4 * i + 3];
	}
#else
	for (i = 0; i < PARAM_N / 8; ++i) {
		r->coeffs[8 * i + 0] = a[3 * i + 0] & 0x07;
		r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 0x07;
		r->coeffs[8 * i + 2] = (a[3 * i + 0] >> 6) | ((a[3 * i + 1] & 0x01) << 2);
		r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 0x07;
		r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 0x07;
		r->coeffs[8 * i + 5] = (a[3 * i + 1] >> 7) | ((a[3 * i + 2] & 0x03) << 1);
		r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 0x07;
		r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5);

		r->coeffs[8 * i + 0] = PARAM_Q + ETA1 - r->coeffs[8 * i + 0];
		r->coeffs[8 * i + 1] = PARAM_Q + ETA1 - r->coeffs[8 * i + 1];
		r->coeffs[8 * i + 2] = PARAM_Q + ETA1 - r->coeffs[8 * i + 2];
		r->coeffs[8 * i + 3] = PARAM_Q + ETA1 - r->coeffs[8 * i + 3];
		r->coeffs[8 * i + 4] = PARAM_Q + ETA1 - r->coeffs[8 * i + 4];
		r->coeffs[8 * i + 5] = PARAM_Q + ETA1 - r->coeffs[8 * i + 5];
		r->coeffs[8 * i + 6] = PARAM_Q + ETA1 - r->coeffs[8 * i + 6];
		r->coeffs[8 * i + 7] = PARAM_Q + ETA1 - r->coeffs[8 * i + 7];
	}
#endif
}
void polyeta2_unpack(poly *r, const unsigned char *a) 
{
#if ETA2 > 7
#error "polyeta2_unpack() assumes ETA2 <= 7"
#endif

  unsigned int i;
#if ETA2 <= 3
  for(i = 0; i < PARAM_N/8; ++i) {
    r->coeffs[8*i+0] = a[3*i+0] & 0x07;
    r->coeffs[8*i+1] = (a[3*i+0] >> 3) & 0x07;
    r->coeffs[8*i+2] = (a[3*i+0] >> 6) | ((a[3*i+1] & 0x01) << 2);
    r->coeffs[8*i+3] = (a[3*i+1] >> 1) & 0x07;
    r->coeffs[8*i+4] = (a[3*i+1] >> 4) & 0x07;
    r->coeffs[8*i+5] = (a[3*i+1] >> 7) | ((a[3*i+2] & 0x03) << 1);
    r->coeffs[8*i+6] = (a[3*i+2] >> 2) & 0x07;
    r->coeffs[8*i+7] = (a[3*i+2] >> 5);

    r->coeffs[8*i+0] = PARAM_Q + ETA2 - r->coeffs[8*i+0];
    r->coeffs[8*i+1] = PARAM_Q + ETA2 - r->coeffs[8*i+1];
    r->coeffs[8*i+2] = PARAM_Q + ETA2 - r->coeffs[8*i+2];
    r->coeffs[8*i+3] = PARAM_Q + ETA2 - r->coeffs[8*i+3];
    r->coeffs[8*i+4] = PARAM_Q + ETA2 - r->coeffs[8*i+4];
    r->coeffs[8*i+5] = PARAM_Q + ETA2 - r->coeffs[8*i+5];
    r->coeffs[8*i+6] = PARAM_Q + ETA2 - r->coeffs[8*i+6];
    r->coeffs[8*i+7] = PARAM_Q + ETA2 - r->coeffs[8*i+7];
  }
#else
  for(i = 0; i < PARAM_N/2; ++i) {
    r->coeffs[2*i+0] = a[i] & 0x0F;
    r->coeffs[2*i+1] = a[i] >> 4;
    r->coeffs[2*i+0] = PARAM_Q + ETA2 - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = PARAM_Q + ETA2 - r->coeffs[2*i+1];
  }
#endif
}

void polyt1_pack(unsigned char *r, const poly *a) 
{
#if QBITS - PARAM_D != 8
#error "polyt1_pack() assumes QBITS - PARAM_D == 8"
#endif

  unsigned int i;
  for(i = 0; i < PARAM_N; ++i)
	  r[i]  =  a->coeffs[i];
}

void polyt1_unpack(poly *r, const unsigned char *a) 
{
#if QBITS - PARAM_D != 8
#error "polyt1_unpack() assumes QBITS - PARAM_D == 8"
#endif

  unsigned int i;
  for(i = 0; i < PARAM_N; ++i)
	  r->coeffs[i]  =  a[i];
}

void polyt0_pack(unsigned char *r, const poly *a) {

#if PARAM_D!=13 && PARAM_D!=14
#error "polyt0_unpack() assumes PARAM_D== 13 or 14"
#endif

	unsigned int i;
#if PARAM_D == 13
  uint32_t t[8];
  for(i = 0; i < PARAM_N/8; ++i) {
	  t[0] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+0];
	  t[1] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+1];
	  t[2] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+2];
	  t[3] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+3];
	  t[4] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+4];
	  t[5] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+5];
	  t[6] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+6];
	  t[7] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[8*i+7];

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
  uint32_t t[4];
  for(i = 0; i < PARAM_N/4; ++i) {
    t[0] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[4*i+0];
    t[1] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[4*i+1];
    t[2] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[4*i+2];
    t[3] = PARAM_Q + (1 << (PARAM_D-1)) - a->coeffs[4*i+3];

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
#endif
}

void polyt0_unpack(poly *r, const unsigned char *a) 
{
#if PARAM_D!=13 && PARAM_D!=14
#error "polyt0_unpack() assumes PARAM_D== 13 or 14"
#endif

  unsigned int i;
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


	  r->coeffs[8*i+0] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+0];
      r->coeffs[8*i+1] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+1];
      r->coeffs[8*i+2] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+2];
      r->coeffs[8*i+3] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+3];
	  r->coeffs[8*i+4] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+4];
      r->coeffs[8*i+5] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+5];
      r->coeffs[8*i+6] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+6];
      r->coeffs[8*i+7] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[8*i+7];

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

    r->coeffs[4*i+0] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[4*i+0];
    r->coeffs[4*i+1] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[4*i+1];
    r->coeffs[4*i+2] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[4*i+2];
    r->coeffs[4*i+3] = PARAM_Q + (1 << (PARAM_D-1)) - r->coeffs[4*i+3];
  }
#endif
}

void polyz_pack(unsigned char *r, const poly *a) {
#if GAMMA1 - BETA1 > (1 << 17)
#error "polyz_pack() assumes GAMMA1-BETA1 <= 2^{17}"
#endif
  unsigned int i;
  
  uint32_t t[4];
  for(i = 0; i < PARAM_N/4; ++i) {
    /* Map to {0,...,2*GAMMA1 - 2} */ // 18-bit
    t[0] = GAMMA1 - 1 - a->coeffs[4*i+0];
    t[0] += ((int32_t)t[0] >> 31) & PARAM_Q;
    t[1] = GAMMA1 - 1 - a->coeffs[4*i+1];
    t[1] += ((int32_t)t[1] >> 31) & PARAM_Q;
	t[2] = GAMMA1 - 1 - a->coeffs[4*i+2];
    t[2] += ((int32_t)t[2] >> 31) & PARAM_Q;
	t[3] = GAMMA1 - 1 - a->coeffs[4*i+3];
    t[3] += ((int32_t)t[3] >> 31) & PARAM_Q;

    r[9*i+0]  = t[0];
    r[9*i+1]  = t[0] >> 8;
    r[9*i+2]  = t[0] >> 16;
    r[9*i+2] |= t[1] << 2;
    r[9*i+3]  = t[1] >> 6;
    r[9*i+4]  = t[1] >> 14;
	r[9*i+4] |= t[2] << 4;
    r[9*i+5]  = t[2] >> 4;
    r[9*i+6]  = t[2] >> 12;
    r[9*i+6] |= t[3] << 6;
    r[9*i+7]  = t[3] >> 2;
	r[9*i+8]  = t[3] >> 10;

  }
}

void polyz_unpack(poly *r, const unsigned char *a) {

#if GAMMA1 - BETA1 > (1 << 17)
#error "polyz_unpack() assumes GAMMA1 - BETA1<= 2^{17}"
#endif
	
  unsigned int i;
  for(i = 0; i < PARAM_N/4; ++i) {
	  r->coeffs[4*i+0]  = a[9*i+0];
	  r->coeffs[4*i+0] |= (uint32_t)a[9*i+1] << 8;
	  r->coeffs[4*i+0] |= (uint32_t)(a[9*i+2] & 0x03) << 16;
	  r->coeffs[4*i+0] = GAMMA1 - 1 - r->coeffs[4*i+0];
	  r->coeffs[4*i+0] += ((int32_t)r->coeffs[4*i+0] >> 31) & PARAM_Q;

	  r->coeffs[4*i+1]  = a[9*i+2] >> 2;
	  r->coeffs[4*i+1] |= (uint32_t)a[9*i+3] << 6;
	  r->coeffs[4*i+1] |= (uint32_t)(a[9*i+4] & 0x0F) << 14;
	  r->coeffs[4*i+1] = GAMMA1 - 1 - r->coeffs[4*i+1];
	  r->coeffs[4*i+1] += ((int32_t)r->coeffs[4*i+1] >> 31) & PARAM_Q;

	  r->coeffs[4*i+2]  = a[9*i+4] >> 4;
	  r->coeffs[4*i+2] |= (uint32_t)a[9*i+5] << 4;
	  r->coeffs[4*i+2] |= (uint32_t)(a[9*i+6] & 0x3F) << 12;
	  r->coeffs[4*i+2] = GAMMA1 - 1 - r->coeffs[4*i+2];
	  r->coeffs[4*i+2] += ((int32_t)r->coeffs[4*i+2] >> 31) & PARAM_Q;


	  r->coeffs[4*i+3]  = a[9*i+6] >> 6;
	  r->coeffs[4*i+3] |= (uint32_t)a[9*i+7] << 2;
	  r->coeffs[4*i+3] |= (uint32_t)a[9*i+8] << 10;
	  r->coeffs[4*i+3] = GAMMA1 - 1 - r->coeffs[4*i+3];
	  r->coeffs[4*i+3] += ((int32_t)r->coeffs[4*i+3] >> 31) & PARAM_Q;
  }
}

void polyw1_pack(unsigned char *r, const poly *a) 
{
#if PARAM_Q/ALPHA > 8
#error "polyw1_pack() assumes PARAM_Q/ALPHA -1 <= 7"
#endif
  unsigned int i;

  for(i = 0; i < PARAM_N/8; ++i)
  {
    r[3*i+0] = a->coeffs[8*i+0]      | (a->coeffs[8*i+1] << 3) | (a->coeffs[8*i+ 2] << 6);
	r[3*i+1] = (a->coeffs[8*i+2]>>2) | (a->coeffs[8*i+3] << 1) | (a->coeffs[8*i+ 4] << 4) | (a->coeffs[8*i+ 5] << 7);
	r[3*i+2] = (a->coeffs[8*i+5]>>1) | (a->coeffs[8*i+6] << 2) | (a->coeffs[8*i+ 7] << 5);
 }
}
