#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "fips202.h"

typedef struct {
   int32_t coeffs[PARAM_N];
} poly;

void poly_amodq(poly *a);
void poly_cmodq(poly *a);
void poly_reduce(poly *a);
void poly_g_reduce(poly *a);
void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);
void poly_subw(poly *c, const poly *a, const poly *w);
void poly_shiftl(poly *a, unsigned int k);

void poly_ntt(poly *a);
void poly_invntt_montgomery(poly *a);
void poly_pointwise_invmontgomery(poly *c, const poly *a, const poly *b);

int  poly_chknorm(const poly *a, int32_t bound);
void poly_uniform(poly *a, uint8_t *seed, uint32_t seedbytes);
void poly_uniform_eta_1(poly *a,
                      const uint8_t seed[SEEDBYTES],
                      uint8_t nonce);
void poly_uniform_eta_2(poly *a,
                       const uint8_t seed[SEEDBYTES],
                       uint8_t nonce);
void poly_uniform_eta_5(poly *a,
                       const uint8_t seed[SEEDBYTES],
                       uint8_t nonce);
void poly_uniform_gamma1(poly *a,
                           const uint8_t seed[SEEDBYTES + CRHBYTES],
                           uint16_t nonce);

void polyeta1_pack(uint8_t *r, const poly *a);
void polyeta1_unpack(poly *r, const uint8_t *a);
void polyeta2_pack(uint8_t *r, const poly *a);
void polyeta2_unpack(poly *r, const uint8_t *a);

void polyt1_pack(uint8_t *r, const poly *a);
void polyt1_unpack(poly *r, const uint8_t *a);

void polyt0_pack(uint8_t *r, const poly *a);
void polyt0_unpack(poly *r, const uint8_t *a);

void polyz_pack(uint8_t *r, const poly *a);
void polyz_unpack(poly *r, const uint8_t *a);

void polyw1_pack(uint8_t *r, const poly *a);


#if PARAMS == 1
typedef uint16_t s2Word;
#else
typedef uint8_t s2Word;
#endif

#endif
