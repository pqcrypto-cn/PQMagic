#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
  uint32_t coeffs[PARAM_N];
} poly __attribute__((aligned(32)));

#define poly_copy AIGIS_SIG_NAMESPACE(poly_copy)
void poly_copy(poly *b, const poly *a);
#define poly_freeze2q AIGIS_SIG_NAMESPACE(poly_freeze2q)
void poly_freeze2q(poly *a);
#define poly_freeze4q AIGIS_SIG_NAMESPACE(poly_freeze4q)
void poly_freeze4q(poly *a);

#define poly_add AIGIS_SIG_NAMESPACE(poly_add)
void poly_add(poly *c, const poly *a, const poly *b);
#define poly_sub AIGIS_SIG_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
#define poly_neg AIGIS_SIG_NAMESPACE(poly_neg)
void poly_neg(poly *a);
#define poly_shiftl AIGIS_SIG_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a, unsigned int k);

#define poly_ntt AIGIS_SIG_NAMESPACE(poly_ntt)
void poly_ntt(poly *a);
#define poly_invntt_montgomery AIGIS_SIG_NAMESPACE(poly_invntt_montgomery)
void poly_invntt_montgomery(poly *a);
#define poly_pointwise_invmontgomery AIGIS_SIG_NAMESPACE(poly_pointwise_invmontgomery)
void poly_pointwise_invmontgomery(poly *c, const poly *a, const poly *b);

#define poly_chknorm AIGIS_SIG_NAMESPACE(poly_chknorm)
int  poly_chknorm(const poly *a, uint32_t B);
#define poly_uniform AIGIS_SIG_NAMESPACE(poly_uniform)
void poly_uniform(poly *a, unsigned char *buf);
#define poly_uniform_eta1 AIGIS_SIG_NAMESPACE(poly_uniform_eta1)
void poly_uniform_eta1(poly *a,
                      const unsigned char seed[SEEDBYTES],
                      unsigned char nonce);
#define poly_uniform_eta2 AIGIS_SIG_NAMESPACE(poly_uniform_eta2)
void poly_uniform_eta2(poly *a,
                      const unsigned char seed[SEEDBYTES],
                      unsigned char nonce);
#define poly_uniform_gamma1m1 AIGIS_SIG_NAMESPACE(poly_uniform_gamma1m1)
void poly_uniform_gamma1m1(poly *a,
                           const unsigned char seed[SEEDBYTES + CRHBYTES],
                           uint16_t nonce);

#define polyeta1_pack AIGIS_SIG_NAMESPACE(polyeta1_pack)
void polyeta1_pack(unsigned char *r, const poly *a);
#define polyeta1_unpack AIGIS_SIG_NAMESPACE(polyeta1_unpack)
void polyeta1_unpack(poly *r, const unsigned char *a);
#define polyeta2_pack AIGIS_SIG_NAMESPACE(polyeta2_pack)
void polyeta2_pack(unsigned char *r, const poly *a);
#define polyeta2_unpack AIGIS_SIG_NAMESPACE(polyeta2_unpack)
void polyeta2_unpack(poly *r, const unsigned char *a);

#define polyt1_pack AIGIS_SIG_NAMESPACE(polyt1_pack)
void polyt1_pack(unsigned char *r, const poly *a);
#define polyt1_unpack AIGIS_SIG_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const unsigned char *a);

#define polyt0_pack AIGIS_SIG_NAMESPACE(polyt0_pack)
void polyt0_pack(unsigned char *r, const poly *a);
#define polyt0_unpack AIGIS_SIG_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const unsigned char *a);

#define polyz_pack AIGIS_SIG_NAMESPACE(polyz_pack)
void polyz_pack(unsigned char *r, const poly *a);
#define polyz_unpack AIGIS_SIG_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const unsigned char *a);

#define polyw1_pack AIGIS_SIG_NAMESPACE(polyw1_pack)
void polyw1_pack(unsigned char *r, const poly *a);
#endif
