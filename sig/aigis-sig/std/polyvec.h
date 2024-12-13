#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[PARAM_L];
} polyvecl;

#define polyvecl_freeze2q AIGIS_SIG_NAMESPACE(polyvecl_freeze2q)
void polyvecl_freeze2q(polyvecl *v);
#define polyvecl_freeze4q AIGIS_SIG_NAMESPACE(polyvecl_freeze4q)
void polyvecl_freeze4q(polyvecl *v);


#define polyvecl_add AIGIS_SIG_NAMESPACE(polyvecl_add)
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

#define polyvecl_ntt AIGIS_SIG_NAMESPACE(polyvecl_ntt)
void polyvecl_ntt(polyvecl *v);
#define polyvecl_pointwise_acc_invmontgomery AIGIS_SIG_NAMESPACE(polyvecl_pointwise_acc_invmontgomery)
void polyvecl_pointwise_acc_invmontgomery(poly *w,
                                          const polyvecl *u,
                                          const polyvecl *v);

#define polyvecl_chknorm AIGIS_SIG_NAMESPACE(polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, uint32_t B);



/* Vectors of polynomials of length K */
typedef struct {
  poly vec[PARAM_K];
} polyveck;

#define polyveck_freeze2q AIGIS_SIG_NAMESPACE(polyveck_freeze2q)
void polyveck_freeze2q(polyveck *v);
#define polyveck_freeze4q AIGIS_SIG_NAMESPACE(polyveck_freeze4q)
void polyveck_freeze4q(polyveck *v);

#define polyveck_add AIGIS_SIG_NAMESPACE(polyveck_add)
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_sub AIGIS_SIG_NAMESPACE(polyveck_sub)
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_neg AIGIS_SIG_NAMESPACE(polyveck_neg)
void polyveck_neg(polyveck *v);
#define polyveck_shiftl AIGIS_SIG_NAMESPACE(polyveck_shiftl)
void polyveck_shiftl(polyveck *v, unsigned int k);

#define polyveck_ntt AIGIS_SIG_NAMESPACE(polyveck_ntt)
void polyveck_ntt(polyveck *v);
#define polyveck_invntt_montgomery AIGIS_SIG_NAMESPACE(polyveck_invntt_montgomery)
void polyveck_invntt_montgomery(polyveck *v);

#define polyveck_chknorm AIGIS_SIG_NAMESPACE(polyveck_chknorm)
int polyveck_chknorm(const polyveck *v, uint32_t B);

#define polyveck_power2round AIGIS_SIG_NAMESPACE(polyveck_power2round)
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_decompose AIGIS_SIG_NAMESPACE(polyveck_decompose)
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_make_hint AIGIS_SIG_NAMESPACE(polyveck_make_hint)
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *u,
                                const polyveck *v);
#define polyveck_use_hint AIGIS_SIG_NAMESPACE(polyveck_use_hint)
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

#endif
