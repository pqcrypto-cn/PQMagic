#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[PARAM_L];
} polyvecl;

void polyvecl_reduce(polyvecl *v);
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void polyvecl_sub(polyvecl *w, const polyvecl *u, const polyvecl *v);
int polyvecl_uniform_gamma1(polyvecl *v, unsigned char* seed, unsigned int nonce);
void polyvecl_uniform_eta1(polyvecl *v, unsigned char* seed, unsigned int nonce);
void polyvecl_ntt(polyvecl *v);
void polyvecl_invntt_montgomery(polyvecl *v);
void polyvecl_pointwise_acc_invmontgomery(poly *w,
                                          const polyvecl *u,
                                          const polyvecl *v);

int polyvecl_chknorm(const polyvecl *v, uint32_t B);



/* Vectors of polynomials of length K */
typedef struct {
  poly vec[PARAM_K];
} polyveck;

void polyveck_amodq(polyveck *v);
void polyveck_cmodq(polyveck *v);
void polyveck_reduce(polyveck *v);
void polyveck_g_reduce(polyveck *v);
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void polyveck_subw(polyveck *v, const polyveck *u, const polyveck *w);
void polyveck_shiftl(polyveck *v, unsigned int k);
void polyveck_uniform_eta2(polyveck *v, unsigned char* seed, unsigned int nonce);
void polyveck_ntt(polyveck *v);
void polyveck_invntt_montgomery(polyveck *v);

int polyveck_chknorm(const polyveck *v, uint32_t B);

void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *u,
                                const polyveck *v);
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

void expand_mat(polyvecl mat[PARAM_K], const unsigned char rho[SEEDBYTES]);
void challenge(uint8_t *seed, const unsigned char mu[CRHBYTES], const polyveck *w1);
void unpack_c(poly *c, const uint8_t seed[SEEDBYTES]);
#endif
