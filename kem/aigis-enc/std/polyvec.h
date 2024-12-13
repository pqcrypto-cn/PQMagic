#ifndef POLYVEC_H
#define POLYVEC_H

#include "params.h"
#include "poly.h"

typedef struct{
  poly vec[PARAM_K];
} polyvec;

#define polyvec_caddq AIGIS_ENC_NAMESPACE(polyvec_caddq)
void polyvec_caddq(polyvec *r);
#define polyvec_reduce AIGIS_ENC_NAMESPACE(polyvec_reduce)
void polyvec_reduce(polyvec *r);
#define polyvec_ct_compress AIGIS_ENC_NAMESPACE(polyvec_ct_compress)
void polyvec_ct_compress(uint8_t *r, const polyvec *a);
#define polyvec_ct_decompress AIGIS_ENC_NAMESPACE(polyvec_ct_decompress)
void polyvec_ct_decompress(polyvec *r, const uint8_t *a);

#define polyvec_pk_compress AIGIS_ENC_NAMESPACE(polyvec_pk_compress)
void polyvec_pk_compress(uint8_t *r, const polyvec *a);
#define polyvec_pk_decompress AIGIS_ENC_NAMESPACE(polyvec_pk_decompress)
void polyvec_pk_decompress(polyvec *r, const uint8_t *a);

#define polyvec_tobytes AIGIS_ENC_NAMESPACE(polyvec_tobytes)
void polyvec_tobytes(uint8_t *r, const polyvec *a);
#define polyvec_frombytes AIGIS_ENC_NAMESPACE(polyvec_frombytes)
void polyvec_frombytes(polyvec *r, const uint8_t *a);

#define polyvec_ntt AIGIS_ENC_NAMESPACE(polyvec_ntt)
void polyvec_ntt(polyvec *r);
#define polyvec_invntt AIGIS_ENC_NAMESPACE(polyvec_invntt)
void polyvec_invntt(polyvec *r);

#define polyvec_pointwise_acc AIGIS_ENC_NAMESPACE(polyvec_pointwise_acc)
void polyvec_pointwise_acc(poly *r, const polyvec *a, const polyvec *b);

#define polyvec_add AIGIS_ENC_NAMESPACE(polyvec_add)
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
#define polyvec_ss_getnoise AIGIS_ENC_NAMESPACE(polyvec_ss_getnoise)
void polyvec_ss_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce);
#define polyvec_ee_getnoise AIGIS_ENC_NAMESPACE(polyvec_ee_getnoise)
void polyvec_ee_getnoise(polyvec *r, const uint8_t *seed, uint8_t nonce);
#endif
