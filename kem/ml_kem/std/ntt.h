#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define zetas ML_KEM_NAMESPACE(_zetas)
extern const int16_t zetas[128];

#define zetas_inv ML_KEM_NAMESPACE(_zetas_inv)
extern const int16_t zetas_inv[128];

#define ntt ML_KEM_NAMESPACE(_ntt)
void ntt(int16_t poly[256]);

#define invntt ML_KEM_NAMESPACE(_invntt)
void invntt(int16_t poly[256]);

#define basemul ML_KEM_NAMESPACE(_basemul)
void basemul(int16_t r[2],
             const int16_t a[2],
             const int16_t b[2],
             int16_t zeta);

#endif
