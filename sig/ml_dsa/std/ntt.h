#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define ntt ML_DSA_NAMESPACE(ntt)
void ntt(int32_t a[N]);

#define invntt_tomont ML_DSA_NAMESPACE(invntt_tomont)
void invntt_tomont(int32_t a[N]);

#endif
