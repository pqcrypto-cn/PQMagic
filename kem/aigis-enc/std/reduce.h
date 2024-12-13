#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"

#define amodq AIGIS_ENC_NAMESPACE(amodq)
int16_t amodq(int16_t x);

#define montgomery_reduce AIGIS_ENC_NAMESPACE(montgomery_reduce)
int16_t montgomery_reduce(int32_t a);

#define barrett_reduce AIGIS_ENC_NAMESPACE(barrett_reduce)
int16_t barrett_reduce(int16_t a);

#define caddq AIGIS_ENC_NAMESPACE(caddq)
//reduce from [-PARAM_Q,PARAM_Q) to [0,PARAM_Q)
int16_t caddq (int16_t x);
#define caddq2 AIGIS_ENC_NAMESPACE(caddq2)
//reduce from [-2*PARAM_Q,PARAM_Q) to [0,PARAM_Q)
int16_t caddq2(int16_t x);

#endif
