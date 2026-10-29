#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"

static inline int16_t montgomery_reduce(int32_t a)
{
    int16_t t;
    t = (int16_t)a * QINV;
    t = (a - (int32_t)t * PARAM_Q) >> 16;
    return t;
}

static inline int16_t fqmul(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}


#if PARAM_Q == 641
static inline int16_t barrett_reduce(int16_t a)
{
    int16_t u;
    u = ((int32_t)a * 51 + (1 << 14)) >> 15;
    u *= PARAM_Q;
    a -= u;
    return a;
}
#elif PARAM_Q == 1409
static inline int16_t barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t v = ((1 << 25) + PARAM_Q / 2) / PARAM_Q;

    t = ((int32_t)v * a + (1 << 24)) >> 25;
    t *= PARAM_Q;
    return a - t;
}
#elif PARAM_Q == 3329
static inline int16_t barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t v = ((1 << 26) + PARAM_Q / 2) / PARAM_Q;

    t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= PARAM_Q;
    return a - t;
}
#elif PARAM_Q == 769
static inline int16_t barrett_reduce(int16_t a)
{
    int16_t t;
    const int16_t v = ((1 << 24) + PARAM_Q / 2) / PARAM_Q;

    t = ((int32_t)v * a + (1 << 23)) >> 24;

    return (int16_t)(a - (int32_t)t * PARAM_Q);
}
#endif

static inline int16_t caddq(int16_t x)
{
    return x + ((x >> 15) & PARAM_Q);
}

#endif