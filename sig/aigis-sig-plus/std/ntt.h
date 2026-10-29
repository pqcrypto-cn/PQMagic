#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

void ntt(int32_t p[PARAM_N]);
void invntt_frominvmont(int32_t p[PARAM_N]);

#endif
