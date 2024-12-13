#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define ntt AIGIS_SIG_NAMESPACE(ntt)
void ntt(uint32_t p[PARAM_N]);

#define invntt_frominvmont AIGIS_SIG_NAMESPACE(invntt_frominvmont)
void invntt_frominvmont(uint32_t p[PARAM_N]);

#endif
