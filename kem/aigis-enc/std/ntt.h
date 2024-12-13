#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

#define ntt AIGIS_ENC_NAMESPACE(ntt)
void ntt(int16_t* poly);
#define invntt AIGIS_ENC_NAMESPACE(invntt)
void invntt(int16_t* poly);
#endif
