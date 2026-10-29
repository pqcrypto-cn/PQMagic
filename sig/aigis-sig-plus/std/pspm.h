#ifndef PSPM_H
#define PSPM_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void emulate_cs1(polyvecl *r, const poly *c, const uint8_t s1_table[PARAM_L][PARAM_N * 3]);

#if PARAMS == 1
void emulate_cs2(polyveck *r, const poly *c, const uint16_t s2_table[PARAM_K][PARAM_N * 3]);
#else
void emulate_cs2(polyveck *r, const poly *c, const uint8_t s2_table[PARAM_K][PARAM_N * 3]);
#endif

int emulate_ct0(polyveck *r, const poly *c, const polyveck *t0);

int emulate_ct1(polyveck *r, const poly *c, const polyveck *t);

#endif
