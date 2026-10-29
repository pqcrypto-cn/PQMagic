/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef RSD_H
#define RSD_H

#include "instances.h"

#include <stdint.h>

SIG_BEGIN_C_DECL

void rsd_owf(const uint8_t* seed_sk, const uint8_t* seed_pk, uint8_t* syndrome,
             const sig_paramset_t* params);
void rsd_extend_witness(uint8_t* witness, const uint8_t* seed_sk,
                        const uint8_t* seed_pk, const sig_paramset_t* params);
uint8_t* rsd_sample_matrix_b(const uint8_t* seed_pk, const sig_paramset_t* params);

SIG_END_C_DECL

#endif
