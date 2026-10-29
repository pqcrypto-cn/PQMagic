/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef QUICKSILVER_H
#define QUICKSILVER_H

#include <stdint.h>

#include "instances.h"

SIG_BEGIN_C_DECL

void rsd_prover(uint8_t* a0_tilde, uint8_t* a1_tilde, const uint8_t* w,
                const uint8_t* u, uint8_t** V, const uint8_t* owf_in, const uint8_t* owf_out,
                const uint8_t* chall_2, const sig_paramset_t* params);
void rsd_verifier(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,
                  const uint8_t* owf_in, const uint8_t* owf_out, const uint8_t* chall_2,
                  const uint8_t* chall_3, const uint8_t* a1_tilde,
                  const sig_paramset_t* params);

SIG_END_C_DECL

#endif
