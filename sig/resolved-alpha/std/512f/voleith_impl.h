/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef VOLEITH_IMPL_H
#define VOLEITH_IMPL_H

#include <stdint.h>
#include <stddef.h>

#include "instances.h"

void voleith_sign(uint8_t* sig, const uint8_t* msg, size_t msglen, const uint8_t* owf_key,
                  const uint8_t* owf_input, const uint8_t* owf_output, const uint8_t* witness,
                  const uint8_t* rho, size_t rholen, const sig_paramset_t* params);

int voleith_verify(const uint8_t* msg, size_t msglen, const uint8_t* sig, const uint8_t* owf_input,
                   const uint8_t* owf_output, const sig_paramset_t* params);

#endif
