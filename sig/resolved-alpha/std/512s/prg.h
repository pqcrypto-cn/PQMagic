/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef PRG_H
#define PRG_H

#include "macros.h"

#include <stddef.h>
#include <stdint.h>

SIG_BEGIN_C_DECL

void prg(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out, unsigned int csp,
         size_t outlen);
void prg_2_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                  unsigned int csp);
void prg_4_lambda(const uint8_t* key, const uint8_t* iv, uint32_t tweak, uint8_t* out,
                  unsigned int csp);

#if defined(SIG_TESTS)
void prg_increment_iv(uint8_t* iv);
#endif

SIG_END_C_DECL

#endif
