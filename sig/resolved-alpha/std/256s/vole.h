/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIG_VOLE_H
#define SIG_VOLE_H

#include <stdbool.h>

#include "bavc.h"

SIG_BEGIN_C_DECL

void vole_commit(const uint8_t* rootKey, const uint8_t* iv, const uint8_t* mu,
                 const uint8_t* tccr_s,
                 unsigned int ellhat,
                 const sig_paramset_t* params, bavc_t* vecCom, uint8_t* c, uint8_t* u,
                 uint8_t** v);

bool vole_reconstruct(uint8_t* com, uint8_t** q, const uint8_t* iv, const uint8_t* chall_3,
                      const uint8_t* decom_i, const uint8_t* c, const uint8_t* mu,
                      const uint8_t* tccr_s, unsigned int ellhat, const sig_paramset_t* params);

#if defined(SIG_TESTS)
unsigned int convert_to_vole(const uint8_t* iv, const uint8_t* sd, bool sd0_bot, unsigned int i,
                             unsigned int outLenBytes, uint8_t* u, uint8_t* v,
                             const sig_paramset_t* params);
#endif

SIG_END_C_DECL

#endif
