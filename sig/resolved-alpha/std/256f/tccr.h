/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef TCCR_H
#define TCCR_H

#include <stddef.h>
#include <stdint.h>

// Tweakable Circular Correlation Robust hash per NGCC spec §SYM.
// TCCRHash(x, s, iv):
//   x  ∈ bool[csp]  — input
//   s  ∈ bool[csp]  — tweak
//   iv ∈ bool[120]  — salt (120 bits = 15 bytes)
//   output ∈ bool[csp]
//
// Uses Enc + orthomorphism σ. For all current parameter sets (csp > blocklen)
// the multi-block path is taken.

void tccr_hash(const uint8_t* x, const uint8_t* s, const uint8_t* iv, uint8_t* out,
               unsigned int csp);

void tccr_hash_x0_x1(const uint8_t* x, const uint8_t* s, const uint8_t* iv, uint8_t* out0,
                     uint8_t* out1, unsigned int csp);

#endif
