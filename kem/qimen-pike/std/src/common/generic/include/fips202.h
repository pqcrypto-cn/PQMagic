// SPDX-License-Identifier: Apache-2.0

#ifndef FIPS202_H
#define FIPS202_H

#include <stddef.h>
#include <stdint.h>
#define SHAKE256_RATE 136

// Context for non-incremental API
typedef struct {
    uint64_t ctx[25];
} shake256ctx;

/* Initialize the state and absorb the provided input.
 *
 * This function does not support being called multiple times
 * with the same state.
 */
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen);
/* Squeeze output out of the sponge.
 *
 * Supports being called multiple times
 */
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);
/* Free the context held by this XOF */
void shake256_ctx_release(shake256ctx *state);

int SHAKE128(unsigned char *output,
             size_t outputByteLen,
             const unsigned char *input,
             size_t inputByteLen);
int SHAKE256(unsigned char *output,
             size_t outputByteLen,
             const unsigned char *input,
             size_t inputByteLen);

#endif
