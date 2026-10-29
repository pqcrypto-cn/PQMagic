#ifndef PACK_H
#define PACK_H

#include "params.h"

#include "polyvec.h"
#include <stdint.h>

void pack_pk(uint8_t *r, const poly *pk, const uint8_t *seed);
void unpack_pk(poly *pk, uint8_t *seed, const uint8_t *packedpk);

void pack_ciphertext(uint8_t *r, const poly *b, const poly *v);
void unpack_ciphertext(poly *b, poly *v, const uint8_t *c);

void pack_sk(uint8_t *r, const poly *sk);
void unpack_sk(poly *sk, const uint8_t *packedsk);

#endif
