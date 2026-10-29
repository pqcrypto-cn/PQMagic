#ifndef NEV_REF_PACK_H
#define NEV_REF_PACK_H

#include "poly.h"

void poly_tobytes(uint8_t *r, const poly *a);
void poly_frombytes(poly *r, const uint8_t *a);
void poly_tomsg(uint8_t msg[SEED_BYTES], const poly *r);
void poly_compress(uint8_t *c, const poly* x);
void poly_decompress(poly* x, const uint8_t *c);

#endif //NEV_REF_PACK_H
