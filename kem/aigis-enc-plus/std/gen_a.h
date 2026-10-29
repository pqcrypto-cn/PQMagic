#ifndef KYBER_GENMATRIX
#define KYBER_GENMATRIX

#include "polyvec.h"

void gen_a(poly *a, const uint8_t *seed);

int rej_uniform15(uint16_t *r,const uint8_t *buf, size_t buflen);
int rej_uniform7(uint16_t *r,const uint8_t *buf, size_t buflen);
int rej_uniform3(uint16_t *r,const uint8_t *buf, size_t buflen);
#endif
