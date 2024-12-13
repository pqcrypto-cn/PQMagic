#ifndef KYBER_GENMATRIX
#define KYBER_GENMATRIX

#include "polyvec.h"
#include "params.h"

#define genmatrix AIGIS_ENC_NAMESPACE(genmatrix)
void genmatrix(polyvec *a, const uint8_t *seed, int transposed);

#endif
