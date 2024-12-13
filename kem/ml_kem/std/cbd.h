#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define cbd_eta1 ML_KEM_NAMESPACE(_cbd_eta1)
void cbd_eta1(poly *r, const uint8_t buf[ML_KEM_ETA1*ML_KEM_N/4]);

#define cbd_eta2 ML_KEM_NAMESPACE(_cbd_eta2)
void cbd_eta2(poly *r, const uint8_t buf[ML_KEM_ETA2*ML_KEM_N/4]);

#endif
