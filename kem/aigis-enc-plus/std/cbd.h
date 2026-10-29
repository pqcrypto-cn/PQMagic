#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "poly.h"

void cbd_etas(poly  *r, const uint8_t *buf);
void cbd_etae(poly  *r, const uint8_t *buf);
#endif
