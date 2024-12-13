#ifndef _DILITHIUM_UTILS_H_
#define _DILITHIUM_UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../poly.h"
#include "../polyvec.h"
#include "../params.h"

void print_uchar(FILE *fp, uint8_t *data, size_t len);
void print_poly(FILE *fp, poly *p);
void print_polyvecl(FILE *fp, polyvecl *pvec);
void print_polyveck(FILE *fp, polyveck *pvec);
#endif