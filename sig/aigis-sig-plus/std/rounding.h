#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>

int32_t power2round(const int32_t a, int32_t *a0);
int32_t decompose(int32_t a, int32_t *a0);
unsigned int make_hint(const int32_t a, const int32_t b); 
int32_t use_hint(const int32_t a, const int32_t hint);

#endif
