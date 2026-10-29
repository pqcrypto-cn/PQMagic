#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>

int16_t amodq(int16_t x);

int16_t montgomery_reduce(int32_t a);

int16_t barrett_reduce(int16_t a);

int16_t caddq(int16_t x);
int16_t caddq2(int16_t x);
#endif
