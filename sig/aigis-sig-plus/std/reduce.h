#ifndef REDUCE_H
#define REDUCE_H

#include <stdint.h>
#include "params.h"

int32_t montgomery_reduce(int64_t a);
int32_t barrat_reduce(int32_t a);
int32_t general_reduce(int32_t a);
int32_t amodq(int32_t a);
int32_t cmodq(int32_t a);
#endif
