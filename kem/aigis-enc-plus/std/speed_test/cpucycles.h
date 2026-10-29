#ifndef CPUCYCLES_H
#define CPUCYCLES_H
#include <stdint.h>
uint64_t cpucycles(void);
uint64_t cpucycles_overhead(void);
double cpucycles_per_second(void);
#endif