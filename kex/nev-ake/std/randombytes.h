#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#define _GNU_SOURCE

#include <unistd.h>

void randombytes(unsigned char *x, unsigned long long xlen);

#endif
