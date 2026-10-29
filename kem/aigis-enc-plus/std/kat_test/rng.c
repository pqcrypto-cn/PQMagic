#include "drng.h"


extern DRNG_ctx drng_algorithm;


void randombytes(unsigned char *x, unsigned long long xlen) {
    get_random_number(&drng_algorithm, x, xlen * 8);

}