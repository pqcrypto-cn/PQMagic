#ifndef test_utils_h__
#define test_utils_h__

#include "../include/fp.h"
#include "../include/fp2.h"
#include <stdlib.h>
#include <bench.h>

#define PASSED 0
#define FAILED 1

// Random elements of fp and fp2, oly suitable for testing
void fp_random_test(fp_t *a);
void fp2_random_test(fp2_t *a);

// Comparison of u64 for qsort
int cmp_u64(const void *v1, const void *v2);

#endif
