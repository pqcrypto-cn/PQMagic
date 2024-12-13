#include <string.h>
#include "genmatrix.h"
#include "polyvec.h"
#include "hashkdf.h"


/*
Generate entry a_{i,j} of matrix A as Parse(SHAKE128(seed|i|j))
*/
void genmatrix(polyvec *a, const uint8_t *seed, int transposed)
{
	int i, j;
	uint8_t extseed[SEED_BYTES + 2];

	for (i = 0; i < SEED_BYTES; i++)
		extseed[i] = seed[i];

	for (i = 0; i < PARAM_K; i++)
		for (j = 0; j < PARAM_K; j++)
		{
			if (transposed)
			{
				extseed[SEED_BYTES] = j;
				extseed[SEED_BYTES + 1] = i;
			}
			else
			{
				extseed[SEED_BYTES] = i;
				extseed[SEED_BYTES + 1] = j;
			}
			poly_uniform_seed(&a[i].vec[j], extseed, SEED_BYTES + 2);
		}
}
