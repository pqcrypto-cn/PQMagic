#include "isog.h"
#include "ec.h"
#include <assert.h>

// -------------------------------------------------------------------------
// -------------------------------------------------------------------------

// xISOG procedure, which is a hybrid between Montgomery and Twisted Edwards
// This tradition fomulae corresponds with the Twisted Edwards formulae but
// mapping the output into Montgomery form
void xisog_t(ec_point_t *B, uint64_t const i, ec_point_t const A)
{
    int j;
    int d = ((int)TORSION_ODD_PRIMES[i] - 1) / 2; // Here, l = 2d + 1

    fp2_t By, Bz, constant_d_edwards, tmp_a, tmp_d;

    fp2_copy(&By, &K[0].x);
    fp2_copy(&Bz, &K[0].z);

    for (j = 1; j < d; j++)
    {
        fp2_mul(&By, &By, &K[j].x);
        fp2_mul(&Bz, &Bz, &K[j].z);
    };

    // Mapping Montgomery curve coefficients into Twisted Edwards form
    fp2_sub(&constant_d_edwards, &A.x, &A.z);
    fp2_copy(&tmp_a, &A.x);
    fp2_copy(&tmp_d, &constant_d_edwards);

    // left-to-right method for computing a^l and d^l
    for (j = 1; j < (int)p_plus_minus_bitlength[i]; j++)
    {
        fp2_sqr(&tmp_a, &tmp_a);
        fp2_sqr(&tmp_d, &tmp_d);
        if ((((int)TORSION_ODD_PRIMES[i] >> ((int)p_plus_minus_bitlength[i] - j - 1)) & 1) != 0)
        {
            fp2_mul(&tmp_a, &tmp_a, &A.x);
            fp2_mul(&tmp_d, &tmp_d, &constant_d_edwards);
        };
    };

    // raising to 8-th power
    for (j = 0; j < 3; j++)
    {
        fp2_sqr(&By, &By);
        fp2_sqr(&Bz, &Bz);
    };

    // Mapping Twisted Edwards curve coefficients into Montgomery form
    fp2_mul(&(B->x), &tmp_a, &Bz);
    fp2_mul(&(B->z), &tmp_d, &By);
    fp2_sub(&(B->z), &(B->x), &(B->z));
}
