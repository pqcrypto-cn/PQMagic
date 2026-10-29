#include "isog.h"
#include "ec.h"
#include <assert.h>

// -----------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------

// Isogeny evaluation on Montgomery curves
// Recall: K has been computed in Twisted Edwards model and none extra additions are required.

// CrissCross procedure as described in Hisil and Costello paper
void
CrissCross(fp2_t *r0,
           fp2_t *r1,
           fp2_t const alpha,
           fp2_t const beta,
           fp2_t const gamma,
           fp2_t const delta)
{
    fp2_t t_1, t_2;

    fp2_mul(&t_1, &alpha, &delta);
    fp2_mul(&t_2, &beta, &gamma);
    fp2_add(&*r0, &t_1, &t_2);
    fp2_sub(&*r1, &t_1, &t_2);
}

void
xeval_t(ec_point_t *Q, uint64_t const i, ec_point_t const P)
{
    int j;
    int d = ((int)TORSION_ODD_PRIMES[i] - 1) / 2; // Here, l = 2d + 1

    fp2_t R0, R1, S0, S1, T0, T1;
    fp2_add(&S0, &P.x, &P.z);
    fp2_sub(&S1, &P.x, &P.z);

    CrissCross(&R0, &R1, K[0].z, K[0].x, S0, S1);
    for (j = 1; j < d; j++) {
        CrissCross(&T0, &T1, K[j].z, K[j].x, S0, S1);
        fp2_mul(&R0, &T0, &R0);
        fp2_mul(&R1, &T1, &R1);
    };

    fp2_sqr(&R0, &R0);
    fp2_sqr(&R1, &R1);

    fp2_mul(&(Q->x), &P.x, &R0);
    fp2_mul(&(Q->z), &P.z, &R1);
}
