#include "isog.h"
#include "curve_extras.h"
#include <assert.h>

/* Cursed global constant */
ec_point_t K[83]; // Finite subsets of the kernel

// -----------------------------------------------------------
// -----------------------------------------------------------
// Traditional Kernel Point computation (KPs)

// Differential doubling in Twisted Edwards model
void ydbl(ec_point_t *Q, ec_point_t *const P, ec_point_t const *A)
{
    fp2_t t_0, t_1, X, Z;

    fp2_sqr(&t_0, &(P->x));
    fp2_sqr(&t_1, &(P->z));
    fp2_mul(&Z, &(A->z), &t_0);
    fp2_mul(&X, &Z, &t_1);
    fp2_sub(&t_1, &t_1, &t_0);
    fp2_mul(&t_0, &(A->x), &t_1);
    fp2_add(&Z, &Z, &t_0);
    fp2_mul(&Z, &Z, &t_1);

    fp2_sub(&(Q->x), &X, &Z);
    fp2_add(&(Q->z), &X, &Z);
}

// Differential addition in Twisted Edwards model
void yadd(ec_point_t *R, ec_point_t *const P, ec_point_t *const Q, ec_point_t *const PQ)
{
    fp2_t a, b, c, d, X, Z;

    fp2_mul(&a, &(P->z), &(Q->x));
    fp2_mul(&b, &(P->x), &(Q->z));
    fp2_add(&c, &a, &b);
    fp2_sub(&d, &a, &b);
    fp2_sqr(&c, &c);
    fp2_sqr(&d, &d);

    fp2_add(&a, &(PQ->z), &(PQ->x));
    fp2_sub(&b, &(PQ->z), &(PQ->x));
    fp2_mul(&X, &b, &c);
    fp2_mul(&Z, &a, &d);

    fp2_sub(&(R->x), &X, &Z);
    fp2_add(&(R->z), &X, &Z);
}

// tvelu formulae
void kps_t(uint64_t const i, ec_point_t const P, ec_point_t const A)
{
    int j;
    int d = ((int)TORSION_ODD_PRIMES[i] - 1) / 2;

    // Mapping the input point x(P), which belongs to a
    // Montogmery curve model, into its Twisted Edwards
    // representation y(P)
    fp2_sub(&K[0].x, &P.x, &P.z);
    fp2_add(&K[0].z, &P.x, &P.z);
    ydbl(&K[1], &K[0], &A); // y([2]P)

    for (j = 2; j < d; j++)
        yadd(&K[j], &K[j - 1], &K[0], &K[j - 2]); // y([j+1]P)
}
