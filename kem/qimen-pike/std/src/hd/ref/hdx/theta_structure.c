#include "theta_structure.h"
#include <assert.h>

/**
 * @brief Perform the theta structure precomputation
 *
 * @param A Output: the theta_structure
 *
 * if A.null_point = (x,y,z,t)
 * if (xx,yy,zz,tt) = to_squared_theta(A.null_point)
 * Computes y0,z0,t0,Y0,Z0,T0 = x/y,x/z,x/t,XX/YY,XX/ZZ,XX/TT
 *
 */
void
theta_precomputation(theta_structure_t *A)
{

    if (!A->precomputation) {
        theta_point_t temp;
        to_squared_theta(&temp, &A->null_point);
        fp2_t t1, t2;
        fp2_mul(&t1, &temp.x, &temp.y);
        fp2_mul(&t2, &temp.z, &temp.t);
        fp2_mul(&A->XYZ0, &t1, &temp.z);
        fp2_mul(&A->XYT0, &t1, &temp.t);
        fp2_mul(&A->YZT0, &t2, &temp.y);
        fp2_mul(&A->XZT0, &t2, &temp.x);

        fp2_mul(&t1, &A->null_point.x, &A->null_point.y);
        fp2_mul(&t2, &A->null_point.z, &A->null_point.t);
        fp2_mul(&A->xyz0, &t1, &A->null_point.z);
        fp2_mul(&A->xyt0, &t1, &A->null_point.t);
        fp2_mul(&A->yzt0, &t2, &A->null_point.y);
        fp2_mul(&A->xzt0, &t2, &A->null_point.x);

        A->precomputation = 1;
    }
}

/**
 * @brief Compute the double of the theta point in on the theta struc A
 *
 * @param out Output: the theta_point
 * @param A a theta structure
 * @param in a theta point in the theta structure A
 * in = (x,y,z,t)
 * out = [2] (x,y,z,t)
 * /!\ assumes that no coordinates is zero
 *
 */
void
double_point(theta_point_t *out, theta_structure_t *A, const theta_point_t *in)
{

    to_squared_theta(out, in);
    fp2_sqr(&out->x, &out->x);
    fp2_sqr(&out->y, &out->y);
    fp2_sqr(&out->z, &out->z);
    fp2_sqr(&out->t, &out->t);
    if (!A->precomputation) {
        theta_precomputation(A);
    }

    fp2_mul(&out->x, &out->x, &A->YZT0);
    fp2_mul(&out->y, &out->y, &A->XZT0);
    fp2_mul(&out->z, &out->z, &A->XYT0);
    fp2_mul(&out->t, &out->t, &A->XYZ0);

    hadamard(out, out);
    fp2_mul(&out->x, &out->x, &A->yzt0);
    fp2_mul(&out->y, &out->y, &A->xzt0);
    fp2_mul(&out->z, &out->z, &A->xyt0);
    fp2_mul(&out->t, &out->t, &A->xyz0);
}

/**
 * @brief Compute the iterated double of the theta point in on the theta struc A
 *
 * @param out Output: the theta_point
 * @param A a theta structure
 * @param in a theta point in the theta structure A
 * @param exp the exponent
 * in = (x,y,z,t)
 * out = [2^2] (x,y,z,t)
 * /!\ assumes that no coordinates is zero and that the precomputation of A has been done
 *
 */
void
double_iter(theta_point_t *out, theta_structure_t *A, const theta_point_t *in, int exp)
{
    if (exp == 0) {
        fp2_copy(&out->x, &in->x);
        fp2_copy(&out->y, &in->y);
        fp2_copy(&out->z, &in->z);
        fp2_copy(&out->t, &in->t);
    } else {
        double_point(out, A, in);
        for (int i = 1; i < exp; i++) {
            double_point(out, A, out);
        }
    }
}
