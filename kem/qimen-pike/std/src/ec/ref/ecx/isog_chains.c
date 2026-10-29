#include "ec.h"
#include "isog.h"
#include <assert.h>

void ec_eval_odd_substep_rec(ec_point_t *A24,
                             unsigned int length_path,
                             unsigned int ii,
                             ec_point_t *ker,
                             ec_point_t *stack,
                             unsigned short length_stack,
                             ec_point_t *points,
                             unsigned short length)
{

    if (length_path == 0)
        return;
    if (length_path == 1)
    {
        ec_point_t B24;
        kps(ii, *ker, *A24);
        xisog(&B24, ii, *A24);
        ec_curve_t tmps;
        A24_to_AC(&tmps, &B24);
        for (int j = 0; j < length_stack; j++)
            xeval(&stack[j], ii, stack[j], *A24);
        for (int j = 0; j < length; j++)
            xeval(&points[j], ii, points[j], *A24);
        copy_point(A24, &B24);
        return;
    }

    long right = length_path / 1.5;
    long left = length_path - right;

    copy_point(&(stack[length_stack]), ker);

    for (int j = 0; j < left; j++)
        xMULv2(ker, ker, &(TORSION_ODD_PRIMES[ii]), p_plus_minus_bitlength[ii], A24);

    ec_eval_odd_substep_rec(A24, right, ii, ker, stack, length_stack + 1, points, length);

    copy_point(ker, &(stack[length_stack]));

    ec_eval_odd_substep_rec(A24, left, ii, ker, stack, length_stack, points, length);

    // ibz_finalize(&pow);
}

void ec_eval_odd_substep(ec_curve_t *image, ec_curve_t *domain, ec_point_t *ker, unsigned int ii, unsigned int power, ec_point_t *points, unsigned short length)
{
    ec_point_t A24;
    ec_point_t stack[500]; // need much smaller stack but okay...

    AC_to_A24(&A24, domain);

    ec_eval_odd_substep_rec(&A24, power, ii, ker, stack, 0, points, length);

    A24_to_AC(image, &A24);

    // TODO:
    // The curve does not have A24 normalised though
    // should we normalise it here, or do it later?
    // image->is_A24_computed_and_normalized = 0;
}

void ec_eval_odd(ec_curve_t *image, const ec_isog_odd_t *phi, ec_point_t *points, unsigned short length)
{
    ec_point_t ker_plus, ker_minus, P, K, A24, B24, eval_points[length + 2];
    int i, j, k;

    AC_to_A24(&A24, &phi->curve);
    copy_curve(image, &phi->curve);
    // Isogenies with kernel in E[p+1]
    copy_point(&ker_plus, &phi->ker_plus);
    copy_point(&ker_minus, &phi->ker_minus);
    for (i = 0; i < length; i++)
    {
        copy_point(&eval_points[i], &points[i]);
    }
    copy_point(&eval_points[length], &ker_plus);
    copy_point(&eval_points[length + 1], &ker_minus);
    for (i = 0; i < P_LEN; i++)
    {
        copy_point(&P, &ker_plus);
        for (j = i + 1; j < P_LEN; j++)
        {
            for (k = 0; k < phi->degree[j]; k++)
                xMULv2(&P, &P, &(TORSION_ODD_PRIMES[j]), p_plus_minus_bitlength[j], &A24);
        }
        ec_eval_odd_substep(image, image, &P, i, phi->degree[i], eval_points, length + 2);
        copy_point(&ker_plus, &eval_points[length]);
        AC_to_A24(&A24, image);
    }
    copy_point(&ker_minus, &eval_points[length + 1]);
    copy_point(&eval_points[length], &ker_minus);
    // Isogenies with kernel in E[p-1]
    for (i = P_LEN; i < P_LEN + M_LEN; i++)
    {
        copy_point(&P, &ker_minus);
        for (j = i + 1; j < P_LEN + M_LEN; j++)
        {
            for (k = 0; k < phi->degree[j]; k++)
                xMULv2(&P, &P, &(TORSION_ODD_PRIMES[j]), p_plus_minus_bitlength[j], &A24);
        }
        ec_eval_odd_substep(image, image, &P, i, phi->degree[i], eval_points, length + 1);
        copy_point(&ker_minus, &eval_points[length]);
        AC_to_A24(&A24, image);
    }
    for (i = 0; i < length; i++)
    {
        copy_point(&points[i], &eval_points[i]);
    }
    A24_to_AC(image, &A24);

    // TODO:
    // The curve does not have A24 normalised though
    // should we normalise it here, or do it later?
    image->is_A24_computed_and_normalized = 0;
}

void ec_isomorphism(ec_isom_t *isom, const ec_curve_t *from, const ec_curve_t *to)
{
    fp2_t t0, t1, t2, t3, t4;
    fp2_mul(&t0, &from->A, &to->C);
    fp2_sqr(&t0, &t0); // fromA^2toC^2
    fp2_mul(&t1, &to->A, &from->C);
    fp2_sqr(&t1, &t1); // toA^2fromC^2
    fp2_mul(&t2, &to->C, &from->C);
    fp2_sqr(&t2, &t2); // toC^2fromC^2
    fp2_add(&t3, &t2, &t2);
    fp2_add(&t2, &t3, &t2); // 3toC^2fromC^2
    fp2_sub(&t3, &t2, &t0); // 3toC^2fromC^2-fromA^2toC^2
    fp2_sub(&t4, &t2, &t1); // 3toC^2fromC^2-toA^2fromC^2
    fp2_inv(&t3);
    fp2_mul(&t4, &t4, &t3);
    fp2_sqrt(&t4); // lambda^2 constant for SW isomorphism
    fp2_sqr(&t3, &t4);
    fp2_mul(&t3, &t3, &t4); // lambda^6

    // Check sign of lambda^2, such that lambda^6 has the right sign
    fp2_sqr(&t0, &from->C);
    fp2_add(&t1, &t0, &t0);
    fp2_add(&t1, &t1, &t1);
    fp2_add(&t1, &t1, &t1);
    fp2_add(&t0, &t0, &t1); // 9fromC^2
    fp2_sqr(&t2, &from->A);
    fp2_add(&t2, &t2, &t2); // 2fromA^2
    fp2_sub(&t2, &t2, &t0);
    fp2_mul(&t2, &t2, &from->A); // -9fromC^2fromA+2fromA^3
    fp2_sqr(&t0, &to->C);
    fp2_mul(&t0, &t0, &to->C);
    fp2_mul(&t2, &t2, &t0); // toC^3* [-9fromC^2fromA+2fromA^3]
    fp2_mul(&t3, &t3, &t2); // lambda^6*(-9fromA+2fromA^3)*toC^3
    fp2_sqr(&t0, &to->C);
    fp2_add(&t1, &t0, &t0);
    fp2_add(&t1, &t1, &t1);
    fp2_add(&t1, &t1, &t1);
    fp2_add(&t0, &t0, &t1); // 9toC^2
    fp2_sqr(&t2, &to->A);
    fp2_add(&t2, &t2, &t2); // 2toA^2
    fp2_sub(&t2, &t2, &t0);
    fp2_mul(&t2, &t2, &to->A); // -9toC^2toA+2toA^3
    fp2_sqr(&t0, &from->C);
    fp2_mul(&t0, &t0, &from->C);
    fp2_mul(&t2, &t2, &t0); // fromC^3* [-9toC^2toA+2toA^3]
    if (!fp2_is_equal(&t2, &t3))
        fp2_neg(&t4, &t4);

    // Mont -> SW -> SW -> Mont
    fp2_set_one(&t0);
    fp2_add(&isom->D, &t0, &t0);
    fp2_add(&isom->D, &isom->D, &t0);
    fp2_mul(&isom->D, &isom->D, &from->C);
    fp2_mul(&isom->D, &isom->D, &to->C);
    fp2_mul(&isom->Nx, &isom->D, &t4);
    fp2_mul(&t4, &t4, &from->A);
    fp2_mul(&t4, &t4, &to->C);
    fp2_mul(&t0, &to->A, &from->C);
    fp2_sub(&isom->Nz, &t0, &t4);
}

void ec_iso_eval(ec_point_t *P, ec_isom_t *isom)
{
    fp2_t tmp;
    fp2_mul(&P->x, &P->x, &isom->Nx);
    fp2_mul(&tmp, &P->z, &isom->Nz);
    fp2_sub(&P->x, &P->x, &tmp);
    fp2_mul(&P->z, &P->z, &isom->D);
}
