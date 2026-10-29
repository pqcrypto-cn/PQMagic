#include "curve_extras.h"
#include "ec.h"
#include "fp2.h"
#include "gf_constants.h"

int ec_is_on_curve(const ec_curve_t *curve, const ec_point_t *P)
{

    fp2_t t0, t1, t2;

    // Check if xz*(C^2x^2+zACx+z^2C^2) is a square
    fp2_mul(&t0, &curve->C, &P->x);
    fp2_mul(&t1, &t0, &P->z);
    fp2_mul(&t1, &t1, &curve->A);
    fp2_mul(&t2, &curve->C, &P->z);
    fp2_sqr(&t0, &t0);
    fp2_sqr(&t2, &t2);
    fp2_add(&t0, &t0, &t1);
    fp2_add(&t0, &t0, &t2);
    fp2_mul(&t0, &t0, &P->x);
    fp2_mul(&t0, &t0, &P->z);
    return fp2_is_square(&t0);
}

void difference_point(ec_point_t *PQ, const ec_point_t *P, const ec_point_t *Q, const ec_curve_t *curve)
{
    // Given P,Q in affine x-only, computes a deterministic choice for (P-Q)
    // The points must be normalized to z=1 and the curve to C=1

    fp2_t t0, t1, t2, t3;

    fp2_sub(&PQ->z, &P->x, &Q->x); // P - Q
    fp2_mul(&t2, &P->x, &Q->x);    // P*Q
    fp2_set_one(&t1);
    fp2_sub(&t3, &t2, &t1);       // P*Q-1
    fp2_mul(&t0, &PQ->z, &t3);    // (P-Q)*(P*Q-1)
    fp2_sqr(&PQ->z, &PQ->z);      // (P-Q)^2
    fp2_sqr(&t0, &t0);            // (P-Q)^2*(P*Q-1)^2
    fp2_add(&t1, &t2, &t1);       // P*Q+1
    fp2_add(&t3, &P->x, &Q->x);   // P+Q
    fp2_mul(&t1, &t1, &t3);       // (P+Q)*(P*Q+1)
    fp2_mul(&t2, &t2, &curve->A); // A*P*Q
    fp2_add(&t2, &t2, &t2);       // 2*A*P*Q
    fp2_add(&t1, &t1, &t2);       // (P+Q)*(P*Q+1) + 2*A*P*Q
    fp2_sqr(&t2, &t1);            // ((P+Q)*(P*Q+1) + 2*A*P*Q)^2
    fp2_sub(&t0, &t2, &t0);       // ((P+Q)*(P*Q+1) + 2*A*P*Q)^2 - (P-Q)^2*(P*Q-1)^2
    fp2_sqrt(&t0);
    fp2_add(&PQ->x, &t0, &t1);
}

void ec_curve_to_basis_2_to_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Q2, P2;

    // normalize
    ec_curve_normalize_A24(curve);

    fp2_set_one(&x);

    int count = 0;

    // Find P
    while (1)
    {
        count++;
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
            continue;

        // Clear odd factors from the order
        xMULv2(&P, &P, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);
        // clear the power of two
        for (int i = 0; i < POWER_OF_2 - f; i++)
        {
            xDBL_A24_normalized(&P, &P, &curve->A24);
        }

        // Check if point has order 2^f
        copy_point(&P2, &P);
        for (int i = 0; i < f - 1; i++)
            xDBL_A24_normalized(&P2, &P2, &curve->A24);
        if (ec_is_zero(&P2))
            continue;
        else
            break;
    }

    hint[0] = count;

    count = 0;
    // Find Q
    while (1)
    {
        count++;
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
            continue;

        // Clear odd factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);
        // clear the power of two
        for (int i = 0; i < POWER_OF_2 - f; i++)
        {
            xDBL_A24_normalized(&Q, &Q, &curve->A24);
        }

        // Check if point has order 2^f
        copy_point(&Q2, &Q);
        for (int i = 0; i < f - 1; i++)
            xDBL_A24_normalized(&Q2, &Q2, &curve->A24);
        if (ec_is_zero(&Q2))
            continue;

        // Check if point is orthogonal to P
        if (is_point_equal(&P2, &Q2))
            continue;
        else
            break;
    }

    hint[1] = count;

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQ2->PmQ, &P, &Q, &E);
    copy_point(&PQ2->P, &P);
    copy_point(&PQ2->Q, &Q);
}

void ec_curve_to_basis_2_from_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q;

    // normalize
    ec_curve_normalize_A24(curve);

    fp2_set_one(&x);

    int count = 0;

    for (int i = 0; i < hint[0]; i++)
    {
        fp_add(&(x.im), &(x.re), &(x.im));
    }
    fp2_copy(&P.x, &x);
    fp2_set_one(&P.z);

    // getting the actual point
    // Clear odd factors from the order
    xMULv2(&P, &P, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);
    // clear the power of two
    for (int i = 0; i < POWER_OF_2 - f; i++)
    {
        xDBL_A24_normalized(&P, &P, &curve->A24);
    }
    // second point

    for (int i = 0; i < hint[1]; i++)
    {
        fp_add(&(x.im), &(x.re), &(x.im));
    }

    fp2_copy(&Q.x, &x);
    fp2_set_one(&Q.z);

    // Clear odd factors from the order
    xMULv2(&Q, &Q, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);
    // clear the power of two
    for (int i = 0; i < POWER_OF_2 - f; i++)
    {
        xDBL_A24_normalized(&Q, &Q, &curve->A24);
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQ2->PmQ, &P, &Q, &E);
    copy_point(&PQ2->P, &P);
    copy_point(&PQ2->Q, &Q);
}

void ec_curve_to_basis_2(ec_basis_t *PQ2, ec_curve_t *curve, int f)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Q2, P2;

    // normalize
    ec_curve_normalize_A24(curve);

    fp2_set_one(&x);

    // Find P
    while (1)
    {
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
            continue;

        // Clear odd factors from the order
        xMULv2(&P, &P, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);
        // clear the power of two
        for (int i = 0; i < POWER_OF_2 - f; i++)
        {
            xDBL_A24_normalized(&P, &P, &curve->A24);
        }

        // Check if point has order 2^f
        copy_point(&P2, &P);
        for (int i = 0; i < f - 1; i++)
            xDBL_A24_normalized(&P2, &P2, &curve->A24);
        if (ec_is_zero(&P2))
            continue;
        else
            break;
    }

    // Find Q
    while (1)
    {
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
            continue;

        // Clear odd factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);
        // clear the power of two
        for (int i = 0; i < POWER_OF_2 - f; i++)
        {
            xDBL_A24_normalized(&Q, &Q, &curve->A24);
        }

        // Check if point has order 2^f
        copy_point(&Q2, &Q);
        for (int i = 0; i < f - 1; i++)
            xDBL_A24_normalized(&Q2, &Q2, &curve->A24);
        if (ec_is_zero(&Q2))
            continue;

        // Check if point is orthogonal to P
        if (is_point_equal(&P2, &Q2))
            continue;
        else
            break;
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQ2->PmQ, &P, &Q, &E);
    copy_point(&PQ2->P, &P);
    copy_point(&PQ2->Q, &Q);
}

void ec_complete_basis_2(ec_basis_t *PQ2, const ec_curve_t *curve, const ec_point_t *P)
{

    fp2_t x, t0, t1, t2;
    ec_point_t Q, Q2, P2, A24;

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Point of order 2 generated by P
    copy_point(&P2, P);
    for (int i = 0; i < POWER_OF_2 - 1; i++)
        xDBL_A24(&P2, &P2, &A24);

    // Find Q
    fp2_set_one(&x);
    while (1)
    {
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
            continue;

        // Clear odd factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_2f, (int)P_COFACTOR_FOR_2F_BITLENGTH, &A24);

        // Check if point has order 2^f
        copy_point(&Q2, &Q);
        for (int i = 0; i < POWER_OF_2 - 1; i++)
            xDBL_A24(&Q2, &Q2, &A24);
        if (ec_is_zero(&Q2))
            continue;

        // Check if point is orthogonal to P
        if (is_point_equal(&P2, &Q2))
            continue;
        else
            break;
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    ec_point_t PP;
    fp2_mul(&t0, &P->z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&PP.x, &P->x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&PP.x, &PP.x, &Q.z);
    fp2_mul(&PP.x, &PP.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P->z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&PP.z);
    fp2_copy(&Q.z, &PP.z);
    fp2_copy(&E.C, &PP.z);

    // Compute P-Q
    difference_point(&PQ2->PmQ, &PP, &Q, &E);
    copy_point(&PQ2->P, &PP);
    copy_point(&PQ2->Q, &Q);
}
void ec_curve_to_basis_pls_to_hint(ec_basis_t *PQpls, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Ptest1, Ptest2, Qtest1, Qtest2, Qtest3, A24, A3;
    ec_point_t Ptest[size], Qtest[size];
    ec_point_t P_2tors, Q_2tors; // 显式声明 2-torsion 点，隔离存储
    ibz_t scalar, remainder;
    uint64_t k;
    int label = 1;
    
    hint[0] = 0;
    hint[1] = 0;

    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_init(&scalar);
    ibz_init(&remainder);

    dscalar[0] = 2 * PRIMES[0];
    for (int i = 1; i < size; i++)
    {
        dscalar[0] *= PRIMES[i];
    }

    ibz_copy_digits(&scalar, dscalar, NWORDS_ORDER);
    ibz_div(&scalar, &remainder, &TORSION_PLUS_ODD_2POWER, &scalar);
    ibz_to_digits(dscalar, &scalar);

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Curve coefficient in the form A3 = (A+2C:A-2C)
    fp2_sub(&A3.z, &A24.x, &A24.z);
    fp2_copy(&A3.x, &A24.x);

    fp2_set_one(&x);

    // Find P
    while (label)
    {
        label = 0;
        hint[0]++;
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        
        if (fp2_is_square(&t1) && fp2_is_square(&x))
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&P, &P, p_cofactor_for_PLUS, (int)P_COFACTOR_FOR_PLUS_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Ptest1, &P);
        xMUL(&Ptest1, &Ptest1, dscalar, TORSION_PLUS_ODD_2POWER->_mp_size, curve);

        // 核心优化：Ptest1 保持不变，仅更新 Ptest2
        for (int i = 0; i < size; i++)
        {
            k = 2;
            for (int j = 0; j < size; j++)
            {
                if (j != i) k *= PRIMES[j];
            }
            
            ec_mul(&Ptest2, curve, &k, 1, &Ptest1);
            if (ec_is_zero(&Ptest2))
            {
                label = 1;
                break;
            }
            copy_point(&Ptest[i], &Ptest2);
        }
        if (label) continue;

        // 验证 2-torsion
        k = 1;
        for (int j = 0; j < size; j++) k *= PRIMES[j];
        
        ec_mul(&P_2tors, curve, &k, 1, &Ptest1);
        if (ec_is_zero(&P_2tors))
        {
            label = 1;
            continue;
        }
    }

    label = 1;
    // Find Q
    while (label)
    {
        label = 0;
        hint[1]++;
        fp_add(&(x.im), &(x.re), &(x.im));
        
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        
        if (fp2_is_square(&t1))
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_PLUS, (int)P_COFACTOR_FOR_PLUS_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Qtest1, &Q);
        xMUL(&Qtest1, &Qtest1, dscalar, TORSION_PLUS_ODD_2POWER->_mp_size, curve);

        // 核心优化：Qtest1 保持不变，仅更新 Qtest2
        for (int i = 0; i < size; i++)
        {
            k = 2;
            for (int j = 0; j < size; j++)
            {
                if (j != i) k *= PRIMES[j];
            }
            
            ec_mul(&Qtest2, curve, &k, 1, &Qtest1);
            if (ec_is_zero(&Qtest2))
            {
                label = 1;
                break;
            }
            copy_point(&Qtest[i], &Qtest2);
        }
        if (label) continue;

        // 验证 2-torsion
        k = 1;
        for (int j = 0; j < size; j++) k *= PRIMES[j];
        
        ec_mul(&Q_2tors, curve, &k, 1, &Qtest1);

        if (ec_is_zero(&Q_2tors) || is_point_equal(&P_2tors, &Q_2tors))
        {
            label = 1;
            continue;
        }

        // Check if point is orthogonal to P
        for (int i = 0; i < size; i++)
        {
            if (is_point_equal(&Ptest[i], &Qtest[i]))
            {
                label = 1; break;
            }
            xDBL_A24(&Qtest1, &Qtest[i], &A24);
            if (is_point_equal(&Ptest[i], &Qtest1))
            {
                label = 1; break;
            }
            copy_point(&Qtest2, &Qtest1);
            copy_point(&Qtest3, &Qtest[i]);
            for (int j = 2; j < PRIMES[i] / 2; j++)
            {
                xADD(&Qtest1, &Qtest[i], &Qtest2, &Qtest3);
                if (is_point_equal(&Ptest[i], &Qtest1))
                {
                    label = 1; break;
                }
                copy_point(&Qtest3, &Qtest2);
                copy_point(&Qtest2, &Qtest1);
            }
            if (label) break;
        }
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQpls->PmQ, &P, &Q, &E);
    copy_point(&PQpls->P, &P);
    copy_point(&PQpls->Q, &Q);
    
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
}

void ec_curve_to_basis_pls_from_hint(ec_basis_t *PQpls, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Ptest1, Ptest2, Ptest3, Qtest1, Qtest2, Qtest3, A24, A3;
    ec_point_t Ptest[size], Qtest[size];
    ibz_t scalar, tmp, remainder;
    uint64_t k = {0};
    int label = 1;

    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_init(&scalar);
    ibz_init(&tmp);
    ibz_init(&remainder);
    dscalar[0] = PRIMES[0];
    for (int i = 1; i < size; i++)
    {
        dscalar[0] = PRIMES[i] * dscalar[0];
    }
    dscalar[0] = 2 * dscalar[0];
    ibz_copy_digits(&scalar, dscalar, NWORDS_ORDER);
    ibz_div(&scalar, &remainder, &TORSION_PLUS_ODD_2POWER, &scalar);
    ibz_to_digits(dscalar, &scalar);

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Curve coefficient in the form A3 = (A+2C:A-2C)
    fp2_sub(&A3.z, &A24.x, &A24.z);
    fp2_copy(&A3.x, &A24.x);

    fp2_set_one(&x);

    // Find P
    while (label)
    {
        label = 0;
        for (int i = 0; i < hint[0]; i++)
        {
            fp_add(&(x.im), &(x.re), &(x.im));
        }
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) && fp2_is_square(&x))
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&P, &P, p_cofactor_for_PLUS, (int)P_COFACTOR_FOR_PLUS_BITLENGTH, &A24);
    }

    label = 1;
    // Find Q
    while (label)
    {
        label = 0;
        for (int i = 0; i < hint[1]; i++)
        {
            fp_add(&(x.im), &(x.re), &(x.im));
        }
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_PLUS, (int)P_COFACTOR_FOR_PLUS_BITLENGTH, &A24);
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQpls->PmQ, &P, &Q, &E);
    copy_point(&PQpls->P, &P);
    copy_point(&PQpls->Q, &Q);
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
}

void ec_curve_to_basis_pls(ec_basis_t *PQpls, const ec_curve_t *curve, const uint64_t *PRIMES, const int size)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Ptest1, Ptest2, Ptest3, Qtest1, Qtest2, Qtest3, A24, A3;
    ec_point_t Ptest[size], Qtest[size];
    ibz_t scalar, tmp, remainder;
    uint64_t k = {0};
    int label = 1;

    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_init(&scalar);
    ibz_init(&tmp);
    ibz_init(&remainder);
    dscalar[0] = PRIMES[0];
    for (int i = 1; i < size; i++)
    {
        dscalar[0] = PRIMES[i] * dscalar[0];
    }
    dscalar[0] = 2 * dscalar[0];
    ibz_copy_digits(&scalar, dscalar, NWORDS_ORDER);
    ibz_div(&scalar, &remainder, &TORSION_PLUS_ODD_2POWER, &scalar);
    ibz_to_digits(dscalar, &scalar);

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Curve coefficient in the form A3 = (A+2C:A-2C)
    fp2_sub(&A3.z, &A24.x, &A24.z);
    fp2_copy(&A3.x, &A24.x);

    fp2_set_one(&x);

    // Find P
    while (label)
    {
        label = 0;
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) && fp2_is_square(&x))
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&P, &P, p_cofactor_for_PLUS, (int)P_COFACTOR_FOR_PLUS_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Ptest1, &P);
        xMUL(&Ptest1, &Ptest1, dscalar, TORSION_PLUS_ODD_2POWER->_mp_size, curve);
        copy_point(&Ptest3, &Ptest1);
        for (int i = 0; i < size - 1; i++)
        {
            k = 2;
            copy_point(&Ptest2, &Ptest1);
            for (int j = i; j < size - 1; j++)
            {
                k = k * PRIMES[j];
            }
            ec_mul(&Ptest2, curve, &k, 1, &Ptest2);
            if (ec_is_zero(&Ptest2))
            {
                label = 1;
                continue;
            }
            copy_point(&Ptest[i + 1], &Ptest2);
            ec_mul(&Ptest1, curve, &PRIMES[i], 1, &Ptest1);
        }
        k = 2;
        for (int j = 1; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Ptest2, curve, &k, 1, &Ptest3);
        if (ec_is_zero(&Ptest2))
        {
            label = 1;
            continue;
        }
        copy_point(&Ptest[0], &Ptest2);
        k = 1;
        for (int j = 0; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Ptest2, curve, &k, 1, &Ptest3);
    }

    label = 1;
    // Find Q
    while (label)
    {
        label = 0;
        fp_add(&(x.im), &(x.re), &(x.im));
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1))
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_PLUS, (int)P_COFACTOR_FOR_PLUS_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Qtest1, &Q);
        xMUL(&Qtest1, &Qtest1, dscalar, TORSION_PLUS_ODD_2POWER->_mp_size, curve);
        copy_point(&Qtest3, &Qtest1);
        for (int i = 0; i < size - 1; i++)
        {
            k = 2;
            copy_point(&Qtest2, &Qtest1);
            for (int j = i; j < size - 1; j++)
            {
                k = k * PRIMES[j];
            }
            ec_mul(&Qtest2, curve, &k, 1, &Qtest2);
            if (ec_is_zero(&Qtest2))
            {
                label = 1;
                continue;
            }
            copy_point(&Qtest[i + 1], &Qtest2);
            ec_mul(&Qtest1, curve, &PRIMES[i], 1, &Qtest1);
        }
        k = 2;
        for (int j = 1; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Qtest2, curve, &k, 1, &Qtest3);
        if (ec_is_zero(&Qtest2))
        {
            label = 1;
            continue;
        }
        copy_point(&Qtest[0], &Qtest2);
        k = 1;
        for (int j = 0; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Qtest2, curve, &k, 1, &Qtest3);
        if (ec_is_zero(&Qtest2))
        {
            label = 1;
            continue;
        }

        // Check if point is orthogonal to P
        if (is_point_equal(&Ptest2, &Qtest2))
        {
            label = 1;
            continue;
        }
        for (int i = 0; i < size; i++)
        {
            if (is_point_equal(&Ptest[i], &Qtest[i]))
            {
                label = 1;
                continue;
            }
            xDBL_A24(&Qtest1, &Qtest[i], &A24);
            if (is_point_equal(&Ptest[i], &Qtest1))
            {
                label = 1;
                continue;
            }
            copy_point(&Qtest2, &Qtest1);
            copy_point(&Qtest3, &Qtest[i]);
            for (int j = 2; j < PRIMES[i] / 2; j++)
            {
                xADD(&Qtest1, &Qtest[i], &Qtest2, &Qtest3);
                if (is_point_equal(&Ptest[i], &Qtest1))
                {
                    label = 1;
                    continue;
                }
                copy_point(&Qtest3, &Qtest2);
                copy_point(&Qtest2, &Qtest1);
            }
        }
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQpls->PmQ, &P, &Q, &E);
    copy_point(&PQpls->P, &P);
    copy_point(&PQpls->Q, &Q);
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
}

void ec_curve_to_basis_Tmin_to_hint(ec_basis_t *PQTmin, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Ptest1, Ptest2, Ptest3, Qtest1, Qtest2, Qtest3, A24, A3;
    ec_point_t Ptest[size], Qtest[size];
    ibz_t scalar, tmp, remainder;
    uint64_t k = {0};
    int label = 1;
    hint[0] = 0;
    hint[1] = 0;

    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_init(&scalar);
    ibz_init(&tmp);
    ibz_init(&remainder);
    dscalar[0] = PRIMES[0];
    for (int i = 1; i < size; i++)
    {
        dscalar[0] = PRIMES[i] * dscalar[0];
    }
    ibz_copy_digits(&scalar, dscalar, NWORDS_ORDER);
    ibz_div(&scalar, &remainder, &TORSION_ODD_MINUS, &scalar);
    ibz_to_digits(dscalar, &scalar);

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Curve coefficient in the form A3 = (A+2C:A-2C)
    fp2_sub(&A3.z, &A24.x, &A24.z);
    fp2_copy(&A3.x, &A24.x);

    fp2_set_one(&x);

    // Find P
    while (label)
    {
        label = 0;
        hint[0]++;
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) == false)
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&P, &P, p_cofactor_for_Tmin, (int)P_COFACTOR_FOR_TMIN_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Ptest1, &P);
        xMUL(&Ptest1, &Ptest1, dscalar, TORSION_ODD_MINUS->_mp_size, curve);
        copy_point(&Ptest3, &Ptest1);
        for (int i = 0; i < size - 1; i++)
        {
            k = 1;
            copy_point(&Ptest2, &Ptest1);
            for (int j = i; j < size - 1; j++)
            {
                k = k * PRIMES[j];
            }
            ec_mul(&Ptest2, curve, &k, 1, &Ptest2);
            if (ec_is_zero(&Ptest2))
            {
                label = 1;
                continue;
            }
            copy_point(&Ptest[i + 1], &Ptest2);
            ec_mul(&Ptest1, curve, &PRIMES[i], 1, &Ptest1);
        }
        k = 1;
        for (int j = 1; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Ptest2, curve, &k, 1, &Ptest3);
        if (ec_is_zero(&Ptest2))
        {
            label = 1;
            continue;
        }
        copy_point(&Ptest[0], &Ptest2);
    }

    label = 1;
    // Find Q
    while (label)
    {
        label = 0;
        hint[1]++;
        fp_add(&(x.im), &(x.re), &(x.im));
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) == false)
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_Tmin, (int)P_COFACTOR_FOR_TMIN_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Qtest1, &Q);
        xMUL(&Qtest1, &Qtest1, dscalar, TORSION_ODD_MINUS->_mp_size, curve);
        copy_point(&Qtest3, &Qtest1);
        for (int i = 0; i < size - 1; i++)
        {
            k = 1;
            copy_point(&Qtest2, &Qtest1);
            for (int j = i; j < size - 1; j++)
            {
                k = k * PRIMES[j];
            }
            ec_mul(&Qtest2, curve, &k, 1, &Qtest2);
            if (ec_is_zero(&Qtest2))
            {
                label = 1;
                continue;
            }
            copy_point(&Qtest[i + 1], &Qtest2);
            ec_mul(&Qtest1, curve, &PRIMES[i], 1, &Qtest1);
        }
        k = 1;
        for (int j = 1; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Qtest2, curve, &k, 1, &Qtest3);
        if (ec_is_zero(&Qtest2))
        {
            label = 1;
            continue;
        }
        copy_point(&Qtest[0], &Qtest2);

        // Check if point is orthogonal to P
        for (int i = 0; i < size; i++)
        {
            if (is_point_equal(&Ptest[i], &Qtest[i]))
            {
                label = 1;
                continue;
            }
            xDBL_A24(&Qtest1, &Qtest[i], &A24);
            if (is_point_equal(&Ptest[i], &Qtest1))
            {
                label = 1;
                continue;
            }
            copy_point(&Qtest2, &Qtest1);
            copy_point(&Qtest3, &Qtest[i]);
            for (int j = 2; j < PRIMES[i] / 2; j++)
            {
                xADD(&Qtest1, &Qtest[i], &Qtest2, &Qtest3);
                if (is_point_equal(&Ptest[i], &Qtest1))
                {
                    label = 1;
                    continue;
                }
                copy_point(&Qtest3, &Qtest2);
                copy_point(&Qtest2, &Qtest1);
            }
        }
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQTmin->PmQ, &P, &Q, &E);
    copy_point(&PQTmin->P, &P);
    copy_point(&PQTmin->Q, &Q);
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
}

void ec_curve_to_basis_Tmin_from_hint(ec_basis_t *PQTmin, const ec_curve_t *curve, const uint64_t *PRIMES, const int size, int *hint)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Ptest1, Ptest2, Ptest3, Qtest1, Qtest2, Qtest3, A24, A3;
    ec_point_t Ptest[size], Qtest[size];
    ibz_t scalar, tmp, remainder;
    uint64_t k = {0};
    int label = 1;

    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_init(&scalar);
    ibz_init(&tmp);
    ibz_init(&remainder);
    dscalar[0] = PRIMES[0];
    for (int i = 1; i < size; i++)
    {
        dscalar[0] = PRIMES[i] * dscalar[0];
    }
    ibz_copy_digits(&scalar, dscalar, NWORDS_ORDER);
    ibz_div(&scalar, &remainder, &TORSION_ODD_MINUS, &scalar);
    ibz_to_digits(dscalar, &scalar);

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Curve coefficient in the form A3 = (A+2C:A-2C)
    fp2_sub(&A3.z, &A24.x, &A24.z);
    fp2_copy(&A3.x, &A24.x);

    fp2_set_one(&x);

    // Find P
    while (label)
    {
        label = 0;
        for (int i = 0; i < hint[0]; i++)
        {
            fp_add(&(x.im), &(x.re), &(x.im));
        }
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) == false)
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&P, &P, p_cofactor_for_Tmin, (int)P_COFACTOR_FOR_TMIN_BITLENGTH, &A24);
    }

    label = 1;
    // Find Q
    while (label)
    {
        label = 0;
        for (int i = 0; i < hint[1]; i++)
        {
            fp_add(&(x.im), &(x.re), &(x.im));
        }
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) == false)
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_Tmin, (int)P_COFACTOR_FOR_TMIN_BITLENGTH, &A24);
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQTmin->PmQ, &P, &Q, &E);
    copy_point(&PQTmin->P, &P);
    copy_point(&PQTmin->Q, &Q);
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
}

void ec_curve_to_basis_Tmin(ec_basis_t *PQTmin, const ec_curve_t *curve, const uint64_t *PRIMES, const int size)
{
    fp2_t x, t0, t1, t2;
    ec_point_t P, Q, Ptest1, Ptest2, Ptest3, Qtest1, Qtest2, Qtest3, A24, A3;
    ec_point_t Ptest[size], Qtest[size];
    ibz_t scalar, tmp, remainder;
    uint64_t k = {0};
    int label = 1;

    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_init(&scalar);
    ibz_init(&tmp);
    ibz_init(&remainder);
    dscalar[0] = PRIMES[0];
    for (int i = 1; i < size; i++)
    {
        dscalar[0] = PRIMES[i] * dscalar[0];
    }
    ibz_copy_digits(&scalar, dscalar, NWORDS_ORDER);
    ibz_div(&scalar, &remainder, &TORSION_ODD_MINUS, &scalar);
    ibz_to_digits(dscalar, &scalar);

    // Curve coefficient in the form A24 = (A+2C:4C)
    fp2_add(&A24.z, &curve->C, &curve->C);
    fp2_add(&A24.x, &curve->A, &A24.z);
    fp2_add(&A24.z, &A24.z, &A24.z);

    // Curve coefficient in the form A3 = (A+2C:A-2C)
    fp2_sub(&A3.z, &A24.x, &A24.z);
    fp2_copy(&A3.x, &A24.x);

    fp2_set_one(&x);

    // Find P
    while (label)
    {
        label = 0;
        fp_add(&(x.im), &(x.re), &(x.im));

        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) == false)
        {
            fp2_copy(&P.x, &x);
            fp2_set_one(&P.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&P, &P, p_cofactor_for_Tmin, (int)P_COFACTOR_FOR_TMIN_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Ptest1, &P);
        xMUL(&Ptest1, &Ptest1, dscalar, TORSION_ODD_MINUS->_mp_size, curve);
        copy_point(&Ptest3, &Ptest1);
        for (int i = 0; i < size - 1; i++)
        {
            k = 1;
            copy_point(&Ptest2, &Ptest1);
            for (int j = i; j < size - 1; j++)
            {
                k = k * PRIMES[j];
            }
            ec_mul(&Ptest2, curve, &k, 1, &Ptest2);
            if (ec_is_zero(&Ptest2))
            {
                label = 1;
                continue;
            }
            copy_point(&Ptest[i + 1], &Ptest2);
            ec_mul(&Ptest1, curve, &PRIMES[i], 1, &Ptest1);
        }
        k = 1;
        for (int j = 1; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Ptest2, curve, &k, 1, &Ptest3);
        if (ec_is_zero(&Ptest2))
        {
            label = 1;
            continue;
        }
        copy_point(&Ptest[0], &Ptest2);
    }

    label = 1;
    // Find Q
    while (label)
    {
        label = 0;
        fp_add(&(x.im), &(x.re), &(x.im));
        // Check if point is rational
        fp2_sqr(&t0, &curve->C);
        fp2_mul(&t1, &t0, &x);
        fp2_mul(&t2, &curve->A, &curve->C);
        fp2_add(&t1, &t1, &t2);
        fp2_mul(&t1, &t1, &x);
        fp2_add(&t1, &t1, &t0);
        fp2_mul(&t1, &t1, &x);
        if (fp2_is_square(&t1) == false)
        {
            fp2_copy(&Q.x, &x);
            fp2_set_one(&Q.z);
        }
        else
        {
            label = 1;
            continue;
        }

        // Clear factors from the order
        xMULv2(&Q, &Q, p_cofactor_for_Tmin, (int)P_COFACTOR_FOR_TMIN_BITLENGTH, &A24);

        // Check if point has full order
        copy_point(&Qtest1, &Q);
        xMUL(&Qtest1, &Qtest1, dscalar, TORSION_ODD_MINUS->_mp_size, curve);
        copy_point(&Qtest3, &Qtest1);
        for (int i = 0; i < size - 1; i++)
        {
            k = 1;
            copy_point(&Qtest2, &Qtest1);
            for (int j = i; j < size - 1; j++)
            {
                k = k * PRIMES[j];
            }
            ec_mul(&Qtest2, curve, &k, 1, &Qtest2);
            if (ec_is_zero(&Qtest2))
            {
                label = 1;
                continue;
            }
            copy_point(&Qtest[i + 1], &Qtest2);
            ec_mul(&Qtest1, curve, &PRIMES[i], 1, &Qtest1);
        }
        k = 1;
        for (int j = 1; j < size; j++)
        {
            k = k * PRIMES[j];
        }
        ec_mul(&Qtest2, curve, &k, 1, &Qtest3);
        if (ec_is_zero(&Qtest2))
        {
            label = 1;
            continue;
        }
        copy_point(&Qtest[0], &Qtest2);

        // Check if point is orthogonal to P
        for (int i = 0; i < size; i++)
        {
            if (is_point_equal(&Ptest[i], &Qtest[i]))
            {
                label = 1;
                continue;
            }
            xDBL_A24(&Qtest1, &Qtest[i], &A24);
            if (is_point_equal(&Ptest[i], &Qtest1))
            {
                label = 1;
                continue;
            }
            copy_point(&Qtest2, &Qtest1);
            copy_point(&Qtest3, &Qtest[i]);
            for (int j = 2; j < PRIMES[i] / 2; j++)
            {
                xADD(&Qtest1, &Qtest[i], &Qtest2, &Qtest3);
                if (is_point_equal(&Ptest[i], &Qtest1))
                {
                    label = 1;
                    continue;
                }
                copy_point(&Qtest3, &Qtest2);
                copy_point(&Qtest2, &Qtest1);
            }
        }
    }

    // Normalize points
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P.z, &Q.z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P.x, &P.x, &t1);
    fp2_mul(&Q.x, &Q.x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P.x, &P.x, &Q.z);
    fp2_mul(&P.x, &P.x, &curve->C);
    fp2_mul(&Q.x, &Q.x, &P.z);
    fp2_mul(&Q.x, &Q.x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P.z);
    fp2_copy(&Q.z, &P.z);
    fp2_copy(&E.C, &P.z);

    // Compute P-Q
    difference_point(&PQTmin->PmQ, &P, &Q, &E);
    copy_point(&PQTmin->P, &P);
    copy_point(&PQTmin->Q, &Q);
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
}

// New methods for basis generation using Entangled / ApresSQI like
// methods. Finds a point of full order with square checking, then
// finds the point of desired order by clearing cofactors. Not need
// to double all the way down to ensure the correct order.
//
// This also allows a faster method for completing a torsion basis
// as if we know a point P is above (0 : 0) or not, we can directly
// compute the point Q orthogonal to this one using
// ec_curve_to_point_2f_above_montgomery or
// ec_curve_to_point_2f_not_above_montgomery

/// Finds a point of order k * 2^n where n is the largest power of two
/// dividing (p+1).
/// The x-coordinate is picked such that the point (0 : 0) is always
/// the point of order two below the point.

static int
ec_curve_to_point_2f_above_montgomery(ec_point_t *P, const ec_curve_t *curve)
{
    fp_t one;
    fp_set_one(&one);

    // Compute a root of x^2 + Ax + 1
    fp2_t t0, x, four;
    fp2_t a, d, alpha;

    // TODO: do I need to compute A/C here?
    // a = A / C
    fp2_copy(&a, &curve->C);
    fp2_inv(&a);
    fp2_mul(&a, &a, &curve->A);

    // d = sqrt(A^2 - 4)
    fp2_set_small(&four, 4);
    fp2_sqr(&d, &a);
    fp2_sub(&d, &d, &four);
    fp2_sqrt(&d);

    // alpha = (-A + d) / 2
    fp2_sub(&alpha, &d, &a);
    fp2_half(&alpha, &alpha);

    int hint = 0;
    fp2_t z1, z2;
    for (;;)
    {
        // collect z2-value from table, we have 20 chances
        // and expect to be correct 50% of the time.
        if (hint < 20)
        {
            z2 = Z_NQR_TABLE[hint];
        }
        // Fallback method for when we're unlucky
        else
        {
            if (hint == 20)
            {
                fp_set_one(&z1.im);
                fp_set_one(&z2.im);
                fp_set_small(&z1.re, hint - 2);
                fp_set_small(&z2.re, hint - 1);
            }

            // Look for z2 = i + hint with z2 a square and
            // z2 - 1 not a square.
            for (;;)
            {
                // Set z2 = i + hint and z1 = z2 - 1
                // TODO: we could swap z1 and z2 on failure
                // and save one addition
                fp_add(&z1.re, &z1.re, &one);
                fp_add(&z2.re, &z2.re, &one);

                // Now check whether z2 is a square and z1 is not
                if (fp2_is_square(&z2) && !fp2_is_square(&z1))
                {
                    break;
                }
                else
                {
                    hint += 1;
                }
            }
        }

        // Compute x-coordinate
        fp2_mul(&x, &z2, &alpha);

        // Find a point on curve with x a NQR
        fp2_add(&t0, &x, &a);         // x + (A/C)
        fp2_mul(&t0, &t0, &x);        // x^2 + (A/C)*x
        fp_add(&t0.re, &t0.re, &one); // x^2 + (A/C)*x + 1
        fp2_mul(&t0, &t0, &x);        // x^3 + (A/C)*x^2 + x

        if (fp2_is_square(&t0))
        {
            fp2_copy(&P->x, &x);
            fp2_set_one(&P->z);
            break;
        }
        else
        {
            hint += 1;
        }
    }

    return hint;
}

/// Finds a point of order k * 2^n where n is the largest power of two
/// dividing (p+1) using a hint such that z2 = i + hint above the point
/// (0 : 0).
static void
ec_curve_to_point_2f_above_montgomery_from_hint(ec_point_t *P, const ec_curve_t *curve, int hint)
{
    fp2_t x, four;
    fp2_t a, d, alpha;

    // TODO: do I need to compute A/C here?
    // a = A / C
    fp2_copy(&a, &curve->C);
    fp2_inv(&a);
    fp2_mul(&a, &a, &curve->A);

    // d = sqrt(A^2 - 4)
    fp2_set_small(&four, 4);
    fp2_sqr(&d, &a);
    fp2_sub(&d, &d, &four);
    fp2_sqrt(&d);

    // alpha = (-A + d) / 2
    fp2_sub(&alpha, &d, &a);
    fp2_half(&alpha, &alpha);

    // Compute the x coordinate from the hint and alpha
    // With 1/2^20 chance we can use the table look up
    fp2_t z1, z2;
    if (hint < 20)
    {
        z2 = Z_NQR_TABLE[hint];
    }
    // Otherwise we create this using the form i + hint
    else
    {
        fp_set_small(&z2.re, hint);
        fp_set_one(&z2.im);
    }

    // fp_set_small(&z2.re, hint);
    // fp_set_one(&z2.im);
    fp2_mul(&x, &z2, &alpha);

    // Set the point
    fp2_copy(&P->x, &x);
    fp2_set_one(&P->z);
}

/// Finds a point of order k * 2^n where n is the largest power of two
/// dividing (p+1).
/// The x-coordinate is picked such that the point (0 : 0) is never the
/// point of order two.
static int
ec_curve_to_point_2f_not_above_montgomery(ec_point_t *P, const ec_curve_t *curve)
{
    int hint = 0;
    fp_t one;
    fp2_t x, t, t0, t1;

    for (;;)
    {
        // For each guess of an x, we expect it to be a point 1/2
        // the time, so our table look up will work with failure 2^20
        if (hint < 20)
        {
            x = NQR_TABLE[hint];
        }

        // Fallback method in case we do not find a value!
        // For the cases where we are unlucky, we try points of the form
        // x = hint + i
        else
        {
            // When we first hit this loop, set x to be i + (hint - 1)
            // NOTE: we do hint -1 as we add one before checking a square
            //       in the below loop
            if (hint == 20)
            {
                fp_set_one(&one);
                fp_set_one(&x.im);
                fp_set_small(&x.re, hint - 1);
            }

            // Now we find a t which is a NQR of the form i + hint
            for (;;)
            {
                // Increase the real part by one until a NQR is found
                // TODO: could be made faster by adding one rather
                // than setting each time, but this is OK for now.
                fp_add(&x.re, &x.re, &one);
                if (!fp2_is_square(&x))
                {
                    break;
                }
                else
                {
                    hint += 1;
                }
            }
        }

        // Now we have x which is a NQR -- is it on the curve?
        // Note: the below method saves two multiplications compared
        // to old method
        fp2_mul(&t0, &x, &curve->C);  // t0 = x*C
        fp2_add(&t1, &t0, &curve->A); // C*x + A
        fp2_mul(&t1, &t1, &x);        // C*x^2 + A*x
        fp2_add(&t1, &t1, &curve->C); // C*x^2 + A*x + C
        fp2_mul(&t1, &t1, &t0);       // C^2*x^3 + A*C*x^2 + C^2*x = C^2*y^2

        if (fp2_is_square(&t1))
        {
            fp2_copy(&P->x, &x);
            fp2_set_one(&P->z);
            break;
        }
        else
        {
            hint += 1;
        }
    }

    return hint;
}

/// Finds a point of order k * 2^n where n is the largest power of two
/// dividing (p+1) using a hint such that z2 = i + hint not above
/// the point (0 : 0).
static void
ec_curve_to_point_2f_not_above_montgomery_from_hint(ec_point_t *P,
                                                    const ec_curve_t *curve,
                                                    int hint)
{
    fp2_t x;

    // If we got lucky (1/2^20) then we just grab an x-value
    // from the table
    if (hint < 20)
    {
        x = NQR_TABLE[hint];
    }
    // Otherwise, we find points of the form
    // i + hint
    else
    {
        fp_set_small(&x.re, hint);
        fp_set_one(&x.im);
    }

    fp2_copy(&P->x, &x);
    fp2_set_one(&P->z);
}

// Helper function to construct normalised basis given E[N] = <P, Q>
static inline void
normalise_points_for_basis(ec_basis_t *PQ2, const ec_curve_t *curve, ec_point_t *P, ec_point_t *Q)
{
    // Normalize points
    fp2_t t0, t1;
    ec_curve_t E;
    ec_curve_init(&E);

    fp2_mul(&t0, &P->z, &Q->z);
    fp2_mul(&t1, &t0, &curve->C);
    fp2_inv(&t1);
    fp2_mul(&P->x, &P->x, &t1);
    fp2_mul(&Q->x, &Q->x, &t1);
    fp2_mul(&E.A, &curve->A, &t1);
    fp2_mul(&P->x, &P->x, &Q->z);
    fp2_mul(&P->x, &P->x, &curve->C);
    fp2_mul(&Q->x, &Q->x, &P->z);
    fp2_mul(&Q->x, &Q->x, &curve->C);
    fp2_mul(&E.A, &E.A, &t0);
    fp2_set_one(&P->z);
    fp2_copy(&Q->z, &P->z);
    fp2_copy(&E.C, &P->z);

    // Compute P-Q
    difference_point(&PQ2->PmQ, P, Q, &E);
    copy_point(&PQ2->P, P);
    copy_point(&PQ2->Q, Q);
}

// Helper function which given a point of order k*2^n with n maximal
// and k odd, computes a point of order 2^f
static inline void
clear_cofactor_for_maximal_even_order(ec_point_t *P, const ec_curve_t *curve, int f)
{
    // clear out the odd cofactor to get a point of order 2^n
    xMULv2(P, P, p_cofactor_for_2f, P_COFACTOR_FOR_2F_BITLENGTH, &curve->A24);

    // clear the power of two to get a point of order 2^f
    for (int i = 0; i < POWER_OF_2 - f; i++)
    {
        xDBL_A24_normalized(P, P, &curve->A24);
    }
}

// Computes a basis E[2^f] = <P, Q> where the point Q is above (0 : 0)
void ec_curve_to_basis_2f(ec_basis_t *PQ2, ec_curve_t *curve, int f)
{
    // TODO: is this fastest for this case?
    // normalize the curve
    ec_curve_normalize_A24(curve);

    // Compute the points P, Q
    ec_point_t P, Q;
    ec_curve_to_point_2f_not_above_montgomery(&P, curve);
    ec_curve_to_point_2f_above_montgomery(&Q, curve);

    // clear out the odd cofactor to get a point of order 2^f
    clear_cofactor_for_maximal_even_order(&P, curve, f);
    clear_cofactor_for_maximal_even_order(&Q, curve, f);

    // Normalise and compute the basis P, Q and P - Q
    normalise_points_for_basis(PQ2, curve, &P, &Q);
}

// Computes a basis E[2^f] = <P, Q> where the point Q is above (0 : 0)
// and stores hints as an array for faster recomputation at a later point
void ec_curve_to_basis_2f_to_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint)
{
    // TODO: is this fastest for this case?
    // normalize the curve
    ec_curve_normalize_A24(curve);

    // Compute the points P, Q
    ec_point_t P, Q;
    hint[0] = ec_curve_to_point_2f_not_above_montgomery(&P, curve);
    hint[1] = ec_curve_to_point_2f_above_montgomery(&Q, curve);

    // clear out the odd cofactor to get a point of order 2^f
    clear_cofactor_for_maximal_even_order(&P, curve, f);
    clear_cofactor_for_maximal_even_order(&Q, curve, f);

    // Normalise and compute the basis P, Q and P - Q
    normalise_points_for_basis(PQ2, curve, &P, &Q);
}

void ec_curve_to_basis_2f_from_hint(ec_basis_t *PQ2, ec_curve_t *curve, int f, int *hint)
{
    // TODO: is this fastest for this case?
    // normalize the curve
    ec_curve_normalize_A24(curve);

    // Compute the points P, Q
    ec_point_t P, Q;
    ec_curve_to_point_2f_not_above_montgomery_from_hint(&P, curve, hint[0]);
    ec_curve_to_point_2f_above_montgomery_from_hint(&Q, curve, hint[1]);

    // clear out the odd cofactor to get a point of order 2^f
    clear_cofactor_for_maximal_even_order(&P, curve, f);
    clear_cofactor_for_maximal_even_order(&Q, curve, f);

    // Normalise and compute the basis P, Q and P - Q
    normalise_points_for_basis(PQ2, curve, &P, &Q);
}

/// Given a point R in E[2^f] compute E[2^f] = <P, Q> with Q above (0 : 0)
void ec_complete_basis_2f(ec_basis_t *PQ2, ec_curve_t *curve, const ec_point_t *R, int f)
{
    ec_point_t R2, P, Q;

    // TODO: is this fastest for this case?
    // normalize the curve
    ec_curve_normalize_A24(curve);

    // Compute the point of order two beneath R
    copy_point(&R2, R);
    for (int i = 0; i < f - 1; i++)
    {
        xDBL_A24(&R2, &R2, &curve->A24);
    }

    // If R2 = (0 : 0) then we ensure P is not above the Montgomery point
    // and set R = Q
    if (fp2_is_zero(&R2.x))
    {
        // Compute point of order k*2^n, not above (0 : 0)
        ec_curve_to_point_2f_not_above_montgomery(&P, curve);

        // clear out the odd cofactor to get a point of order 2^f
        clear_cofactor_for_maximal_even_order(&P, curve, f);

        copy_point(&Q, R);
    }
    // Otherwise, we set P = R and find Q above (0 : 0)
    else
    {
        copy_point(&P, R);

        // Set Q to be the point above (0 : 0)
        ec_curve_to_point_2f_above_montgomery(&Q, curve);

        // clear out the odd cofactor to get a point of order 2^f
        clear_cofactor_for_maximal_even_order(&Q, curve, f);
    }

    normalise_points_for_basis(PQ2, curve, &P, &Q);
}
