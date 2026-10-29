#include "theta_isogenies.h"
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <tools.h>

void theta_print(char *name, theta_point_t P)
{
    fp2_t a;
    assert(!fp2_is_zero(&P.y));
    fp2_copy(&a, &P.y);
    fp2_inv(&a);
    fp2_mul(&a, &a, &P.t);
    fp2_print(name, &a);
}

void fp2_sett(fp2_t *a, int t)
{
    if (t == 1)
    {
        fp2_set_one(a);
    }
    else if (t == 0)
    {
        fp2_set_zero(a);
    }
    else if (t == -1)
    {
        fp2_set_one(a);
        fp2_neg(a, a);
    }
    else
    {
        fp2_set_small(a, t);
    }
}

void choose_index_theta_point(fp2_t *res, int ind, const theta_point_t *T)
{
    int t = ind % 4;
    if (t == 0)
    {
        fp2_copy(res, &T->x);
    }
    else if (t == 1)
    {
        fp2_copy(res, &T->y);
    }
    else if (t == 2)
    {
        fp2_copy(res, &T->z);
    }
    else if (t == 3)
    {
        fp2_copy(res, &T->t);
    }
    else
    {
        assert(0);
    }
}

void set_index_theta_point(theta_point_t *res, int ind, const fp2_t *val)
{
    int t = ind % 4;
    if (t == 0)
    {
        fp2_copy(&res->x, val);
    }
    else if (t == 1)
    {
        fp2_copy(&res->y, val);
    }
    else if (t == 2)
    {
        fp2_copy(&res->z, val);
    }
    else if (t == 3)
    {
        fp2_copy(&res->t, val);
    }
    else
    {
        assert(0);
    }
}

// compute the theta_point corresponding to the couple of point T on an elliptic product
void base_change(theta_point_t *out, const theta_gluing_t *phi, const theta_couple_point_t *T)
{
    fp2_t a, b, c, d, x1, x2;
    if (fp2_is_zero(&T->P1.z) && fp2_is_zero(&T->P1.x))
    {
        fp2_sett(&x1, 1);
    }
    else
    {
        x1 = T->P1.x;
    }
    if (fp2_is_zero(&T->P2.z) && fp2_is_zero(&T->P2.x))
    {
        fp2_sett(&x2, 1);
    }
    else
    {
        x2 = T->P2.x;
    }

    // a = P1.x P2.x, b = P1.x P2.z, c =P1.z P2.x, d = P1.z P2.z
    fp2_mul(&a, &x1, &x2);
    fp2_mul(&b, &x1, &T->P2.z);
    fp2_mul(&c, &x2, &T->P1.z);
    fp2_mul(&d, &T->P1.z, &T->P2.z);

    // Apply the matrix
    fp2_mul(&out->x, &a, &phi->M00);
    fp2_mul(&x1, &b, &phi->M01);
    fp2_add(&out->x, &out->x, &x1);
    fp2_mul(&x1, &c, &phi->M02);
    fp2_add(&out->x, &out->x, &x1);
    fp2_mul(&x1, &d, &phi->M03);
    fp2_add(&out->x, &out->x, &x1);

    fp2_mul(&out->y, &a, &phi->M10);
    fp2_mul(&x1, &b, &phi->M11);
    fp2_add(&out->y, &out->y, &x1);
    fp2_mul(&x1, &c, &phi->M12);
    fp2_add(&out->y, &out->y, &x1);
    fp2_mul(&x1, &d, &phi->M13);
    fp2_add(&out->y, &out->y, &x1);

    fp2_mul(&out->z, &a, &phi->M20);
    fp2_mul(&x1, &b, &phi->M21);
    fp2_add(&out->z, &out->z, &x1);
    fp2_mul(&x1, &c, &phi->M22);
    fp2_add(&out->z, &out->z, &x1);
    fp2_mul(&x1, &d, &phi->M23);
    fp2_add(&out->z, &out->z, &x1);

    fp2_mul(&out->t, &a, &phi->M30);
    fp2_mul(&x1, &b, &phi->M31);
    fp2_add(&out->t, &out->t, &x1);
    fp2_mul(&x1, &c, &phi->M32);
    fp2_add(&out->t, &out->t, &x1);
    fp2_mul(&x1, &d, &phi->M33);
    fp2_add(&out->t, &out->t, &x1);
}

/**
 * @brief Compute the gluing isogeny from an elliptic product
 *
 * @param out Output: the theta_gluing
 * @param K1_8 a couple point
 * @param E12 an elliptic curve product
 * @param K2_8 a point in E2[8]
 *
 * out : E1xE2 -> A of kernel [4](K1_8,K2_8)
 *
 */
void gluing_comput(theta_gluing_t *out,
                   theta_couple_curve_t *E12,
                   const theta_couple_jac_point_t *xyK1_8,
                   const theta_couple_jac_point_t *xyK2_8
                   // const theta_couple_point_t *K1_8,const theta_couple_point_t *K2_8, const
                   // theta_couple_point_t *K1m2_8
)
{
    // var init
    fp2_t M1100;
    fp2_t M1101;
    fp2_t M1110;
    fp2_t M1111;
    fp2_t M1200;
    fp2_t M1201;
    fp2_t M1210;
    fp2_t M1211;
    fp2_t M2100;
    fp2_t M2101;
    fp2_t M2110;
    fp2_t M2111;
    fp2_t M2200;
    fp2_t M2201;
    fp2_t M2210;
    fp2_t M2211;
    fp2_t t001, t101, t002, t102, temp;

    theta_point_t TT1, TT2;
    theta_couple_point_t K1m2_4;
    ec_basis_t B;
    theta_couple_point_t K1_8, K2_8;

    double_couple_jac_point_iter(&out->xyK1_4, 1, E12, xyK1_8);
    double_couple_jac_point_iter(&out->xyK2_4, 1, E12, xyK2_8);

    couple_jac_to_xz(&K1_8, xyK1_8);
    couple_jac_to_xz(&K2_8, xyK2_8);
    couple_jac_to_xz(&out->K1_4, &out->xyK1_4);
    couple_jac_to_xz(&out->K2_4, &out->xyK2_4);
    // assert(test_point_order_twof(&K1_8.P1,&E12->E1,8));

    // computing the base change matrix
    ec_point_t P11, P12, P21, P22;
    fp2_t t[8];
    fp2_t temp_fp;

    ec_dbl(&P11, &E12->E1, &out->K1_4.P1);
    ec_dbl(&P12, &E12->E2, &out->K1_4.P2);
    ec_dbl(&P21, &E12->E1, &out->K2_4.P1);
    ec_dbl(&P22, &E12->E2, &out->K2_4.P2);

    fp2_copy(&t[0], &out->K1_4.P1.z);
    fp2_copy(&t[1], &out->K1_4.P2.z);
    fp2_copy(&t[2], &out->K2_4.P1.z);
    fp2_copy(&t[3], &out->K2_4.P2.z);

    // Ki_4.Pj = (xij,zij)
    // Pij = (uij,wij)
    // detij = xij wij - uij zij
    fp2_mul(&t[4], &out->K1_4.P1.x, &P11.z);
    fp2_mul(&temp_fp, &out->K1_4.P1.z, &P11.x);
    fp2_sub(&t[4], &t[4], &temp_fp);
    fp2_mul(&t[5], &out->K1_4.P2.x, &P12.z);
    fp2_mul(&temp_fp, &out->K1_4.P2.z, &P12.x);
    fp2_sub(&t[5], &t[5], &temp_fp);
    fp2_mul(&t[6], &out->K2_4.P1.x, &P21.z);
    fp2_mul(&temp_fp, &out->K2_4.P1.z, &P21.x);
    fp2_sub(&t[6], &t[6], &temp_fp);
    fp2_mul(&t[7], &out->K2_4.P2.x, &P22.z);
    fp2_mul(&temp_fp, &out->K2_4.P2.z, &P22.x);
    fp2_sub(&t[7], &t[7], &temp_fp);

    fp2_batched_inv(t, 8);

    // Mij10 = uij xij /detij - xij/zij
    fp2_mul(&temp_fp, &out->K1_4.P1.x, &t[0]);
    fp2_mul(&M1110, &out->K1_4.P1.x, &P11.x);
    fp2_mul(&M1110, &M1110, &t[4]);
    fp2_sub(&M1110, &M1110, &temp_fp);
    fp2_mul(&temp_fp, &out->K1_4.P2.x, &t[1]);
    fp2_mul(&M1210, &out->K1_4.P2.x, &P12.x);
    fp2_mul(&M1210, &M1210, &t[5]);
    fp2_sub(&M1210, &M1210, &temp_fp);
    fp2_mul(&temp_fp, &out->K2_4.P1.x, &t[2]);
    fp2_mul(&M2110, &out->K2_4.P1.x, &P21.x);
    fp2_mul(&M2110, &M2110, &t[6]);
    fp2_sub(&M2110, &M2110, &temp_fp);
    fp2_mul(&temp_fp, &out->K2_4.P2.x, &t[3]);
    fp2_mul(&M2210, &out->K2_4.P2.x, &P22.x);
    fp2_mul(&M2210, &M2210, &t[7]);
    fp2_sub(&M2210, &M2210, &temp_fp);

    // Mij11 = uij zij * detij
    fp2_mul(&M1111, &P11.x, &t[4]);
    fp2_mul(&M1111, &M1111, &out->K1_4.P1.z);
    fp2_mul(&M1211, &P12.x, &t[5]);
    fp2_mul(&M1211, &M1211, &out->K1_4.P2.z);
    fp2_mul(&M2111, &P21.x, &t[6]);
    fp2_mul(&M2111, &M2111, &out->K2_4.P1.z);
    fp2_mul(&M2211, &P22.x, &t[7]);
    fp2_mul(&M2211, &M2211, &out->K2_4.P2.z);

    // Mij00 = -Mij11
    fp2_neg(&M1100, &M1111);
    fp2_neg(&M1200, &M1211);
    fp2_neg(&M2100, &M2111);
    fp2_neg(&M2200, &M2211);

    // Mij01 = - wij zij detij
    fp2_mul(&M1101, &P11.z, &t[4]);
    fp2_mul(&M1101, &M1101, &out->K1_4.P1.z);
    fp2_neg(&M1101, &M1101);
    fp2_mul(&M1201, &P12.z, &t[5]);
    fp2_mul(&M1201, &M1201, &out->K1_4.P2.z);
    fp2_neg(&M1201, &M1201);
    fp2_mul(&M2101, &P21.z, &t[6]);
    fp2_mul(&M2101, &M2101, &out->K2_4.P1.z);
    fp2_neg(&M2101, &M2101);
    fp2_mul(&M2201, &P22.z, &t[7]);
    fp2_mul(&M2201, &M2201, &out->K2_4.P2.z);
    fp2_neg(&M2201, &M2201);

    // multiplication of the matrices
    // t001,t101 (resp t002,t102) first column of M11 * M21 (resp M12 * M22)
    fp2_mul(&t001, &M1100, &M2100);
    fp2_mul(&temp, &M1101, &M2110);
    fp2_add(&t001, &t001, &temp);

    fp2_mul(&t101, &M1110, &M2100);
    fp2_mul(&temp, &M1111, &M2110);
    fp2_add(&t101, &t101, &temp);

    fp2_mul(&t002, &M1200, &M2200);
    fp2_mul(&temp, &M1201, &M2210);
    fp2_add(&t002, &t002, &temp);

    fp2_mul(&t102, &M1210, &M2200);
    fp2_mul(&temp, &M1211, &M2210);
    fp2_add(&t102, &t102, &temp);

    // trace for the first row
    fp2_sett(&out->M00, 1);
    fp2_mul(&temp, &t001, &t002);
    fp2_add(&out->M00, &out->M00, &temp);
    fp2_mul(&temp, &M2100, &M2200);
    fp2_add(&out->M00, &out->M00, &temp);
    fp2_mul(&temp, &M1100, &M1200);
    fp2_add(&out->M00, &out->M00, &temp);

    fp2_mul(&out->M01, &t001, &t102);
    fp2_mul(&temp, &M2100, &M2210);
    fp2_add(&out->M01, &out->M01, &temp);
    fp2_mul(&temp, &M1100, &M1210);
    fp2_add(&out->M01, &out->M01, &temp);

    fp2_mul(&out->M02, &t101, &t002);
    fp2_mul(&temp, &M2110, &M2200);
    fp2_add(&out->M02, &out->M02, &temp);
    fp2_mul(&temp, &M1110, &M1200);
    fp2_add(&out->M02, &out->M02, &temp);

    fp2_mul(&out->M03, &t101, &t102);
    fp2_mul(&temp, &M2110, &M2210);
    fp2_add(&out->M03, &out->M03, &temp);
    fp2_mul(&temp, &M1110, &M1210);
    fp2_add(&out->M03, &out->M03, &temp);

    // Compute the action of (0,out.K2_4.P2) for the second row
    fp2_mul(&temp, &M2201, &out->M01);
    fp2_mul(&out->M10, &M2200, &out->M00);
    fp2_add(&out->M10, &out->M10, &temp);

    fp2_mul(&temp, &M2211, &out->M01);
    fp2_mul(&out->M11, &M2210, &out->M00);
    fp2_add(&out->M11, &out->M11, &temp);

    fp2_mul(&temp, &M2201, &out->M03);
    fp2_mul(&out->M12, &M2200, &out->M02);
    fp2_add(&out->M12, &out->M12, &temp);

    fp2_mul(&temp, &M2211, &out->M03);
    fp2_mul(&out->M13, &M2210, &out->M02);
    fp2_add(&out->M13, &out->M13, &temp);

    // compute the action of (K1_4.P1,0) for the third row
    fp2_mul(&temp, &M1101, &out->M02);
    fp2_mul(&out->M20, &M1100, &out->M00);
    fp2_add(&out->M20, &out->M20, &temp);

    fp2_mul(&temp, &M1101, &out->M03);
    fp2_mul(&out->M21, &M1100, &out->M01);
    fp2_add(&out->M21, &out->M21, &temp);

    fp2_mul(&temp, &M1111, &out->M02);
    fp2_mul(&out->M22, &M1110, &out->M00);
    fp2_add(&out->M22, &out->M22, &temp);

    fp2_mul(&temp, &M1111, &out->M03);
    fp2_mul(&out->M23, &M1110, &out->M01);
    fp2_add(&out->M23, &out->M23, &temp);

    // compute the action of (K1_4.P1,K2_4.P2) for the final row
    fp2_mul(&temp, &M1101, &out->M12);
    fp2_mul(&out->M30, &M1100, &out->M10);
    fp2_add(&out->M30, &out->M30, &temp);

    fp2_mul(&temp, &M1101, &out->M13);
    fp2_mul(&out->M31, &M1100, &out->M11);
    fp2_add(&out->M31, &out->M31, &temp);

    fp2_mul(&temp, &M1111, &out->M12);
    fp2_mul(&out->M32, &M1110, &out->M10);
    fp2_add(&out->M32, &out->M32, &temp);

    fp2_mul(&temp, &M1111, &out->M13);
    fp2_mul(&out->M33, &M1110, &out->M11);
    fp2_add(&out->M33, &out->M33, &temp);

    // apply the base change
    base_change(&out->T1_8, out, &K1_8);
    base_change(&out->T2_8, out, &K2_8);

    // computing the codomain
    // computation of the zero index
    to_squared_theta(&TT1, &out->T1_8);
    to_squared_theta(&TT2, &out->T2_8);

    if (fp2_is_zero(&TT1.x))
    {
        out->zero_idx = 0;
    }
    else if (fp2_is_zero(&TT1.y))
    {
        out->zero_idx = 1;
    }
    else if (fp2_is_zero(&TT1.z))
    {
        out->zero_idx = 2;
    }
    else
    {
        out->zero_idx = 3;
    }

#ifndef NDEBUG
    fp2_t a1, a2;
    choose_index_theta_point(&a1, out->zero_idx, &TT1);
    choose_index_theta_point(&a2, out->zero_idx, &TT2);
    assert(fp2_is_zero(&a1) && fp2_is_zero(&a2));
#endif

    choose_index_theta_point(&t001, 1 ^ out->zero_idx, &TT2);
    choose_index_theta_point(&t002, 2 ^ out->zero_idx, &TT1);
    choose_index_theta_point(&t101, 3 ^ out->zero_idx, &TT2);
    choose_index_theta_point(&t102, 3 ^ out->zero_idx, &TT1);

    fp2_t t1, t2, t3, t4;
    // t1 = t001;t2=t002;t3=t101;t4=t102;
    fp2_copy(&t1, &t001);
    fp2_copy(&t2, &t002);
    fp2_copy(&t3, &t101);
    fp2_copy(&t4, &t102);

    fp2_t t_inv[4];
    fp2_copy(&t_inv[0], &t1);
    fp2_copy(&t_inv[1], &t2);
    fp2_copy(&t_inv[2], &t3);
    fp2_copy(&t_inv[3], &t4);
    fp2_batched_inv(t_inv, 4);
    fp2_copy(&t001, &t_inv[0]);
    fp2_copy(&t002, &t_inv[1]);
    fp2_copy(&t101, &t_inv[2]);
    fp2_copy(&t102, &t_inv[3]);

    // Compute A,B,C,D
    fp2_sett(&temp, 0);
    set_index_theta_point(&out->codomain, 0 ^ out->zero_idx, &temp);
    fp2_mul(&temp, &t101, &t1);
    set_index_theta_point(&out->codomain, 1 ^ out->zero_idx, &temp);
    fp2_mul(&temp, &t2, &t102);
    set_index_theta_point(&out->codomain, 2 ^ out->zero_idx, &temp);
    fp2_sett(&temp, 1);
    set_index_theta_point(&out->codomain, 3 ^ out->zero_idx, &temp);
    choose_index_theta_point(&temp, 2 ^ out->zero_idx, &out->codomain);

    // compute precomp
    fp2_sett(&temp, 0);
    set_index_theta_point(&out->precomputation, out->zero_idx, &temp);
    fp2_mul(&temp, &t001, &t3);
    set_index_theta_point(&out->precomputation, 1 ^ out->zero_idx, &temp);
    fp2_mul(&temp, &t4, &t002);
    set_index_theta_point(&out->precomputation, 2 ^ out->zero_idx, &temp);
    fp2_sett(&temp, 1);
    set_index_theta_point(&out->precomputation, 3 ^ out->zero_idx, &temp);
    choose_index_theta_point(&temp, 2 ^ out->zero_idx, &out->precomputation);

    // compute the final codomain
    hadamard(&out->codomain, &out->codomain);
}

// sub routine of the gluing eval
void gluing_eval_point(theta_point_t *image1,
                       const theta_couple_point_t *P,
                       const theta_couple_point_t *Pt,
                       const theta_gluing_t *phi)
{

    theta_point_t T, Tt;
    fp2_t x, y, z, t, temp;

    // apply the basis change
    base_change(&T, phi, P);
    base_change(&Tt, phi, Pt);

    // apply the to_squared_theta transform
    to_squared_theta(&T, &T);
    to_squared_theta(&Tt, &Tt);

    // compute y,z,t
    choose_index_theta_point(&y, 1 ^ phi->zero_idx, &T);
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&y, &y, &temp);
    choose_index_theta_point(&z, 2 ^ phi->zero_idx, &T);
    choose_index_theta_point(&temp, 2 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&z, &z, &temp);
    choose_index_theta_point(&t, 3 ^ phi->zero_idx, &T);

    //  normalize
    if (!fp2_is_zero(&z))
    {
        fp2_copy(&x, &z);
        choose_index_theta_point(&temp, 3 ^ phi->zero_idx, &Tt);

        fp2_mul(&y, &y, &temp);
        fp2_mul(&z, &z, &temp);
        fp2_mul(&t, &t, &temp);
    }
    else
    {
        choose_index_theta_point(&temp, 2 ^ phi->zero_idx, &Tt);
        choose_index_theta_point(&x, 2 ^ phi->zero_idx, &phi->precomputation);
        fp2_mul(&temp, &temp, &x);
        fp2_copy(&x, &t);

        fp2_mul(&y, &y, &temp);
        fp2_mul(&z, &z, &temp);
        fp2_mul(&t, &t, &temp);
    }

    // recover x
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &Tt);
    fp2_mul(&x, &x, &temp);
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&x, &x, &temp);

    // fill the image coordinates
    set_index_theta_point(image1, 0 ^ phi->zero_idx, &x);
    set_index_theta_point(image1, 1 ^ phi->zero_idx, &y);
    set_index_theta_point(image1, 2 ^ phi->zero_idx, &z);
    set_index_theta_point(image1, 3 ^ phi->zero_idx, &t);

    // hadamard
    hadamard(image1, image1);
}

// same as gluing_eval_point but in the very special case where we already know that the point will
// have a zero coordinate at the place where the zero coordinate of the dual_theta_nullpoint would
// have made the computation difficult
void gluing_eval_point_special_case(theta_point_t *image,
                                    const theta_couple_point_t *P,
                                    const theta_gluing_t *phi)
{
    theta_point_t T;
    fp2_t x, y, z, t, temp;

    // apply the basis change
    base_change(&T, phi, P);

    // apply the to_squared_theta transform
    to_squared_theta(&T, &T);

    // compute y,z,t
    choose_index_theta_point(&y, 1 ^ phi->zero_idx, &T);
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&y, &y, &temp);
    choose_index_theta_point(&z, 2 ^ phi->zero_idx, &T);
    choose_index_theta_point(&temp, 2 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&z, &z, &temp);
    choose_index_theta_point(&t, 3 ^ phi->zero_idx, &T);

    // this is always 0 in the special case
    fp2_set_zero(&x);

    // fill the image coordinates
    set_index_theta_point(image, 0 ^ phi->zero_idx, &x);
    set_index_theta_point(image, 1 ^ phi->zero_idx, &y);
    set_index_theta_point(image, 2 ^ phi->zero_idx, &z);
    set_index_theta_point(image, 3 ^ phi->zero_idx, &t);

    // hadamard
    hadamard(image, image);
}

// sub routine of the gluing eval
void gluing_eval_point_no_help(theta_point_t *image1,
                               const theta_couple_jac_point_t *P,
                               const theta_couple_curve_t *E12,
                               const theta_gluing_t *phi)
{

    theta_couple_point_t Pt;
    theta_couple_jac_point_t tmp;
    theta_point_t T, Tt;
    fp2_t x, y, z, t, temp;

#ifndef NDEBUG
    jac_to_xz(&Pt.P2, &phi->xyK1_4.P2);
    assert(test_point_order_twof(&phi->K1_4.P2, &E12->E2, 2));
    assert(test_point_order_twof(&Pt.P2, &E12->E2, 2));
#endif

    // we compute Pt
    ADD(&tmp.P1, &P->P1, &phi->xyK1_4.P1, &E12->E1);
    ADD(&tmp.P2, &P->P2, &phi->xyK1_4.P2, &E12->E2);

    couple_jac_to_xz(&Pt, &tmp);

    // apply the basis change
    // on the translated point
    base_change(&Tt, phi, &Pt);
    // on the point to evaluate
    couple_jac_to_xz(&Pt, P);
    base_change(&T, phi, &Pt);

    // apply the to_squared_theta transform
    to_squared_theta(&T, &T);
    to_squared_theta(&Tt, &Tt);

    // compute y,z,t
    choose_index_theta_point(&y, 1 ^ phi->zero_idx, &T);
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&y, &y, &temp);
    choose_index_theta_point(&z, 2 ^ phi->zero_idx, &T);
    choose_index_theta_point(&temp, 2 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&z, &z, &temp);
    choose_index_theta_point(&t, 3 ^ phi->zero_idx, &T);

    //  normalize
    if (!fp2_is_zero(&z))
    {
        fp2_copy(&x, &z);
        choose_index_theta_point(&temp, 3 ^ phi->zero_idx, &Tt);

        fp2_mul(&y, &y, &temp);
        fp2_mul(&z, &z, &temp);
        fp2_mul(&t, &t, &temp);
    }
    else
    {
        choose_index_theta_point(&temp, 2 ^ phi->zero_idx, &Tt);
        choose_index_theta_point(&x, 2 ^ phi->zero_idx, &phi->precomputation);
        fp2_mul(&temp, &temp, &x);
        fp2_copy(&x, &t);

        fp2_mul(&y, &y, &temp);
        fp2_mul(&z, &z, &temp);
        fp2_mul(&t, &t, &temp);
    }

    // recover x
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &Tt);
    fp2_mul(&x, &x, &temp);
    choose_index_theta_point(&temp, 1 ^ phi->zero_idx, &phi->precomputation);
    fp2_mul(&x, &x, &temp);

    // fill the image coordinates
    set_index_theta_point(image1, 0 ^ phi->zero_idx, &x);
    set_index_theta_point(image1, 1 ^ phi->zero_idx, &y);
    set_index_theta_point(image1, 2 ^ phi->zero_idx, &z);
    set_index_theta_point(image1, 3 ^ phi->zero_idx, &t);

    // hadamard
    hadamard(image1, image1);
}

/**
 * @brief Evaluate a gluing isogeny from an elliptic product on a basis
 *
 * @param image1 Output: the theta_point of the image of the first couple of points
 * @param image2 Output : the theta point of the image of the second couple of points
 * @param P : a couple point in E12
 * @param Q : a couple point in E12
 * @param PmQ : a couple point in E12 corresponding to P-Q
 * @param a : ibz
 * @param b : ibz
 * @param E12 : an elliptic product
 * @param phi : a gluing isogeny E1 x E2 -> A
 *
 * The integers a,b are such that the phi.K1_4 = a P + b Q
 * out : phi( P ), Phi (Q)
 *
 */
void gluing_eval_basis(theta_point_t *image1,
                       theta_point_t *image2,
                       // const theta_couple_point_t *P,const theta_couple_point_t *Q, const
                       // theta_couple_point_t *PmQ,const ibz_t *a, const ibz_t *b,
                       const theta_couple_jac_point_t *xyT1,
                       const theta_couple_jac_point_t *xyT2,
                       theta_couple_curve_t *E12,
                       const theta_gluing_t *phi)
{

    theta_couple_point_t P, Pt;
    theta_couple_jac_point_t T;

    // add the point to push with xyK1_4
    ADD(&T.P1, &xyT1->P1, &phi->xyK1_4.P1, &E12->E1);
    ADD(&T.P2, &xyT1->P2, &phi->xyK1_4.P2, &E12->E2);

    couple_jac_to_xz(&Pt, &T);
    couple_jac_to_xz(&P, xyT1);

    // then we evaluate the gluing
    gluing_eval_point(image1, &P, &Pt, phi);

    // then we do the same on the second point
    ADD(&T.P1, &xyT2->P1, &phi->xyK1_4.P1, &E12->E1);
    ADD(&T.P2, &xyT2->P2, &phi->xyK1_4.P2, &E12->E2);

    couple_jac_to_xz(&Pt, &T);
    couple_jac_to_xz(&P, xyT2);
    // then we evaluate the gluing
    gluing_eval_point(image2, &P, &Pt, phi);
}

/**
 * @brief Compute  a (2,2) isogeny in dimension 2 in the theta_model
 *
 * @param out Output: the theta_isogeny
 * @param A a theta null point for the domain
 * @param T1_8 a point in A[8]
 * @param T2_8 a point in A[8]
 * @param bool1 a boolean
 * @param boo2 a boolean
 *
 * out : A -> B of kernel [4](T1_8,T2_8)
 * bool1 controls if the domain is in standard or dual coordinates
 * bool2 controls if the codomain is in standard or dual coordinates
 *
 */
void theta_isogeny_comput(theta_isogeny_t *out,
                          const theta_structure_t *A,
                          const theta_point_t *T1_8,
                          const theta_point_t *T2_8,
                          int bool1,
                          int bool2)
{
    out->bool1 = bool1;
    out->bool2 = bool2;
    out->domain = *A;
    out->T1_8 = *T1_8;
    out->T2_8 = *T2_8;
    out->codomain.precomputation = 0;

    theta_point_t TT1, TT2;

    // fp2_t xA_inv,zA_inv,tB_inv;

    if (bool1)
    {
        hadamard(&TT1, T1_8);
        to_squared_theta(&TT1, &TT1);
        hadamard(&TT2, T2_8);
        to_squared_theta(&TT2, &TT2);
    }
    else
    {
        to_squared_theta(&TT1, T1_8);
        to_squared_theta(&TT2, T2_8);
    }

    if (!bool1 && A->precomputation)
    {
        // xA_inv = TT1.x;
        // zA_inv = TT2.x;
        // tB_inv = TT2.y;
        // fp2_t invs[3];
        // fp2_copy(&invs[0],&xA_inv);
        // fp2_copy(&invs[1],&zA_inv);
        // fp2_copy(&invs[2],&tB_inv);
        // fp2_batched_inv(invs,3);
        // fp2_copy(&xA_inv,&invs[0]);
        // fp2_copy(&zA_inv,&invs[1]);
        // fp2_copy(&tB_inv,&invs[2]);

        // computation of B,C,D for the codomain
        // fp2_sett(&out->codomain.null_point.x,1);
        // fp2_mul(&out->codomain.null_point.y,&xA_inv,&TT1.y);
        // fp2_mul(&out->codomain.null_point.z,&zA_inv,&TT2.z);
        // fp2_mul(&out->codomain.null_point.t,&tB_inv,&TT2.t);
        // fp2_mul(&out->codomain.null_point.t,&out->codomain.null_point.t,&out->codomain.null_point.y);

        fp2_mul(&out->codomain.null_point.x, &TT2.x, &TT2.y);
        fp2_mul(&out->codomain.null_point.y, &out->codomain.null_point.x, &TT1.y);
        fp2_mul(&out->codomain.null_point.x, &out->codomain.null_point.x, &TT1.x);
        fp2_mul(&out->codomain.null_point.z, &TT2.z, &TT1.x);
        fp2_mul(&out->codomain.null_point.z, &out->codomain.null_point.z, &TT2.y);
        fp2_mul(&out->codomain.null_point.t, &TT2.t, &TT2.x);
        fp2_mul(&out->codomain.null_point.t, &out->codomain.null_point.t, &TT1.y);

        // computation B_inv,C_inv,D_inv for the precomputation
        // fp2_sett(&out->precomputation.x,1);
        //     fp2_copy(&out->precomputation.x,&out->codomain.null_point.x);
        //     fp2_mul(&out->precomputation.y,&out->codomain.null_point.y,&out->domain.Y0);
        //     fp2_mul(&out->precomputation.z,&out->codomain.null_point.z,&out->domain.Z0);
        //     fp2_mul(&out->precomputation.t,&out->codomain.null_point.t,&out->domain.T0);

        fp2_mul(&out->precomputation.x, &out->codomain.null_point.x, &out->domain.YZT0);
        fp2_mul(&out->precomputation.y, &out->codomain.null_point.y, &out->domain.XZT0);
        fp2_mul(&out->precomputation.z, &out->codomain.null_point.z, &out->domain.XYT0);
        fp2_mul(&out->precomputation.t, &out->codomain.null_point.t, &out->domain.XYZ0);

        // fp2_mul(&out->precomputation.x,&out->precomputation.x,&out->domain.ZT0);
        // fp2_mul(&out->precomputation.y,&out->precomputation.y,&out->domain.ZT0);
        // fp2_mul(&out->precomputation.z,&out->precomputation.z,&out->domain.XY0);
        // fp2_mul(&out->precomputation.t,&out->precomputation.t,&out->domain.XY0);
    }
    else
    {
        // fp2_t xB_inv,zC_inv,tD_inv;
        // xA_inv = TT1.x;
        // zA_inv = TT2.x;
        // tB_inv = TT2.y;
        // xB_inv=TT1.y;
        // zC_inv=TT2.z;
        // tD_inv=TT2.t;
        // fp2_t invs[3];

        // fp2_copy(&invs[0],&xA_inv);
        // fp2_copy(&invs[1],&zA_inv);
        // fp2_copy(&invs[2],&tB_inv);
        // // fp2_copy(&invs[3],&xB_inv);
        // // fp2_copy(&invs[4],&zC_inv);
        // // fp2_copy(&invs[5],&tD_inv);
        // fp2_batched_inv(invs,3);
        // fp2_copy(&xA_inv,&invs[0]);
        // fp2_copy(&zA_inv,&invs[1]);
        // fp2_copy(&tB_inv,&invs[2]);
        // fp2_copy(&xB_inv,&invs[3]);
        // fp2_copy(&zC_inv,&invs[4]);
        // fp2_copy(&tD_inv,&invs[5]);

        fp2_mul(&out->codomain.null_point.x, &TT2.x, &TT2.y);
        fp2_mul(&out->codomain.null_point.y, &out->codomain.null_point.x, &TT1.y);
        fp2_mul(&out->codomain.null_point.x, &out->codomain.null_point.x, &TT1.x);
        fp2_mul(&out->codomain.null_point.z, &TT2.z, &TT1.x);
        fp2_mul(&out->codomain.null_point.z, &out->codomain.null_point.z, &TT2.y);
        fp2_mul(&out->codomain.null_point.t, &TT2.t, &TT2.x);
        fp2_mul(&out->codomain.null_point.t, &out->codomain.null_point.t, &TT1.y);

        // fp2_sett(&out->codomain.null_point.x,1);

        // // computation of B,C,D for the codomain
        // fp2_mul(&out->codomain.null_point.y,&xA_inv,&TT1.y);
        // fp2_mul(&out->codomain.null_point.z,&zA_inv,&TT2.z);
        // fp2_mul(&out->codomain.null_point.t,&tB_inv,&TT2.t);
        // fp2_mul(&out->codomain.null_point.t,&out->codomain.null_point.t,&out->codomain.null_point.y);

        // computation of B_inv,C_inv,D_inv for the precomputation
        // fp2_sett(&out->precomputation.x,1);
        // fp2_mul(&out->precomputation.y,&xB_inv,&TT1.x);
        // fp2_mul(&out->precomputation.z,&zC_inv,&TT2.x);
        // fp2_mul(&out->precomputation.t,&tD_inv,&TT2.y);
        // fp2_mul(&out->precomputation.t,&out->precomputation.t,&out->precomputation.y);

        fp2_mul(&out->precomputation.x, &TT2.t, &TT2.z);
        fp2_mul(&out->precomputation.y, &out->precomputation.x, &TT1.x);
        fp2_mul(&out->precomputation.x, &out->precomputation.x, &TT1.y);
        fp2_mul(&out->precomputation.z, &TT2.x, &TT1.y);
        fp2_mul(&out->precomputation.z, &out->precomputation.z, &TT2.t);
        fp2_mul(&out->precomputation.t, &TT2.z, &TT2.y);
        fp2_mul(&out->precomputation.t, &out->precomputation.t, &TT1.x);
    }
    if (bool2)
    {
        hadamard(&out->codomain.null_point, &out->codomain.null_point);
    }
}

/**
 * @brief Compute a (2,2) isogeny when only the 4 torsion above the kernel is known and not the 8
 * torsion
 *
 * @param out Output: the theta_isogeny
 * @param A a theta null point for the domain
 * @param T1_4 a point in A[4]
 * @param T2_4 a point in A[4]
 * @param bool1 a boolean
 * @param boo2 a boolean
 *
 * out : A -> B of kernel [2](T1_4,T2_4)
 * bool1 controls if the domain is in standard or dual coordinates
 * bool2 controls if the codomain is in standard or dual coordinates
 *
 */
void theta_isogeny_comput4(theta_isogeny_t *out,
                           const theta_structure_t *A,
                           const theta_point_t *T1_4,
                           const theta_point_t *T2_4,
                           int bool1,
                           int bool2)
{

    out->bool1 = bool1;
    out->bool2 = bool2;
    out->domain = *A;
    out->T1_8 = *T1_4;
    out->T2_8 = *T2_4;
    out->codomain.precomputation = 0;

    theta_point_t TT1, TT2;
    // we will compute:
    // TT1 = (xAB, _ , xCD, _)
    // TT2 = (AA,BB,CC,DD)

    // fp2_t xA_inv,zA_inv,tB_inv;

    if (bool1)
    {

        hadamard(&TT1, T1_4);
        to_squared_theta(&TT1, &TT1);

        hadamard(&TT2, &A->null_point);
        to_squared_theta(&TT2, &TT2);
    }
    else
    {
        to_squared_theta(&TT1, T1_4);
        to_squared_theta(&TT2, &A->null_point);
    }

    fp2_t sqaabb, sqaacc;
    fp2_mul(&sqaabb, &TT2.x, &TT2.y);
    fp2_mul(&sqaacc, &TT2.x, &TT2.z);
    // sqaabb = sqrt(AA*BB)
    fp2_sqrt(&sqaabb);
    // sqaacc = sqrt(AA*CC)
    fp2_sqrt(&sqaacc);

    // we compute out->codomain.null_point = (xAB * sqaacc * AA, xAB *sqaabb *sqaacc, xCD*sqaabb *
    // AA) out->precomputation = (xAB * BB * CC *DD , sqaabb * CC * DD * xAB , sqaacc * BB* DD * xAB
    // , xCD * sqaabb *sqaacc * BB)

    fp2_mul(&out->codomain.null_point.y, &sqaabb, &sqaacc);
    fp2_mul(&out->precomputation.t, &out->codomain.null_point.y, &TT1.z);
    fp2_mul(&out->codomain.null_point.y,
            &out->codomain.null_point.y,
            &TT1.x); // done for out->codomain.null_point.y

    fp2_mul(&out->codomain.null_point.t, &TT1.z, &sqaabb);
    fp2_mul(&out->codomain.null_point.t,
            &out->codomain.null_point.t,
            &TT2.x); // done for out->codomain.null_point.t

    fp2_mul(&out->codomain.null_point.x, &TT1.x, &TT2.x);
    fp2_mul(&out->codomain.null_point.z,
            &out->codomain.null_point.x,
            &TT2.z); // done for out->codomain.null_point.z
    fp2_mul(&out->codomain.null_point.x,
            &out->codomain.null_point.x,
            &sqaacc); // done for out->codomain.null_point.x

    fp2_mul(&out->precomputation.x, &TT1.x, &TT2.t);
    fp2_mul(&out->precomputation.z, &out->precomputation.x, &TT2.y);
    fp2_mul(&out->precomputation.x, &out->precomputation.x, &TT2.z);
    fp2_mul(
        &out->precomputation.y, &out->precomputation.x, &sqaabb); // done for out->precomputation.y
    fp2_mul(
        &out->precomputation.x, &out->precomputation.x, &TT2.y); // done for out->precomputation.x
    fp2_mul(
        &out->precomputation.z, &out->precomputation.z, &sqaacc); // done for out->precomputation.z
    fp2_mul(
        &out->precomputation.t, &out->precomputation.t, &TT2.y); // done for out->precomputation.t

    if (bool2)
    {
        hadamard(&out->codomain.null_point, &out->codomain.null_point);
    }
}

/**
 * @brief Compute a (2,2) isogeny when only the kernel is known and not the 8 or 4 torsion above
 *
 * @param out Output: the theta_isogeny
 * @param A a theta null point for the domain
 * @param T1_2 a point in A[2]
 * @param T2_2 a point in A[2]
 * @param bool1 a boolean
 * @param boo2 a boolean
 *
 * out : A -> B of kernel (T1_2,T2_2)
 * bool1 controls if the domain is in standard or dual coordinates
 * bool2 controls if the codomain is in standard or dual coordinates
 *
 */
void theta_isogeny_comput2(theta_isogeny_t *out,
                           const theta_structure_t *A,
                           const theta_point_t *T1_2,
                           const theta_point_t *T2_2,
                           int bool1,
                           int bool2)
{

    out->bool1 = bool1;
    out->bool2 = bool2;
    out->domain = *A;
    out->T1_8 = *T1_2;
    out->T2_8 = *T2_2;
    out->codomain.precomputation = 0;

    theta_point_t TT2;
    // we will compute:
    // TT2 = (AA,BB,CC,DD)

    if (bool1)
    {
        hadamard(&TT2, &A->null_point);
        to_squared_theta(&TT2, &TT2);
    }
    else
    {
        to_squared_theta(&TT2, &A->null_point);
    }

    // we compute out->codomain.null_point = (AA,sqaabb, sqaacc, sqaadd)
    // out->precomputation = (  BB * CC *DD , sqaabb * CC * DD , sqaacc * BB* DD , sqaadd * BB * CC)
    fp2_copy(&out->codomain.null_point.x, &TT2.x);
    fp2_mul(&out->codomain.null_point.y, &TT2.x, &TT2.y);
    fp2_mul(&out->codomain.null_point.z, &TT2.x, &TT2.z);
    fp2_mul(&out->codomain.null_point.t, &TT2.x, &TT2.t);
    fp2_sqrt(&out->codomain.null_point.y);
    fp2_sqrt(&out->codomain.null_point.z);
    fp2_sqrt(&out->codomain.null_point.t);
    // fp2_neg(&out->codomain.null_point.t,&out->codomain.null_point.t);

    fp2_mul(&out->precomputation.x, &TT2.z, &TT2.t);
    fp2_mul(&out->precomputation.y,
            &out->precomputation.x,
            &out->codomain.null_point.y); // done for out->precomputation.y
    fp2_mul(
        &out->precomputation.x, &out->precomputation.x, &TT2.y); // done for out->precomputation.x
    fp2_mul(&out->precomputation.z, &TT2.t, &out->codomain.null_point.z);
    fp2_mul(
        &out->precomputation.z, &out->precomputation.z, &TT2.y); // done for out->precomputation.z
    fp2_mul(&out->precomputation.t, &TT2.z, &out->codomain.null_point.t);
    fp2_mul(
        &out->precomputation.t, &out->precomputation.t, &TT2.y); // done for out->precomputation.t

    if (bool2)
    {
        hadamard(&out->codomain.null_point, &out->codomain.null_point);
    }
}

/**
 * @brief Evaluate a theta isogeny
 *
 * @param out Output: the evaluating point
 * @param phi a theta isogeny
 * @param P a point in the domain of phi
 *
 * out = phi(P)
 *
 */
void theta_isogeny_eval(theta_point_t *out, const theta_isogeny_t *phi, const theta_point_t *P)
{
    if (phi->bool1)
    {
        hadamard(out, P);
        to_squared_theta(out, out);
    }
    else
    {
        to_squared_theta(out, P);
    }
    fp2_mul(&out->x, &out->x, &phi->precomputation.x);
    fp2_mul(&out->y, &out->y, &phi->precomputation.y);
    fp2_mul(&out->z, &out->z, &phi->precomputation.z);
    fp2_mul(&out->t, &out->t, &phi->precomputation.t);

    if (phi->bool2)
    {
        hadamard(out, out);
    }
}

void apply_isomorphism(theta_point_t *res, const theta_splitting_t *out, const theta_point_t *P)
{

    theta_point_t temp;

    fp2_t x1;
    fp2_mul(&temp.x, &P->x, &out->M00);
    fp2_mul(&x1, &P->y, &out->M01);
    fp2_add(&temp.x, &temp.x, &x1);
    fp2_mul(&x1, &P->z, &out->M02);
    fp2_add(&temp.x, &temp.x, &x1);
    fp2_mul(&x1, &P->t, &out->M03);
    fp2_add(&temp.x, &temp.x, &x1);

    fp2_mul(&temp.y, &P->x, &out->M10);
    fp2_mul(&x1, &P->y, &out->M11);
    fp2_add(&temp.y, &temp.y, &x1);
    fp2_mul(&x1, &P->z, &out->M12);
    fp2_add(&temp.y, &temp.y, &x1);
    fp2_mul(&x1, &P->t, &out->M13);
    fp2_add(&temp.y, &temp.y, &x1);

    fp2_mul(&temp.z, &P->x, &out->M20);
    fp2_mul(&x1, &P->y, &out->M21);
    fp2_add(&temp.z, &temp.z, &x1);
    fp2_mul(&x1, &P->z, &out->M22);
    fp2_add(&temp.z, &temp.z, &x1);
    fp2_mul(&x1, &P->t, &out->M23);
    fp2_add(&temp.z, &temp.z, &x1);

    fp2_mul(&temp.t, &P->x, &out->M30);
    fp2_mul(&x1, &P->y, &out->M31);
    fp2_add(&temp.t, &temp.t, &x1);
    fp2_mul(&x1, &P->z, &out->M32);
    fp2_add(&temp.t, &temp.t, &x1);
    fp2_mul(&x1, &P->t, &out->M33);
    fp2_add(&temp.t, &temp.t, &x1);

    fp2_copy(&res->x, &temp.x);
    fp2_copy(&res->y, &temp.y);
    fp2_copy(&res->z, &temp.z);
    fp2_copy(&res->t, &temp.t);
}

/**
 * @brief Compute the splitting isomorphism from a theta structure to the product theta structure,
 * returns false if the given theta structure is not isomorphic to an elliptic product
 *
 * @return a boolean indicating if A is isomorphic to an elliptic product
 * @param out: the splitting isomorphism
 * @param A : the theta_structure in consideration
 *
 * out : A -> B where B is theta product associated to ExF an elliptic product
 */
int splitting_comput(theta_splitting_t *out, const theta_structure_t *A)
{
    // init
    int good = 0;
    int even_index[10][2] = {
        {0, 0},
        {0, 1},
        {0, 2},
        {0, 3},
        {1, 0},
        {1, 2},
        {2, 0},
        {2, 1},
        {3, 0},
        {3, 3}};
    int chi_eval[4][4] = {
        {1, 1, 1, 1},
        {1, -1, 1, -1},
        {1, 1, -1, -1},
        {1, -1, -1, 1}};

    fp2_t U_cst, temp, temp2;

    // enumerate through all indices
    for (int i = 0; i < 10; i++)
    {
        fp2_sett(&U_cst, 0);
        for (int t = 0; t < 4; t++)
        {
            choose_index_theta_point(&temp2, t, &A->null_point);
            choose_index_theta_point(&temp, t ^ even_index[i][1], &A->null_point);
            fp2_mul(&temp, &temp, &temp2);
            fp2_sett(&temp2, chi_eval[even_index[i][0]][t]);
            fp2_mul(&temp, &temp, &temp2);
            fp2_add(&U_cst, &U_cst, &temp);
        }
        if (fp2_is_zero(&U_cst))
        {
            good = 1 + i;
            break;
        }
    }

    // temp = sqrt{-1}
    // TODO precompute this?
    fp2_sett(&temp, -1);
    fp2_sqrt(&temp);

    // compute the matrix
    if (good == 1)
    {
        // (0, 0): [1, i, 1, i,
        //          1, -i, -1, i,
        //          1, i, -1, -i,
        //          -1, i, -1, i],
        fp2_sett(&out->M00, 1);
        fp2_copy(&out->M01, &temp);
        fp2_sett(&out->M02, 1);
        fp2_copy(&out->M03, &temp);
        fp2_sett(&out->M10, 1);
        fp2_neg(&out->M11, &temp);
        fp2_sett(&out->M12, -1);
        fp2_copy(&out->M13, &temp);
        fp2_sett(&out->M20, 1);
        fp2_copy(&out->M21, &temp);
        fp2_neg(&out->M23, &temp);
        fp2_sett(&out->M22, -1);
        fp2_sett(&out->M30, -1);
        fp2_copy(&out->M31, &temp);
        fp2_sett(&out->M32, -1);
        fp2_copy(&out->M33, &temp);
    }
    else if (good == 2)
    {
        // (0, 1): [1, 0, 0, 0,
        //          0, 0, 0, 1,
        //          0, 0, 1, 0,
        //          0, -1, 0, 0],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 0);
        fp2_sett(&out->M02, 0);
        fp2_sett(&out->M03, 0);
        fp2_sett(&out->M10, 0);
        fp2_sett(&out->M11, 0);
        fp2_sett(&out->M12, 0);
        fp2_sett(&out->M13, 1);
        fp2_sett(&out->M20, 0);
        fp2_sett(&out->M21, 0);
        fp2_sett(&out->M22, 1);
        fp2_sett(&out->M23, 0);
        fp2_sett(&out->M30, 0);
        fp2_sett(&out->M31, -1);
        fp2_sett(&out->M32, 0);
        fp2_sett(&out->M33, 0);
    }
    else if (good == 3)
    {
        // (0, 2): [1, 0, 0, 0,
        //          0, 1, 0, 0,
        //          0, 0, 0, 1,
        //      0, 0, -1, 0],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 0);
        fp2_sett(&out->M02, 0);
        fp2_sett(&out->M03, 0);
        fp2_sett(&out->M10, 0);
        fp2_sett(&out->M11, 1);
        fp2_sett(&out->M12, 0);
        fp2_sett(&out->M13, 0);
        fp2_sett(&out->M20, 0);
        fp2_sett(&out->M21, 0);
        fp2_sett(&out->M22, 0);
        fp2_sett(&out->M23, 1);
        fp2_sett(&out->M30, 0);
        fp2_sett(&out->M31, 0);
        fp2_sett(&out->M32, -1);
        fp2_sett(&out->M33, 0);
    }
    else if (good == 4)
    {
        // (0, 3): [1, 0, 0, 0,
        //          0, 1, 0, 0,
        //          0, 0, 1, 0,
        //          0, 0, 0, -1],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 0);
        fp2_sett(&out->M02, 0);
        fp2_sett(&out->M03, 0);
        fp2_sett(&out->M10, 0);
        fp2_sett(&out->M11, 1);
        fp2_sett(&out->M12, 0);
        fp2_sett(&out->M13, 0);
        fp2_sett(&out->M20, 0);
        fp2_sett(&out->M21, 0);
        fp2_sett(&out->M22, 1);
        fp2_sett(&out->M23, 0);
        fp2_sett(&out->M30, 0);
        fp2_sett(&out->M31, 0);
        fp2_sett(&out->M32, 0);
        fp2_sett(&out->M33, -1);
    }
    else if (good == 7)
    {
        // (2, 0): [1, 1, 1, 1,
        //          1, -1, 1, -1,
        //          1, -1, -1, 1,
        //          -1, -1, 1, 1],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 1);
        fp2_sett(&out->M02, 1);
        fp2_sett(&out->M03, 1);
        fp2_sett(&out->M10, 1);
        fp2_sett(&out->M11, -1);
        fp2_sett(&out->M12, 1);
        fp2_sett(&out->M13, -1);
        fp2_sett(&out->M20, 1);
        fp2_sett(&out->M21, -1);
        fp2_sett(&out->M22, -1);
        fp2_sett(&out->M23, 1);
        fp2_sett(&out->M30, -1);
        fp2_sett(&out->M31, -1);
        fp2_sett(&out->M32, 1);
        fp2_sett(&out->M33, 1);
    }
    else if (good == 8)
    {
        //(2, 1): [1, 1, 1, 1,
        //          1, -1, 1, -1,
        //          1, -1, -1, 1,
        //          1, 1, -1, -1],

        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 1);
        fp2_sett(&out->M02, 1);
        fp2_sett(&out->M03, 1);
        fp2_sett(&out->M10, 1);
        fp2_sett(&out->M11, -1);
        fp2_sett(&out->M12, 1);
        fp2_sett(&out->M13, -1);
        fp2_sett(&out->M20, 1);
        fp2_sett(&out->M21, -1);
        fp2_sett(&out->M22, -1);
        fp2_sett(&out->M23, 1);
        fp2_sett(&out->M30, 1);
        fp2_sett(&out->M31, 1);
        fp2_sett(&out->M32, -1);
        fp2_sett(&out->M33, -1);
    }
    else if (good == 5)
    {
        // (1, 0): [1, 1, 1, 1,
        //          1, -1, -1, 1,
        //          1, 1, -1, -1,
        //          -1, 1, -1, 1],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 1);
        fp2_sett(&out->M02, 1);
        fp2_sett(&out->M03, 1);
        fp2_sett(&out->M10, 1);
        fp2_sett(&out->M11, -1);
        fp2_sett(&out->M12, -1);
        fp2_sett(&out->M13, 1);
        fp2_sett(&out->M20, 1);
        fp2_sett(&out->M21, 1);
        fp2_sett(&out->M22, -1);
        fp2_sett(&out->M23, -1);
        fp2_sett(&out->M30, -1);
        fp2_sett(&out->M31, 1);
        fp2_sett(&out->M32, -1);
        fp2_sett(&out->M33, 1);
    }
    else if (good == 6)
    {
        //(1, 2): [1, 0, 0, 0,
        //          0, 1, 0, 0,
        //          0, 0, 0, 1,
        //          0, 0, 1, 0],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 0);
        fp2_sett(&out->M02, 0);
        fp2_sett(&out->M03, 0);
        fp2_sett(&out->M10, 0);
        fp2_sett(&out->M11, 1);
        fp2_sett(&out->M12, 0);
        fp2_sett(&out->M13, 0);
        fp2_sett(&out->M20, 0);
        fp2_sett(&out->M21, 0);
        fp2_sett(&out->M22, 0);
        fp2_sett(&out->M23, 1);
        fp2_sett(&out->M30, 0);
        fp2_sett(&out->M31, 0);
        fp2_sett(&out->M32, 1);
        fp2_sett(&out->M33, 0);
    }
    else if (good == 9)
    {
        // (3, 0): [1, 1, 1, 1,
        //          1, -1, 1, -1,
        //          1, 1, -1, -1,
        //          -1, 1, 1, -1],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 1);
        fp2_sett(&out->M02, 1);
        fp2_sett(&out->M03, 1);
        fp2_sett(&out->M10, 1);
        fp2_sett(&out->M11, -1);
        fp2_sett(&out->M12, 1);
        fp2_sett(&out->M13, -1);
        fp2_sett(&out->M20, 1);
        fp2_sett(&out->M21, 1);
        fp2_sett(&out->M22, -1);
        fp2_sett(&out->M23, -1);
        fp2_sett(&out->M30, -1);
        fp2_sett(&out->M31, 1);
        fp2_sett(&out->M32, 1);
        fp2_sett(&out->M33, -1);
    }
    else if (good == 10)
    {
        // (3, 3): [1, 0, 0, 0,
        //          0, 1, 0, 0,
        //          0, 0, 1, 0,
        //          0, 0, 0, 1],
        fp2_sett(&out->M00, 1);
        fp2_sett(&out->M01, 0);
        fp2_sett(&out->M02, 0);
        fp2_sett(&out->M03, 0);
        fp2_sett(&out->M10, 0);
        fp2_sett(&out->M11, 1);
        fp2_sett(&out->M12, 0);
        fp2_sett(&out->M13, 0);
        fp2_sett(&out->M20, 0);
        fp2_sett(&out->M21, 0);
        fp2_sett(&out->M22, 1);
        fp2_sett(&out->M23, 0);
        fp2_sett(&out->M30, 0);
        fp2_sett(&out->M31, 0);
        fp2_sett(&out->M32, 0);
        fp2_sett(&out->M33, 1);
    }

    // now we apply the isomorphism if it was computed
    if (good)
    {
        apply_isomorphism(&out->B.null_point, out, &A->null_point);
    }
    return good;
}

void theta_product_structure_to_elliptic_product(theta_couple_curve_t *E12, theta_structure_t *A)
{
    fp2_t xx, yy, temp1, temp2;

    ec_curve_init(&(E12->E1));
    ec_curve_init(&(E12->E2));

    // xx = x², yy = y²
    fp2_sqr(&xx, &A->null_point.x);
    fp2_sqr(&yy, &A->null_point.y);

    // A1 = ( (xx² + yy²)² + (xx² - yy²)² )  / (xx² - yy²)
    fp2_add(&temp1, &xx, &yy);
    fp2_sub(&temp2, &xx, &yy);
    fp2_mul(&E12->E1.C, &temp1, &temp2);
    fp2_sqr(&temp1, &temp1);
    fp2_sqr(&temp2, &temp2);
    fp2_add(&temp1, &temp1, &temp2);
    // TODO fix this!
    fp2_sett(&E12->E1.A, 1);
    fp2_mul(&E12->E1.A, &E12->E1.A, &temp1);
    fp2_neg(&E12->E1.A, &E12->E1.A);
    // fp2_sett(&E12->E1.C,1);

    // same with y,t
    fp2_sqr(&xx, &A->null_point.y);
    fp2_sqr(&yy, &A->null_point.t);

    // A2 = ( (xx² + yy²)² + (xx² - yy²)² )  / (xx² - yy²)
    fp2_add(&temp1, &xx, &yy);
    fp2_sub(&temp2, &xx, &yy);
    fp2_mul(&E12->E2.C, &temp1, &temp2);
    fp2_sqr(&temp1, &temp1);
    fp2_sqr(&temp2, &temp2);
    fp2_add(&temp1, &temp1, &temp2);
    fp2_sett(&E12->E2.A, 1);
    fp2_mul(&E12->E2.A, &E12->E2.A, &temp1);
    fp2_neg(&E12->E2.A, &E12->E2.A);
}

/**
 * @brief Compute  a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the theta_chain
 * @param n : the length of the isogeny chain
 * @param E12 an elliptic curve product
 * @param T1 a couple point on E12[2^(n+2)]
 * @param T2 a couple point on E12[2^(n+2)]
 * @param T1m2 a couple point on E12[2^(n+2)] equal to T1-T2
 *
 * out : E1xE2 -> E3xE4 of kernel [4](T1,T2)
 *
 */
void theta_chain_comput_strategy(theta_chain_t *out,
                                 int n,
                                 theta_couple_curve_t *E12,
                                 const theta_couple_point_t *T1,
                                 const theta_couple_point_t *T2,
                                 const theta_couple_point_t *T1m2,
                                 int *strategy,
                                 int eight_above)
{
    theta_couple_point_t P1, P2, P1m2;
    theta_point_t R1, R2;
    theta_isogeny_t steps[n - 1];
    theta_structure_t codomain;

    // init of the isogeny chain
    out->domain = *E12;
    out->length = n;
    out->T1 = *T1;
    out->T2 = *T2;
    out->steps = malloc((n - 1) * sizeof(theta_isogeny_t));

    // lift the basis
    theta_couple_jac_point_t xyT1, xyT2, xyK1, xyK2;
    ec_basis_t bas1, bas2;
    copy_point(&bas1.P, &T1->P1);
    copy_point(&bas1.Q, &T2->P1);
    copy_point(&bas1.PmQ, &T1m2->P1);

    copy_point(&bas2.P, &T1->P2);
    copy_point(&bas2.Q, &T2->P2);
    copy_point(&bas2.PmQ, &T1m2->P2);

    if (eight_above)
    {
        assert(test_point_order_twof(&bas2.P, &E12->E2, n + 2));
    }
    else
    {
        assert(test_point_order_twof(&bas2.P, &E12->E2, n));
    }

    lift_basis(&xyT1.P1, &xyT2.P1, &bas1, &E12->E1);
    lift_basis(&xyT1.P2, &xyT2.P2, &bas2, &E12->E2);
    if (eight_above)
    {
        assert(test_jac_order_twof(&xyT1.P2, &E12->E2, n + 2));
    }
    else
    {
        assert(test_jac_order_twof(&xyT1.P2, &E12->E2, n));
    }

    int adjusting = 2 * (1 - eight_above);
    assert((eight_above && adjusting == 0) || (!eight_above && adjusting == 2));

    // prepare the points for the first step
    // first we must compute the length of the list
    int len_count = 0;
    int index = 0;
    while (len_count != n - 1 - adjusting && index < n + 10)
    {
        len_count = len_count + strategy[index];
        index++;
    }
    int len_list = index + 1;

    theta_couple_jac_point_t points1[n];
    theta_couple_jac_point_t points2[n];
    theta_point_t Q1[n];
    theta_point_t Q2[n];
    int level[n];

    // the first point
    copy_jac_point(&points1[0].P1, &xyT1.P1);
    copy_jac_point(&points1[0].P2, &xyT1.P2);
    copy_jac_point(&points2[0].P1, &xyT2.P1);
    copy_jac_point(&points2[0].P2, &xyT2.P2);
    level[0] = 0;
    // and then the rest
    for (int i = 1; i < len_list; i++)
    {
        double_couple_jac_point_iter(&points1[i], strategy[i - 1], E12, &points1[i - 1]);
        double_couple_jac_point_iter(&points2[i], strategy[i - 1], E12, &points2[i - 1]);
        level[i] = strategy[i - 1];
    }

    // prepare the kernel of the first step
    copy_jac_point(&xyK1.P1, &points1[len_list - 1].P1);
    copy_jac_point(&xyK1.P2, &points1[len_list - 1].P2);
    copy_jac_point(&xyK2.P1, &points2[len_list - 1].P1);
    copy_jac_point(&xyK2.P2, &points2[len_list - 1].P2);

    assert(test_jac_order_twof(&xyK1.P2, &E12->E2, 3));
    assert(test_jac_order_twof(&xyK2.P2, &E12->E2, 3));

    // compute the gluing isogeny
    gluing_comput(&out->first_step, E12, &xyK1, &xyK2);

    // set-up the theta_structure for the first codomain
    codomain.null_point = out->first_step.codomain;
    codomain.precomputation = 0;
    theta_precomputation(&codomain);

    len_list--;

    // push the kernel through the gluing isogeny
    // need to setup the input before
    for (int i = 0; i < len_list; i++)
    {
        gluing_eval_basis(&Q1[i], &Q2[i], &points1[i], &points2[i], E12, &out->first_step);
    }
    // and now we do the remaining steps
    for (int i = 0; i < n - 1 - adjusting; i++)
    {

        len_count = 0;
        for (int j = 0; j < len_list; j++)
        {
            len_count = len_count + level[j];
        }
        while (len_count != n - i - 2 - adjusting)
        {
            len_count = len_count + strategy[index];
            double_iter(&Q1[len_list], &codomain, &Q1[len_list - 1], strategy[index]);
            double_iter(&Q2[len_list], &codomain, &Q2[len_list - 1], strategy[index]);
            level[len_list] = strategy[index];
            index++;
            len_list++;
        }

        // computing the kernel of the next step
        // double_iter(&R1,&codomain,&Q1,n-i-2);
        // double_iter(&R2,&codomain,&Q2,n-i-2);
        // TODO : proper copying here ?
        R1 = Q1[len_list - 1];
        R2 = Q2[len_list - 1];

        // computing the next step
        if (i == n - 3)
        {
            if (eight_above)
            {
                theta_isogeny_comput(&out->steps[i], &codomain, &R1, &R2, 0, 0);
            }
        }
        else if (i == n - 2)
        {
            if (eight_above)
            {
                theta_isogeny_comput(&out->steps[i], &codomain, &R1, &R2, 1, 0);
            }
        }
        else
        {
            theta_isogeny_comput(&out->steps[i], &codomain, &R1, &R2, 0, 1);
        }
        // updating the codomain
        codomain = out->steps[i].codomain;

        len_list--;

        // pushing the kernel
        if (i < n - 2)
        {
            for (int j = 0; j < len_list; j++)
            {
                theta_isogeny_eval(&Q1[j], &out->steps[i], &Q1[j]);
                theta_isogeny_eval(&Q2[j], &out->steps[i], &Q2[j]);
            }
        }
    }

    if (!eight_above)
    {
        // the last two steps are done here
        R1 = Q1[0];
        R2 = Q2[0];
        theta_isogeny_eval(&R1, &out->steps[n - 4], &R1);
        theta_isogeny_eval(&R2, &out->steps[n - 4], &R2);
        theta_isogeny_comput4(&out->steps[n - 3], &codomain, &R1, &R2, 0, 0);
        codomain = out->steps[n - 3].codomain;
        theta_isogeny_eval(&R1, &out->steps[n - 3], &R1);
        theta_isogeny_eval(&R2, &out->steps[n - 3], &R2);
        theta_isogeny_comput2(&out->steps[n - 2], &codomain, &R1, &R2, 1, 0);
        codomain = out->steps[n - 2].codomain;
    }

    // final splitting step
    int is_split = splitting_comput(&out->last_step, &out->steps[n - 2].codomain);
    assert(is_split);

    // computing the curves of the codomain
    theta_product_structure_to_elliptic_product(&out->codomain, &out->last_step.B);
}

void theta_chain_comput_strategy_faster_no_eval(theta_chain_t *out,
                                                int n,
                                                theta_couple_curve_t *E12,
                                                const theta_couple_point_t *T1,
                                                const theta_couple_point_t *T2,
                                                const theta_couple_point_t *T1m2,
                                                int *strategy,
                                                int eight_above)
{

    theta_point_t R1, R2;
    theta_isogeny_t steps[n - 1];
    theta_structure_t codomain;

    // init of the isogeny chain
    out->domain = *E12;
    out->length = n;
    out->T1 = *T1;
    out->T2 = *T2;
    out->steps = malloc((n - 1) * sizeof(theta_isogeny_t));

    // lift the basis
    theta_couple_jac_point_t xyT1, xyT2, xyK1, xyK2;
    ec_basis_t bas1, bas2;
    copy_point(&bas1.P, &T1->P1);
    copy_point(&bas1.Q, &T2->P1);
    copy_point(&bas1.PmQ, &T1m2->P1);

    copy_point(&bas2.P, &T1->P2);
    copy_point(&bas2.Q, &T2->P2);
    copy_point(&bas2.PmQ, &T1m2->P2);

    if (eight_above)
    {
        assert(test_point_order_twof(&bas2.P, &E12->E2, n + 2));
    }
    else
    {
        assert(test_point_order_twof(&bas2.P, &E12->E2, n));
    }

    // t = tic();
    lift_basis(&xyT1.P1, &xyT2.P1, &bas1, &E12->E1);
    lift_basis(&xyT1.P2, &xyT2.P2, &bas2, &E12->E2);
    if (eight_above)
    {
        assert(test_jac_order_twof(&xyT1.P2, &E12->E2, n + 2));
    }
    else
    {
        assert(test_jac_order_twof(&xyT1.P2, &E12->E2, n));
    }

    int adjusting = 2 * (1 - eight_above);
    assert((eight_above && adjusting == 0) || (!eight_above && adjusting == 2));

    // prepare the points for the first step
    // first we must compute the length of the list
    int len_count = 0;
    int index = 0;
    while (len_count != n - 1 - adjusting && index < n + 10)
    {
        len_count = len_count + strategy[index];
        index++;
    }
    int len_list = index + 1;

    theta_couple_jac_point_t points1[n];
    theta_couple_jac_point_t points2[n];
    theta_point_t Q1[n];
    theta_point_t Q2[n];
    int level[n];

    // the first point
    copy_jac_point(&points1[0].P1, &xyT1.P1);
    copy_jac_point(&points1[0].P2, &xyT1.P2);
    copy_jac_point(&points2[0].P1, &xyT2.P1);
    copy_jac_point(&points2[0].P2, &xyT2.P2);
    level[0] = 0;
    // and then the rest
    for (int i = 1; i < len_list; i++)
    {
        double_couple_jac_point_iter(&points1[i], strategy[i - 1], E12, &points1[i - 1]);
        double_couple_jac_point_iter(&points2[i], strategy[i - 1], E12, &points2[i - 1]);
        level[i] = strategy[i - 1];
    }

    // prepare the kernel of the first step
    copy_jac_point(&xyK1.P1, &points1[len_list - 1].P1);
    copy_jac_point(&xyK1.P2, &points1[len_list - 1].P2);
    copy_jac_point(&xyK2.P1, &points2[len_list - 1].P1);
    copy_jac_point(&xyK2.P2, &points2[len_list - 1].P2);

    assert(test_jac_order_twof(&xyK1.P2, &E12->E2, 3));
    assert(test_jac_order_twof(&xyK1.P1, &E12->E1, 3));

    // compute the gluing isogeny
    gluing_comput(&out->first_step, E12, &xyK1, &xyK2);

    // set-up the theta_structure for the first codomain
    codomain.null_point = out->first_step.codomain;
    codomain.precomputation = 0;
    theta_precomputation(&codomain);

    len_list--;

    // push the kernel through the gluing isogeny
    // need to setup the input before
    for (int i = 0; i < len_list; i++)
    {
        gluing_eval_basis(&Q1[i], &Q2[i], &points1[i], &points2[i], E12, &out->first_step);
    }
    // and now we do the remaining steps

    for (int i = 0; i < n - 1 - adjusting; i++)
    {

        len_count = 0;
        for (int j = 0; j < len_list; j++)
        {
            len_count = len_count + level[j];
        }
        while (len_count != n - i - 2 - adjusting)
        {
            len_count = len_count + strategy[index];
            double_iter(&Q1[len_list], &codomain, &Q1[len_list - 1], strategy[index]);
            double_iter(&Q2[len_list], &codomain, &Q2[len_list - 1], strategy[index]);
            level[len_list] = strategy[index];
            index++;
            len_list++;
        }

        // computing the kernel of the next step
        // double_iter(&R1,&codomain,&Q1,n-i-2);
        // double_iter(&R2,&codomain,&Q2,n-i-2);
        // TODO : proper copying here ?
        R1 = Q1[len_list - 1];
        R2 = Q2[len_list - 1];

        // computing the next step
        if (i == n - 3)
        {
            if (eight_above)
            {
                theta_isogeny_comput(&out->steps[i], &codomain, &R1, &R2, 0, 0);
            }
        }
        else if (i == n - 2)
        {
            if (eight_above)
            {
                theta_isogeny_comput(&out->steps[i], &codomain, &R1, &R2, 1, 0);
            }
        }
        else
        {
            theta_isogeny_comput(&out->steps[i], &codomain, &R1, &R2, 0, 1);
        }
        // updating the codomain
        codomain = out->steps[i].codomain;

        len_list--;

        // pushing the kernel
        if (i < n - 2)
        {
            for (int j = 0; j < len_list; j++)
            {
                theta_isogeny_eval(&Q1[j], &out->steps[i], &Q1[j]);
                theta_isogeny_eval(&Q2[j], &out->steps[i], &Q2[j]);
            }
        }
    }

    if (!eight_above)
    {
        // the last two steps are done here
        R1 = Q1[0];
        R2 = Q2[0];
        theta_isogeny_eval(&R1, &out->steps[n - 4], &R1);
        theta_isogeny_eval(&R2, &out->steps[n - 4], &R2);
        theta_isogeny_comput4(&out->steps[n - 3], &codomain, &R1, &R2, 0, 0);
        codomain = out->steps[n - 3].codomain;
        theta_isogeny_eval(&R1, &out->steps[n - 3], &R1);
        theta_isogeny_eval(&R2, &out->steps[n - 3], &R2);
        theta_isogeny_comput2(&out->steps[n - 2], &codomain, &R1, &R2, 1, 0);
        codomain = out->steps[n - 2].codomain;
    }

    // final splitting step
    int is_split = splitting_comput(&out->last_step, &out->steps[n - 2].codomain);
    assert(is_split);

    // computing the curves of the codomain
    theta_product_structure_to_elliptic_product(&out->codomain, &out->last_step.B);
}

void theta_point_to_montgomery_point(theta_couple_point_t *P12,
                                     const theta_point_t *P,
                                     const theta_structure_t *A)
{

    fp2_t temp;

    // P1.X = A.null_point.y * P.x + A.null_point.x * P.y
    // P1.Z = - A.null_point.y * P.x + A.null_point.x * P.y
    fp2_mul(&P12->P1.x, &A->null_point.y, &P->x);
    fp2_mul(&temp, &A->null_point.x, &P->y);
    fp2_sub(&P12->P1.z, &temp, &P12->P1.x);
    fp2_add(&P12->P1.x, &P12->P1.x, &temp);

    // P2.X = A.null_point.t * P.y + A.null_point.y * P.t
    // P2.Z = A.null_point.t * P.y - A.null_point.y * P.t
    fp2_mul(&P12->P2.x, &A->null_point.t, &P->y);
    fp2_mul(&temp, &A->null_point.y, &P->t);
    fp2_sub(&P12->P2.z, &temp, &P12->P2.x);
    fp2_add(&P12->P2.x, &P12->P2.x, &temp);
}

/**
 * @brief Evaluate a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the image point
 * @param phi : the (2,2) isogeny chain of domain E12
 * @param P12 a couple point on E12,
 * @param Help a couple point on E12
 *
 * phi : E1xE2 -> E3xE4 of kernel
 * P12 in E1xE2
 * out = phi(P12) in E3xE4
 * Help is equal to phi.first_step.K1_4 + P12
 *
 */
void theta_chain_eval(theta_couple_point_t *out,
                      theta_chain_t *phi,
                      theta_couple_point_t *P12,
                      const theta_couple_point_t *Help)
{
    theta_point_t temp;

    theta_couple_jac_point_t jac_help;

    // first, we apply the gluing
    gluing_eval_point(&temp, P12, Help, &phi->first_step);

    // then, we apply the successive isogenies
    for (int i = 0; i < phi->length - 1; i++)
    {
        theta_isogeny_eval(&temp, &phi->steps[i], &temp);
    }

    // we send the result to the theta product structure of the codomain
    apply_isomorphism(&temp, &phi->last_step, &temp);

    // finaly the send the result to the elliptic product
    theta_point_to_montgomery_point(out, &temp, &phi->last_step.B);
}

/**
 * @brief Evaluate a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the image point
 * @param phi : the (2,2) isogeny chain of domain E12
 * @param P12 a couple jac point on E12,
 *
 * phi : E1xE2 -> E3xE4 of kernel
 * P12 in E1xE2
 * out = phi(P12) in E3xE4
 *
 */
void theta_chain_eval_no_help(theta_couple_point_t *out,
                              theta_chain_t *phi,
                              theta_couple_jac_point_t *P12,
                              const theta_couple_curve_t *E12)
{

    theta_point_t temp;

    // first, we apply the gluing
    gluing_eval_point_no_help(&temp, P12, E12, &phi->first_step);

    // then, we apply the successive isogenies
    for (int i = 0; i < phi->length - 1; i++)
    {
        theta_isogeny_eval(&temp, &phi->steps[i], &temp);
    }

    // we send the result to the theta product structure of the codomain
    apply_isomorphism(&temp, &phi->last_step, &temp);

    // finaly we send the result to the elliptic product
    theta_point_to_montgomery_point(out, &temp, &phi->last_step.B);
}

/**
 * @brief Evaluate a (2,2) isogeny chain in dimension 2 between elliptic products in the theta_model
 *
 * @param out Output: the image point
 * @param phi : the (2,2) isogeny chain of domain E12
 * @param P12 a couple point on E12 where one of the two point is zero,
 *
 * phi : E1xE2 -> E3xE4 of kernel
 * P12 in E1xE2 with P12 = (P1,0) or (0,P2)
 * out = phi(P12) in E3xE4
 *
 */
void theta_chain_eval_special_case(theta_couple_point_t *out,
                                   theta_chain_t *phi,
                                   theta_couple_point_t *P12,
                                   const theta_couple_curve_t *E12)
{
    theta_point_t temp;

#ifndef NDEBUG
    assert(ec_is_zero(&P12->P1) || ec_is_zero(&P12->P2));
    assert(phi->first_step.zero_idx == 3);
#endif

    // first, we apply the gluing
    gluing_eval_point_special_case(&temp, P12, &phi->first_step);

    // then, we apply the successive isogenies
    for (int i = 0; i < phi->length - 1; i++)
    {
        theta_isogeny_eval(&temp, &phi->steps[i], &temp);
    }

    // we send the result to the theta product structure of the codomain
    apply_isomorphism(&temp, &phi->last_step, &temp);

    // finaly we send the result to the elliptic product
    theta_point_to_montgomery_point(out, &temp, &phi->last_step.B);
}
