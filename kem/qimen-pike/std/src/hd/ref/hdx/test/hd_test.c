#include "hd_test.h"
#include <curve_extras.h>
#include <fp2.h>
#include <fp.h>
#include <stdio.h>
#include <inttypes.h>
#include <tools.h>
#include <ec.h>
#include <id2iso.h>
#include <ec_params.h>

// static void ec_biscalar_mul_ibz(ec_point_t* res, const ec_curve_t* curve,
//     const ibz_t* scalarP, const ibz_t* scalarQ,
//     const ec_basis_t* PQ){

//     digit_t scalars[2][NWORDS_FIELD];
//     ibz_to_digit_array(scalars[0], scalarP);
//     ibz_to_digit_array(scalars[1], scalarQ);
//     ec_biscalar_mul(res, curve, scalars[0], scalars[1], PQ);
// }

// p = 5 * 2^248  − 1
// 2^242 - 3^3 = 903829667792956162913972717352870559^2 + 2500096036301568120095447360260176186^2;

int
hd_chain_test()
{

    // var declaration & init
    ibz_t x, y, tmp, twopow;
    ibz_init(&x);
    ibz_init(&y);
    ibz_init(&tmp);
    ibz_init(&twopow);
    ibz_pow(&twopow, &ibz_const_two, TORSION_PLUS_EVEN_POWER);

    ibz_mat_2x2_t mat;
    ibz_mat_2x2_init(&mat);

    digit_t scalars[2][NWORDS_ORDER] = { 0 };

    ec_curve_t E0, E1;
    ec_basis_t B0_two, B1_two, B0_three;
    ec_isog_odd_t phi;

    ec_curve_init(&E0);
    ec_curve_init(&E1);

#ifndef NDEBUG
    // fp2_test
    fp2_t xx, yy, z;

    fp2_set_one(&xx);
    fp2_set_one(&yy);
    fp2_sub(&xx, &xx, &yy);
    assert(fp2_is_zero(&xx));
    fp2_neg(&xx, &yy);
    fp2_sqr(&xx, &yy);
    assert(fp2_is_equal(&xx, &yy));
    fp2_mul(&xx, &yy, &yy);
    assert(fp2_is_equal(&xx, &yy));

    fp2_t test_i, min;
    fp_set_one(&test_i.im);
    fp_set_zero(&test_i.re);
    fp_set_zero(&min.im);
    fp_set_one(&min.re);
    fp2_mul(&test_i, &test_i, &test_i);
    fp2_add(&test_i, &test_i, &min);
    assert(fp2_is_zero(&test_i));
#endif

    // setting the coefficient
    // ibz_set(&x,903829667792956162913972717352870559);
    // ibz_set(&y,2500096036301568120095447360260176186);

    ibz_set_from_str(&x, "903829667792956162913972717352870559", 10);
    ibz_set_from_str(&y, "2500096036301568120095447360260176186", 10);

    // copying the basis
    copy_point(&B0_two.P, &BASIS_EVEN.P);
    copy_point(&B0_two.Q, &BASIS_EVEN.Q);
    copy_point(&B0_two.PmQ, &BASIS_EVEN.PmQ);

    copy_point(&B0_three.P, &BASIS_THREE.P);
    copy_point(&B0_three.Q, &BASIS_THREE.Q);
    copy_point(&B0_three.PmQ, &BASIS_THREE.PmQ);

    E0 = CURVE_E0;

    // point_print("P1",B0_two.P);
    // point_print("P2",B0_two.Q);
    // point_print("P1m2",B0_two.PmQ);

    printf("%llu \n", TORSION_PLUS_EVEN_POWER);

#ifndef NDEBUG
    assert(test_point_order_twof(&B0_two.P, &E0, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&B0_two.Q, &E0, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&B0_two.PmQ, &E0, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_threef(&B0_three.P, &E0, TORSION_MINUS_ODD_POWERS[0]));
#endif

    ibz_set(&mat[0][0], 0);
    ibz_set(&mat[0][1], 0);
    ibz_set(&mat[1][0], 0);
    ibz_set(&mat[1][1], 0);

    // constructing the matrix corresponding to the endomorphism x + iy
    for (unsigned i = 0; i < 2; ++i) {
        ibz_add(&mat[i][i], &mat[i][i], &x);
        for (unsigned j = 0; j < 2; ++j) {
            ibz_mul(&tmp, &ACTION_GEN2[i][j], &y);
            ibz_add(&mat[i][j], &mat[i][j], &tmp);
            ibz_mod(&mat[i][j], &mat[i][j], &twopow);
        }
    }

    // applying the matrix on the two torsion

    // first basis element
    ibz_to_digit_array(scalars[0], &mat[0][0]);
    // ibz_set(&mat[0][1],0);
    ibz_to_digit_array(scalars[1], &mat[1][0]);

    ec_biscalar_mul(&B1_two.P, &CURVE_E0, scalars[0], scalars[1], &B0_two);
    ibz_to_digit_array(scalars[0], &mat[0][1]);
    ibz_to_digit_array(scalars[1], &mat[1][1]);
    ec_biscalar_mul(&B1_two.Q, &CURVE_E0, scalars[0], scalars[1], &B0_two);

    ibz_sub(&tmp, &mat[0][0], &mat[0][1]);
    ibz_to_digit_array(scalars[0], &tmp);
    ibz_sub(&tmp, &mat[1][0], &mat[1][1]);
    ibz_to_digit_array(scalars[1], &tmp);
    clock_t timing = tic();
    ec_biscalar_mul(&B1_two.PmQ, &CURVE_E0, scalars[0], scalars[1], &B0_two);
    // TOC_clock(timing,"biscalar mul");

    assert(test_point_order_twof(&B1_two.P, &E0, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&B1_two.Q, &E0, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&B1_two.PmQ, &E0, TORSION_PLUS_EVEN_POWER));

    // setting up the isogeny
    phi.curve = E0;
    uint8_t tab[2] = { 0, 3 };
    phi.degree[0] = tab[0];
    phi.degree[1] = tab[1];
    ec_set_zero(&phi.ker_plus);
    // preparating the kernel of phi as a point of 3 torsion
    digit_t three[NWORDS_ORDER] = { 0 };
    three[0] = 3;
    phi.ker_minus = B0_three.P;
    for (int i = 0; i < TORSION_MINUS_ODD_POWERS[0] - 3; i++) {
        ec_mul(&phi.ker_minus, &E0, three, 1, &phi.ker_minus);
    }
    ec_eval_odd_basis(&E1, &phi, &B0_two, 1);

    assert(test_point_order_twof(&B0_two.P, &E1, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&B0_two.Q, &E1, TORSION_PLUS_EVEN_POWER));

    // ready to make the dim 2 computation
    theta_couple_curve_t E01;
    theta_couple_point_t T1;
    theta_couple_point_t T2, T1m2;
    theta_chain_t dimtwo_chain;

    clock_t t;

    // setting the couples
    E01.E1 = E0;
    E01.E2 = E1;
    T1.P1 = B1_two.P;
    T1.P2 = B0_two.P;
    T2.P1 = B1_two.Q;
    T2.P2 = B0_two.Q;
    T1m2.P1 = B1_two.PmQ;
    T1m2.P2 = B0_two.PmQ;

    assert(test_point_order_twof(&T1.P1, &E01.E1, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&T1.P2, &E01.E2, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&T2.P1, &E01.E1, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&T2.P2, &E01.E2, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&T1m2.P1, &E01.E1, TORSION_PLUS_EVEN_POWER));
    assert(test_point_order_twof(&T1m2.P2, &E01.E2, TORSION_PLUS_EVEN_POWER));

#ifndef NDEBUG
    theta_couple_point_t C1, C2;
    C1 = T1;
    C2 = T2;
    double_couple_point_iter(&C1, TORSION_PLUS_EVEN_POWER, &E01, &C1);
    double_couple_point_iter(&C2, TORSION_PLUS_EVEN_POWER, &E01, &C2);
    assert(fp2_is_zero(&C1.P1.z));
    assert(fp2_is_zero(&C1.P2.z));
    assert(fp2_is_zero(&C2.P1.z));
    assert(fp2_is_zero(&C2.P2.z));
#endif

    // multiplying by 16
    double_couple_point_iter(&T1, 4, &E01, &T1);
    double_couple_point_iter(&T2, 4, &E01, &T2);
    double_couple_point_iter(&T1m2, 4, &E01, &T1m2);

    int length = 242;

#ifndef NDEBUG
    // checking that the points have the correct order
    theta_couple_point_t P1, P2;
    P1 = T1;
    P2 = T2;
    double_couple_point_iter(&P1, length + 1, &E01, &P1);
    double_couple_point_iter(&P2, length + 1, &E01, &P2);

    ec_point_t test1, test2;
    test1 = P1.P1;
    test2 = P1.P2;
    assert(!fp2_is_zero(&test1.z));
    assert(!fp2_is_zero(&test2.z));
    ec_dbl(&test1, &E01.E1, &test1);
    ec_dbl(&test2, &E01.E2, &test2);
    assert(fp2_is_zero(&test1.z));
    assert(fp2_is_zero(&test2.z));
    test1 = P2.P1;
    test2 = P2.P2;
    assert(!fp2_is_zero(&test1.z));
    assert(!fp2_is_zero(&test2.z));
    ec_dbl(&test1, &E01.E1, &test1);
    ec_dbl(&test2, &E01.E2, &test2);
    assert(fp2_is_zero(&test1.z));
    assert(fp2_is_zero(&test2.z));
#endif

    t = tic();
    theta_chain_comput_strategy(&dimtwo_chain,
                                length,
                                &E01,
                                &T1,
                                &T2,
                                &T1m2,
                                strategies[TORSION_PLUS_EVEN_POWER - length],
                                1);

    // TOC(t,"chain computation with eight above");
    t = tic();
    theta_chain_t no_sq_chain;
    theta_couple_point_t Ts1, Ts2, Ts1m2;
    double_couple_point_iter(&Ts1, 2, &E01, &T1);
    double_couple_point_iter(&Ts2, 2, &E01, &T2);
    double_couple_point_iter(&Ts1m2, 2, &E01, &T1m2);

    theta_chain_comput_strategy(&no_sq_chain,
                                length,
                                &E01,
                                &Ts1,
                                &Ts2,
                                &Ts1m2,
                                strategies[TORSION_PLUS_EVEN_POWER - length + 2],
                                0);

    theta_couple_point_t FP, Help;
    copy_point(&FP.P1, &T1m2.P1);
    ec_set_zero(&FP.P2);
    ibz_t scal;
    ibz_init(&scal);
    digit_t scal_dig[NWORDS_ORDER] = { 0 };
    ibz_pow(&scal, &ibz_const_two, length);
    ibz_add(&scal, &ibz_const_one, &scal);
    ibz_to_digit_array(scal_dig, &scal);
    ec_mul(&Help.P1, &E0, scal_dig, CHARACTERISTIC->_mp_size, &T1.P1);
    copy_point(&Help.P2, &dimtwo_chain.first_step.K1_4.P2);
    assert(ec_is_equal(&dimtwo_chain.first_step.K1_4.P2, &no_sq_chain.first_step.K1_4.P2));
    assert(ec_is_equal(&dimtwo_chain.first_step.K1_4.P1, &no_sq_chain.first_step.K1_4.P1));
    // assert(is_jac_equal(&dimtwo_chain.first_step.xyK1_4.P2,&no_sq_chain.first_step.xyK1_4.P2));
    // assert(is_jac_equal(&dimtwo_chain.first_step.xyK1_4.P1,&no_sq_chain.first_step.xyK1_4.P1));

    t = tic();
    theta_chain_eval(&FP, &dimtwo_chain, &FP, &Help);
    // TOC_clock(t,"chain eval");

    assert(test_point_order_twof(&FP.P1, &dimtwo_chain.codomain.E1, length + 2));
    assert(test_point_order_twof(&FP.P2, &dimtwo_chain.codomain.E2, length + 2));

    // now we check that the evaluation with no helper works
    jac_point_t xyP, xyQ, xyPmQ;
    copy_point(&B0_two.P, &T1.P1);
    copy_point(&B0_two.Q, &T2.P1);
    copy_point(&B0_two.PmQ, &T1m2.P1);
    lift_basis(&xyP, &xyQ, &B0_two, &E0);
    jac_neg(&xyQ, &xyQ);
    ADD(&xyPmQ, &xyP, &xyQ, &E0);
    theta_couple_point_t result_no_help;
    theta_couple_jac_point_t input_no_help;
    copy_jac_point(&input_no_help.P1, &xyPmQ);
    copy_jac_point(&input_no_help.P2, &xyPmQ);
    for (int i = 0; i < length + 2; i++) {
        DBL(&input_no_help.P2, &input_no_help.P2, &E0);
    }
    ec_point_t test;
    jac_to_xz(&test, &input_no_help.P1);
    assert(test_point_order_twof(&test, &E0, length + 2));
    assert(test_jac_order_twof(&input_no_help.P1, &E0, length + 2));
    assert(ec_is_equal(&test, &T1m2.P1));
    fp2_set_zero(&input_no_help.P2.x);
    fp2_set_one(&input_no_help.P2.y);
    fp2_set_zero(&input_no_help.P2.z);

    jac_to_xz(&test, &input_no_help.P2);
    assert(ec_is_zero(&test));
    theta_chain_eval_no_help(&result_no_help, &dimtwo_chain, &input_no_help, &E01);
    assert(test_point_order_twof(&result_no_help.P2, &dimtwo_chain.codomain.E2, length + 2));
    assert(test_point_order_twof(&result_no_help.P1, &dimtwo_chain.codomain.E1, length + 2));

    assert(ec_is_equal(&result_no_help.P1, &FP.P1));
    assert(ec_is_equal(&result_no_help.P2, &FP.P2));

    theta_couple_point_t input_special_case;
    theta_couple_point_t result_special_case;

    jac_to_xz(&input_special_case.P1, &input_no_help.P1);
    jac_to_xz(&input_special_case.P2, &input_no_help.P2);

    theta_chain_eval_special_case(&result_special_case, &dimtwo_chain, &input_special_case, &E01);
    assert(ec_is_equal(&result_no_help.P1, &result_special_case.P1));
    assert(ec_is_equal(&result_no_help.P2, &result_special_case.P2));

    input_special_case.P1 = BASIS_THREE.P;
    ec_set_zero(&input_special_case.P2);

    assert(test_point_order_threef(&input_special_case.P1, &E01.E1, TORSION_MINUS_ODD_POWERS[0]));
    theta_chain_eval_special_case(&result_special_case, &dimtwo_chain, &input_special_case, &E01);
    assert(test_point_order_threef(
        &result_special_case.P2, &dimtwo_chain.codomain.E2, TORSION_MINUS_ODD_POWERS[0]));
    input_special_case.P1 = BASIS_THREE.Q;
    ec_set_zero(&input_special_case.P2);
    assert(test_point_order_threef(&input_special_case.P1, &E01.E1, TORSION_MINUS_ODD_POWERS[0]));
    theta_chain_eval_special_case(&result_special_case, &dimtwo_chain, &input_special_case, &E01);
    assert(test_point_order_threef(
        &result_special_case.P2, &dimtwo_chain.codomain.E2, TORSION_MINUS_ODD_POWERS[0]));

    theta_couple_point_t FP_no_sq;
    theta_couple_curve_t E12_no_sq;
    copy_point(&FP_no_sq.P1, &T1m2.P1);
    ec_set_zero(&FP_no_sq.P2);
    ec_mul(&Help.P1, &E0, scal_dig, CHARACTERISTIC->_mp_size, &T1.P1);
    Help.P2 = no_sq_chain.first_step.K1_4.P2;

    theta_chain_eval(&FP_no_sq, &no_sq_chain, &FP_no_sq, &Help);

    assert(test_point_order_twof(&FP_no_sq.P1, &no_sq_chain.codomain.E1, length + 2));
    assert(test_point_order_twof(&FP_no_sq.P2, &no_sq_chain.codomain.E2, length + 2));

    digit_t a[NWORDS_ORDER] = { 0, 0, 0, 0 };
    digit_t b[NWORDS_ORDER] = { 0, 0, 0, 0 };
    ibz_t scala, scalb;
    ibz_init(&scala);
    ibz_init(&scalb);

    ec_isom_t isom, isom_no_sq;

    ec_isomorphism(&isom, &dimtwo_chain.codomain.E1, &no_sq_chain.codomain.E2);
    ec_iso_eval(&FP.P1, &isom);
    assert(ec_is_equal(&FP.P1, &FP_no_sq.P2));
    ec_isomorphism(&isom, &dimtwo_chain.codomain.E2, &no_sq_chain.codomain.E1);
    ec_iso_eval(&FP.P2, &isom);
    // not equal due to some isomorphism of E0

    ibz_finalize(&scal);
    ibz_finalize(&scala);
    ibz_finalize(&scalb);
    return 1;
}

int
main()
{

    int res = 1;

    randombytes_init((unsigned char *)"some", (unsigned char *)"string", 128);

    printf("Running hd module unit tests\n");

    if (TORSION_PLUS_EVEN_POWER < 250) {
        res = res & hd_chain_test();
    } else {
        printf("the hd test was only coded for level 1, try dim2id2iso test \n");
    }

    if (!res) {
        printf("\nSome tests failed!\n");
    } else {
        printf("\nAll tests passed!\n");
    }
    return (!res);
}
