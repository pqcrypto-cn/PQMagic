#include <pike.h>
#include <hd.h>
#include <endomorphism_action.h>
#include <torsion_constants.h>
#include <klpt.h>
#include <quaternion.h>
#include <intbig.h>
#include <ec.h>
#include <rng.h>
#include <id2iso.h>
#include <biextension.h>
#include <pike_hash.h>

int ibz_random_matrix(ibz_mat_2x2_t mat22, const ibz_t *modulus, pike_xof_ctx_t *state)
{
    ibz_t gcd, det;
    ibz_init(&gcd);
    ibz_init(&det);
    while (1)
    {
        if (state != NULL)
        {
            ibz_rand_interval_with_state(&mat22[0][0], &ibz_const_zero, modulus, state);
            ibz_rand_interval_with_state(&mat22[0][1], &ibz_const_zero, modulus, state);
            ibz_rand_interval_with_state(&mat22[1][0], &ibz_const_zero, modulus, state);
            ibz_rand_interval_with_state(&mat22[1][1], &ibz_const_zero, modulus, state);
        }
        else
        {
            ibz_rand_interval(&mat22[0][0], &ibz_const_zero, modulus);
            ibz_rand_interval(&mat22[0][1], &ibz_const_zero, modulus);
            ibz_rand_interval(&mat22[1][0], &ibz_const_zero, modulus);
            ibz_rand_interval(&mat22[1][1], &ibz_const_zero, modulus);
        }
        ibz_mul(&det, &mat22[0][0], &mat22[1][1]);
        ibz_mul(&gcd, &mat22[0][1], &mat22[1][0]);
        ibz_sub(&det, &det, &gcd);
        ibz_gcd(&gcd, &det, modulus);
        if (ibz_is_one(&gcd))
        {
            break;
        }
    }
    ibz_finalize(&gcd);
    ibz_finalize(&det);
    return 1;
}

int ibz_random_unit(ibz_t *q, const ibz_t *modulus, pike_xof_ctx_t *state)
{
    ibz_t gcd;
    ibz_init(&gcd);
    while (1)
    {
        if (state != NULL)
        {
            ibz_rand_interval_with_state(q, &ibz_const_zero, modulus, state);
        }
        else
        {
            ibz_rand_interval(q, &ibz_const_zero, modulus);
        }
        ibz_gcd(&gcd, q, modulus);
        if (ibz_is_one(&gcd))
        {
            break;
        }
    }
    ibz_finalize(&gcd);
    return 1;
}

int keygen(pike_sk_t *sk, pike_pk_t *pk)
{
    ibz_t q, alpha, beta, iota, gamma1, gamma2, rhs, deg, tmp1, tmp2, scalar, remainder, A, q_bound;
    quat_left_ideal_t ideal;
    ec_point_t pointT, eval_points[3];
    ec_basis_t E0_two, PQmin;
    ec_isog_odd_t isog;
    ec_curve_t curve = CURVE_E0, E1;
    digit_t dscalar[NWORDS_ORDER] = {0}, dTORSION_D[NWORDS_ORDER] = {0}, dalpha[NWORDS_ORDER] = {0}, dbeta[NWORDS_ORDER] = {0}, dgamma2[NWORDS_ORDER] = {0};
    ec_isom_t iso;
    theta_couple_curve_t E01;
    theta_couple_point_t T1, T2, T1m2, tmpS, tmpT1, tmpT2, tmpT3, output_points[3], input_points[3];
    theta_chain_t hd_isog;
    fp2_t fp2inv;

    ibz_init(&q);
    ibz_init(&alpha);
    ibz_init(&beta);
    ibz_init(&iota);
    ibz_init(&gamma1);
    ibz_init(&gamma2);
    ibz_init(&rhs);
    ibz_init(&deg);
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    ibz_init(&A);
    ibz_init(&q_bound);
    ibz_init(&scalar);
    ibz_init(&remainder);
    quat_left_ideal_init(&ideal);
    ibz_div_2exp(&A, &TORSION_PLUS_2POWER, 2);
    ibz_div_2exp(&q_bound, &TORSION_PLUS_2POWER, 4);

    // Set q to a random value in the range [0, TORSION_PLUS_2POWER)
    for (int i = 0; i < 1000; i++)
    {
        ibz_rand_interval(&q, &ibz_const_zero, &q_bound);
        ibz_sub(&deg, &A, &q);
        ibz_mul(&tmp1, &TORSION_D, &ibz_const_two);
        ibz_mul(&tmp1, &tmp1, &TORSION_ODD_PLUS);
        ibz_mul(&tmp1, &tmp1, &TORSION_ODD_MINUS);
        ibz_mul(&tmp2, &q, &deg);
        ibz_gcd(&tmp1, &tmp1, &tmp2);
        if (ibz_is_one(&tmp1))
        {
            break;
        }
    }
    ibz_mul(&rhs, &deg, &q);
    ibz_mul(&rhs, &rhs, &TORSION_ODD_PLUS);
    ibz_mul(&rhs, &rhs, &TORSION_ODD_MINUS);
    ibz_random_unit(&alpha, &A, NULL);
    ibz_random_unit(&beta, &A, NULL);
    ibz_random_unit(&gamma1, &TORSION_ODD_PLUS, NULL);
    ibz_random_unit(&gamma2, &TORSION_ODD_MINUS, NULL);
    ibz_random_unit(&iota, &TORSION_D, NULL);
    memset(&sk->deg, 0, NWORDS_ORDER * RADIX / 8);
    memset(&sk->alpha, 0, NWORDS_ORDER * RADIX / 8);
    memset(&sk->beta, 0, NWORDS_ORDER * RADIX / 8);
    memset(&sk->iota, 0, NWORDS_ORDER * RADIX / 8);
    ibz_to_digits(sk->deg, &q);
    ibz_to_digits(sk->alpha, &alpha);
    ibz_to_digits(sk->beta, &beta);
    ibz_to_digits(sk->iota, &iota);

    ibz_crt(&alpha, &alpha, &gamma1, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    ibz_crt(&beta, &beta, &gamma1, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);

    // generate the endomorphism tau
    quat_alg_elem_t tau;
    quat_alg_elem_init(&tau);
    if (represent_integer(&tau, &rhs, &QUATALG_PINFTY) == 0)
    {
        printf("Failed to represent integer in non-diagonal form\n");
        return 1;
    }

    copy_point(&E0_two.P, &BASIS_EVEN.P);
    copy_point(&E0_two.Q, &BASIS_EVEN.Q);
    copy_point(&E0_two.PmQ, &BASIS_EVEN.PmQ);

    // evaluate tau at the 2^a torsions
    endomorphism_application_even_basis(&E0_two, &curve, &tau, TORSION_PLUS_EVEN_POWER);
    ibz_mul(&scalar, &TORSION_ODD_MINUS, &TORSION_ODD_PLUS);
    // Compute the conjugate of tau
    quat_alg_conj(&tau, &tau);
    quat_lideal_create_from_primitive(&ideal, &tau, &scalar, &MAXORD_O0, &QUATALG_PINFTY);
    id2iso_ideal_to_isogeny_odd(&isog, &curve, &BASIS_ODD_PLUS, &BASIS_ODD_MINUS, &ideal);
    copy_point(&eval_points[0], &E0_two.P);
    copy_point(&eval_points[1], &E0_two.Q);
    copy_point(&eval_points[2], &E0_two.PmQ);
    ec_eval_odd(&E1, &isog, (ec_point_t *)&eval_points, 3);
    copy_point(&T1.P2, &eval_points[0]);
    copy_point(&T2.P2, &eval_points[1]);
    copy_point(&T1m2.P2, &eval_points[2]);

    // Evaluating the secret isogeny
    E01.E1 = curve;
    E01.E2 = E1;
    T1.P1 = BASIS_EVEN.P;
    T2.P1 = BASIS_EVEN.Q;
    T1m2.P1 = BASIS_EVEN.PmQ;
    ibz_mul(&scalar, &scalar, &q);
    ibz_mod(&scalar, &scalar, &TORSION_PLUS_2POWER);
    ibz_to_digits(dscalar, &scalar);
    ec_mul(&T1.P1, &curve, dscalar, TORSION_PLUS_2POWER->_mp_size, &T1.P1);
    ec_mul(&T2.P1, &curve, dscalar, TORSION_PLUS_2POWER->_mp_size, &T2.P1);
    ec_mul(&T1m2.P1, &curve, dscalar, TORSION_PLUS_2POWER->_mp_size, &T1m2.P1);
    theta_chain_comput_strategy(&hd_isog, TORSION_PLUS_EVEN_POWER - 2, &E01, &T1, &T2, &T1m2, strategies[2], 1);
    copy_point(&PQmin.P, &BASIS_ODD_MINUS.P);
    copy_point(&PQmin.Q, &BASIS_ODD_MINUS.Q);
    copy_point(&PQmin.PmQ, &BASIS_ODD_MINUS.PmQ);
    input_points[0].P1 = BASIS_EVEN.P;
    input_points[1].P1 = BASIS_EVEN.Q;
    input_points[2].P1 = BASIS_EVEN.PmQ;
    for (int i = 0; i < 3; i++)
    {
        ec_set_zero(&input_points[i].P2);
        theta_chain_eval_special_case(&output_points[i], &hd_isog, &input_points[i], &E01);
    }
    fp2_copy(&tmpT1.P1.x, &xPpt);
    fp2_set_one(&tmpT1.P1.z);
    ec_set_zero(&tmpT1.P2);
    copy_point(&tmpT2.P1, &BASIS_EVEN_AND_ODD_PLUS.Q);
    ec_set_zero(&tmpT2.P2);
    copy_point(&tmpT3.P1, &BASIS_EVEN_AND_ODD_PLUS.PmQ);
    ec_set_zero(&tmpT3.P2);
    theta_chain_eval_special_case(&tmpT1, &hd_isog, &tmpT1, &E01);
    theta_chain_eval_special_case(&tmpT2, &hd_isog, &tmpT2, &E01);
    theta_chain_eval_special_case(&tmpT3, &hd_isog, &tmpT3, &E01);
    copy_point(&tmpS.P1, &PQmin.P);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&PQmin.P, &tmpS.P1);
    copy_point(&tmpS.P1, &PQmin.Q);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&PQmin.Q, &tmpS.P1);
    copy_point(&tmpS.P1, &PQmin.PmQ);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&PQmin.PmQ, &tmpS.P1);

    E01.E1 = hd_isog.codomain.E1;
    E01.E2 = hd_isog.codomain.E2;
    theta_chain_comput_strategy(&hd_isog, TORSION_PLUS_EVEN_POWER - 2, &E01, &output_points[0], &output_points[1], &output_points[2], strategies[2], 1);

    ec_isomorphism(&iso, &hd_isog.codomain.E1, &E1);

    copy_point(&tmpS.P1, &PQmin.P);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&PQmin.P, &tmpS.P1);
    copy_point(&tmpS.P1, &PQmin.Q);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&PQmin.Q, &tmpS.P1);
    copy_point(&tmpS.P1, &PQmin.PmQ);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&PQmin.PmQ, &tmpS.P1);
    ec_iso_eval(&PQmin.P, &iso);
    ec_iso_eval(&PQmin.Q, &iso);
    ec_iso_eval(&PQmin.PmQ, &iso);

    ec_set_zero(&tmpT1.P2);
    theta_chain_eval_special_case(&tmpT1, &hd_isog, &tmpT1, &E01);
    ec_iso_eval(&tmpT1.P1, &iso);
    ec_set_zero(&tmpT2.P2);
    theta_chain_eval_special_case(&tmpT2, &hd_isog, &tmpT2, &E01);
    ec_iso_eval(&tmpT2.P1, &iso);
    ec_set_zero(&tmpT3.P2);
    theta_chain_eval_special_case(&tmpT3, &hd_isog, &tmpT3, &E01);
    ec_iso_eval(&tmpT3.P1, &iso);

    // mask points
    ibz_to_digits(dTORSION_D, &TORSION_D);
    ec_mul(&pointT, &E1, dTORSION_D, TORSION_D->_mp_size, &tmpT1.P1);
    xADD(&tmpT3.P1, &pointT, &tmpT2.P1, &tmpT3.P1);
    ibz_to_digits(dalpha, &alpha);
    ibz_to_digits(dbeta, &beta);
    xDBLMUL_bounded(&tmpT3.P1, &pointT, dalpha, &tmpT2.P1, dbeta, &tmpT3.P1, &E1, TORSION_PLUS_ODD_2POWER->_mp_size);

    ibz_crt(&alpha, &alpha, &iota, &TORSION_PLUS_ODD_2POWER, &TORSION_D);
    ibz_to_digits(dalpha, &alpha);
    ec_mul(&tmpT1.P1, &E1, dalpha, TORSION_PLUS_ODD_D_2POWER->_mp_size, &tmpT1.P1);
    ec_mul(&tmpT2.P1, &E1, dbeta, TORSION_PLUS_ODD_2POWER->_mp_size, &tmpT2.P1);

    ec_mul(&pointT, &E1, dTORSION_D, TORSION_D->_mp_size, &tmpT1.P1);
    fp2_mul(&fp2inv, &pointT.z, &tmpT2.P1.z);
    fp2_mul(&fp2inv, &fp2inv, &E1.C);
    fp2_inv(&fp2inv);
    fp2_mul(&pointT.x, &fp2inv, &pointT.x);
    fp2_mul(&pointT.x, &tmpT2.P1.z, &pointT.x);
    fp2_mul(&pointT.x, &E1.C, &pointT.x);
    fp2_mul(&fp2inv, &fp2inv, &pointT.z);
    fp2_mul(&tmpT2.P1.x, &fp2inv, &tmpT2.P1.x);
    fp2_mul(&tmpT2.P1.x, &E1.C, &tmpT2.P1.x);
    fp2_mul(&E1.A, &fp2inv, &E1.A);
    fp2_mul(&E1.A, &tmpT2.P1.z, &E1.A);
    fp2_set_one(&pointT.z);
    fp2_set_one(&tmpT2.P1.z);
    fp2_set_one(&E1.C);
    difference_point(&pointT, &pointT, &tmpT2.P1, &E1);
    pk->label_pls = is_point_equal(&pointT, &tmpT3.P1);

    // mask the basis information
    ibz_to_digits(dgamma2, &gamma2);
    ec_mul(&PQmin.P, &E1, dgamma2, TORSION_ODD_MINUS->_mp_size, &PQmin.P);
    ec_mul(&PQmin.Q, &E1, dgamma2, TORSION_ODD_MINUS->_mp_size, &PQmin.Q);
    ec_mul(&PQmin.PmQ, &E1, dgamma2, TORSION_ODD_MINUS->_mp_size, &PQmin.PmQ);

    // normalize the points
    fp2_t t1, t2, t3, t4;
    fp2_copy(&t1, &tmpT1.P1.z);
    fp2_copy(&t2, &tmpT2.P1.z);
    fp2_copy(&t3, &PQmin.P.z);
    fp2_copy(&t4, &PQmin.Q.z);
    fp2_copy(&fp2inv, &PQmin.PmQ.z);
    fp2_mul(&t2, &t1, &t2);
    fp2_mul(&t3, &t2, &t3);
    fp2_mul(&t4, &t3, &t4);
    fp2_mul(&fp2inv, &t4, &fp2inv);
    fp2_inv(&fp2inv);
    fp2_mul(&pk->xPQmin, &PQmin.PmQ.x, &t4);
    fp2_mul(&pk->xPQmin, &pk->xPQmin, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &PQmin.PmQ.z);
    fp2_mul(&pk->xQmin, &PQmin.Q.x, &t3);
    fp2_mul(&pk->xQmin, &pk->xQmin, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &PQmin.Q.z);
    fp2_mul(&pk->xPmin, &PQmin.P.x, &t2);
    fp2_mul(&pk->xPmin, &pk->xPmin, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &PQmin.P.z);
    fp2_mul(&pk->xQpls, &tmpT2.P1.x, &t1);
    fp2_mul(&pk->xQpls, &pk->xQpls, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &tmpT2.P1.z);
    fp2_mul(&pk->xPpls, &tmpT1.P1.x, &fp2inv);

    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
    ibz_finalize(&q);
    ibz_finalize(&alpha);
    ibz_finalize(&beta);
    ibz_finalize(&iota);
    ibz_finalize(&gamma1);
    ibz_finalize(&gamma2);
    ibz_finalize(&rhs);
    ibz_finalize(&deg);
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
    ibz_finalize(&A);
    ibz_finalize(&q_bound);
    quat_alg_elem_finalize(&tau);
    quat_left_ideal_finalize(&ideal);
    return 1;
}

int encrypt(pike_ct_t *ct, const pike_pk_t *pk, const unsigned char *m, const size_t m_len, const unsigned char *seed, const size_t seed_len)
{
    ec_isog_odd_t isogB1, isogB2;
    ibz_t beta1, beta2, omega, omega_inv, A, t1, t2, t1t2;
    ec_curve_t EB, EAB;
    ec_basis_t EA_two, EA_Tpls, PQmin;
    ec_point_t Ppls, eval_points[2];
    ec_point_t Ppls_B, Qpls_B, Ppls_AB, Qpls_AB;
    pike_xof_ctx_t state;
    digit_t beta1_scalar[NWORDS_ORDER] = {0}, beta2_scalar[NWORDS_ORDER] = {0}, omega_scalar[NWORDS_ORDER] = {0}, omega_inv_scalar[NWORDS_ORDER] = {0}, t1_scalar[NWORDS_ORDER] = {0}, t2_scalar[NWORDS_ORDER] = {0}, scalar[NWORDS_ORDER] = {0}, dTORSION_ODD_PLUS[NWORDS_ORDER] = {0}, dTORSION_PLUS_2POWER[NWORDS_ORDER] = {0}, dTORSION_D[NWORDS_ORDER] = {0}, exp[NWORDS_ORDER] = {0};
    fp2_t fp2inv, shared_sec;

    ibz_init(&beta1);
    ibz_init(&beta2);
    ibz_init(&omega);
    ibz_init(&omega_inv);
    ibz_init(&A);
    ibz_init(&t1);
    ibz_init(&t2);
    ibz_init(&t1t2);

    ibz_div_2exp(&A, &TORSION_PLUS_2POWER, 2);
    if (seed != NULL)
    {
        pike_xof_stream_init(&state, seed, seed_len);
        ibz_random_unit(&beta1, &TORSION_ODD_PLUS, &state);
        ibz_random_unit(&beta2, &TORSION_ODD_MINUS, &state);
        ibz_random_unit(&omega, &A, &state);
        ibz_random_unit(&t1, &TORSION_D, &state);
        ibz_random_unit(&t2, &TORSION_D, &state);
        ibz_mul(&t1t2, &t1, &t2);
        ibz_mod(&t1t2, &t1t2, &TORSION_D);
        pike_xof_stream_release(&state);
    }
    else
    {
        ibz_random_unit(&beta1, &TORSION_ODD_PLUS, NULL);
        ibz_random_unit(&beta2, &TORSION_ODD_MINUS, NULL);
        ibz_random_unit(&omega, &A, NULL);
        ibz_random_unit(&t1, &TORSION_D, NULL);
        ibz_random_unit(&t2, &TORSION_D, NULL);
        ibz_mul(&t1t2, &t1, &t2);
        ibz_mod(&t1t2, &t1t2, &TORSION_D);
    }

    ibz_invmod(&omega_inv, &omega, &A);
    ibz_to_digits(omega_scalar, &omega);
    ibz_to_digits(omega_inv_scalar, &omega_inv);
    ibz_to_digits(beta1_scalar, &beta1);
    ibz_to_digits(beta2_scalar, &beta2);
    ibz_to_digits(t1_scalar, &t1);
    ibz_to_digits(t2_scalar, &t2);

    // compute the isogeny from E0 to EB
    isogB1.curve = CURVE_E0;
    for (int i = 0; i < P_LEN; i++)
    {
        isogB1.degree[i] = TORSION_PLUS_ODD_POWERS[i];
    }
    for (int i = 0; i < M_LEN; i++)
    {
        isogB1.degree[P_LEN + i] = TORSION_MINUS_ODD_POWERS[i];
    }
    ec_curve_normalize_A24(&isogB1.curve);
    ec_ladder3pt_bounded(&isogB1.ker_plus, beta1_scalar, &BASIS_ODD_PLUS.P, &BASIS_ODD_PLUS.Q, &BASIS_ODD_PLUS.PmQ, &isogB1.curve, TORSION_ODD_PLUS->_mp_size);
    ec_ladder3pt_bounded(&isogB1.ker_minus, beta2_scalar, &BASIS_ODD_MINUS.P, &BASIS_ODD_MINUS.Q, &BASIS_ODD_MINUS.PmQ, &isogB1.curve, TORSION_ODD_MINUS->_mp_size);
    copy_point(&eval_points[0], &BASIS_EVEN.P);
    fp2_copy(&eval_points[1].x, &xQpt);
    fp2_set_one(&eval_points[1].z);
    ec_eval_odd(&EB, &isogB1, eval_points, 2);

    ibz_to_digits(dTORSION_ODD_PLUS, &TORSION_ODD_PLUS);
    ibz_to_digits(dTORSION_PLUS_2POWER, &TORSION_PLUS_2POWER);
    ibz_to_digits(dTORSION_D, &TORSION_D);
    fp2_inv(&EB.C);
    fp2_mul(&EB.A, &EB.A, &EB.C);
    fp2_set_one(&EB.C);
    fp2_copy(&ct->EB_cof, &EB.A);
    // Masking evaluated points
    ec_mul(&Ppls_B, &EB, omega_scalar, TORSION_PLUS_2POWER->_mp_size, &eval_points[0]);
    ibz_crt(&t1, &t1, &omega_inv, &TORSION_D, &TORSION_PLUS_2POWER);
    ibz_to_digits(scalar, &t1);
    ec_mul(&Qpls_B, &EB, scalar, TORSION_PLUS_D_2POWER->_mp_size, &eval_points[1]);

    // compute the isogeny from EA to EAB
    fp2_copy(&PQmin.P.x, &pk->xPmin);
    fp2_copy(&PQmin.Q.x, &pk->xQmin);
    fp2_copy(&PQmin.PmQ.x, &pk->xPQmin);
    fp2_set_one(&PQmin.P.z);
    fp2_set_one(&PQmin.Q.z);
    fp2_set_one(&PQmin.PmQ.z);
    recover_domain(&isogB2.curve, &PQmin.P, &PQmin.Q, &PQmin.PmQ);
    for (int i = 0; i < P_LEN; i++)
    {
        isogB2.degree[i] = TORSION_PLUS_ODD_POWERS[i];
    }
    for (int i = 0; i < M_LEN; i++)
    {
        isogB2.degree[P_LEN + i] = TORSION_MINUS_ODD_POWERS[i];
    }

    fp2_copy(&Ppls.x, &pk->xPpls);
    fp2_set_one(&Ppls.z);
    ec_mul(&EA_Tpls.P, &isogB2.curve, dTORSION_D, TORSION_D->_mp_size, &Ppls);
    fp2_copy(&EA_Tpls.Q.x, &pk->xQpls);
    fp2_set_one(&EA_Tpls.Q.z);

    fp2_mul(&fp2inv, &EA_Tpls.P.z, &isogB2.curve.C);
    fp2_inv(&fp2inv);
    fp2_mul(&EA_Tpls.P.x, &fp2inv, &EA_Tpls.P.x);
    fp2_mul(&EA_Tpls.P.x, &isogB2.curve.C, &EA_Tpls.P.x);
    fp2_mul(&isogB2.curve.A, &fp2inv, &isogB2.curve.A);
    fp2_mul(&isogB2.curve.A, &EA_Tpls.P.z, &isogB2.curve.A);
    fp2_set_one(&EA_Tpls.P.z);
    fp2_set_one(&isogB2.curve.C);
    difference_point(&EA_Tpls.PmQ, &EA_Tpls.P, &EA_Tpls.Q, &isogB2.curve);
    if (pk->label_pls == 0)
    {
        xADD(&EA_Tpls.PmQ, &EA_Tpls.P, &EA_Tpls.Q, &EA_Tpls.PmQ);
    }

    fp2_copy(&EA_two.Q.x, &pk->xQpls);
    fp2_set_one(&EA_two.Q.z);
    ec_mul(&EA_two.Q, &isogB2.curve, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &EA_two.Q);
    fp2_copy(&EA_Tpls.Q.x, &pk->xQpls);
    fp2_set_one(&EA_Tpls.Q.z);
    ec_mul(&EA_two.PmQ, &isogB2.curve, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &EA_Tpls.PmQ);
    
    ec_curve_normalize_A24(&isogB2.curve);
    ec_ladder3pt_bounded(&isogB2.ker_plus, beta1_scalar, &EA_Tpls.P, &EA_Tpls.Q, &EA_Tpls.PmQ, &isogB2.curve, TORSION_ODD_PLUS->_mp_size);
    ec_mul(&isogB2.ker_plus, &isogB2.curve, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &isogB2.ker_plus);
    ec_ladder3pt_bounded(&isogB2.ker_minus, beta2_scalar, &PQmin.P, &PQmin.Q, &PQmin.PmQ, &isogB2.curve, TORSION_ODD_MINUS->_mp_size);
    ec_mul(&eval_points[0], &isogB2.curve, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &Ppls);
    copy_point(&eval_points[1], &EA_two.Q);
    ec_eval_odd(&EAB, &isogB2, eval_points, 2);

    fp2_inv(&EAB.C);
    fp2_mul(&EAB.A, &EAB.A, &EAB.C);
    fp2_set_one(&EAB.C);
    fp2_copy(&ct->EAB_cof, &EAB.A);
    ec_mul(&Qpls_AB, &EAB, omega_inv_scalar, TORSION_PLUS_2POWER->_mp_size, &eval_points[1]);

    ibz_crt(&t2, &t2, &omega, &TORSION_D, &TORSION_PLUS_2POWER);
    ibz_to_digits(t2_scalar, &t2);
    ec_mul(&Ppls_AB, &EAB, t2_scalar, TORSION_PLUS_D_2POWER->_mp_size, &eval_points[0]);

    // normalize the points
    fp2_t tmp1, tmp2, tmp3;
    fp2_copy(&tmp1, &Ppls_B.z);
    fp2_copy(&tmp2, &Qpls_B.z);
    fp2_copy(&tmp3, &Ppls_AB.z);
    fp2_copy(&fp2inv, &Qpls_AB.z);
    fp2_mul(&tmp2, &tmp1, &tmp2);
    fp2_mul(&tmp3, &tmp2, &tmp3);
    fp2_mul(&fp2inv, &tmp3, &fp2inv);
    fp2_inv(&fp2inv);
    fp2_mul(&ct->xQpls_AB, &Qpls_AB.x, &tmp3);
    fp2_mul(&ct->xQpls_AB, &ct->xQpls_AB, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &Qpls_AB.z);
    fp2_mul(&ct->xPpls_AB, &Ppls_AB.x, &tmp2);
    fp2_mul(&ct->xPpls_AB, &ct->xPpls_AB, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &Ppls_AB.z);
    fp2_mul(&ct->xQpls_B, &Qpls_B.x, &tmp1);
    fp2_mul(&ct->xQpls_B, &ct->xQpls_B, &fp2inv);
    fp2_mul(&fp2inv, &fp2inv, &Qpls_B.z);
    fp2_mul(&ct->xPpls_B, &Ppls_B.x, &fp2inv);

    unsigned char hash_input[FP_NBYTES] = {0};
    unsigned char hash_output[PIKE_SHARED_SECRET_BYTES] = {0};
    ibz_to_digits(exp, &t1t2);

    // compute the plaintext
    // compute the trace of the pairing
    fp_copy(&shared_sec.re, &Pairing_value.re);
    fp_add(&shared_sec.re, &shared_sec.re, &shared_sec.re);
    // use Lucas sequences to perform the exponentation
    lucas_sequence(&shared_sec.re, &shared_sec.re, exp, TORSION_D->_mp_size);
    fp_encode(hash_input, &shared_sec.re);

    pike_xof(hash_output, sizeof(hash_output), hash_input, sizeof(hash_input));

    // ct->ct = m xor hash_output
    memset(ct->ct, 0, sizeof(ct->ct));
    for (size_t i = 0; i < PIKE_SHARED_SECRET_BYTES; i++)
    {
        if (i >= m_len)
        {
            ct->ct[i] = hash_output[i];
        }
        else
        {
            ct->ct[i] = m[i] ^ hash_output[i];
        }
    }

    ibz_finalize(&A);
    ibz_finalize(&beta1);
    ibz_finalize(&beta2);
    ibz_finalize(&t1);
    ibz_finalize(&t2);
    ibz_finalize(&omega);
    ibz_finalize(&omega_inv);
    return 1;
}

int decrypt(unsigned char *m, size_t *m_len, const pike_ct_t *ct, const pike_sk_t *sk)
{
    unsigned char hash_input[FP_NBYTES] = {0};
    unsigned char hash_output[PIKE_SHARED_SECRET_BYTES] = {0};
    digit_t T1_scalar[NWORDS_ORDER] = {0}, T2_scalar[NWORDS_ORDER] = {0}, dTORSION_D[NWORDS_ORDER] = {0}, dTORSION_PLUS_2POWER[NWORDS_ORDER] = {0}, exp[NWORDS_ORDER] = {0};
    theta_chain_t hd_isog;
    theta_couple_curve_t EBAB;
    theta_couple_point_t T1, T2, T1m2, tmp;
    ibz_t deg_alpha_inv, deg_beta_inv, deg, iota, A, d;
    ec_point_t Psmid, Qsmid, PmQsmid;
    fp2_t fp2inv, fp2tmp1, fp2tmp2, shared_sec;
    fp2_t r1, r2;

    ibz_init(&deg_alpha_inv);
    ibz_init(&deg_beta_inv);
    ibz_init(&deg);
    ibz_init(&iota);
    ibz_init(&A);
    ibz_init(&d);
    

    ibz_copy_digits(&deg, sk->deg, NWORDS_ORDER);
    ibz_div_2exp(&A, &TORSION_PLUS_2POWER, 2);
    ibz_copy_digits(&deg_alpha_inv, sk->alpha, NWORDS_ORDER);
    ibz_copy_digits(&deg_beta_inv, sk->beta, NWORDS_ORDER);
    ibz_mul(&deg_alpha_inv, &deg, &deg_alpha_inv);
    ibz_mul(&deg_beta_inv, &deg, &deg_beta_inv);
    ibz_invmod(&deg_alpha_inv, &deg_alpha_inv, &TORSION_PLUS_2POWER);
    ibz_invmod(&deg_beta_inv, &deg_beta_inv, &TORSION_PLUS_2POWER);

    ibz_sub(&d, &A, &deg);
    ibz_mul(&d, &deg, &d);
    ibz_mod(&d, &d, &TORSION_D);
    ibz_copy_digits(&iota, sk->iota, NWORDS_ORDER);
    ibz_mul(&d, &iota, &d);
    ibz_mod(&d, &d, &TORSION_D);
    ibz_mul(&d, &d, &TORSION_ODD_PLUS);
    ibz_mod(&d, &d, &TORSION_D);
    ibz_mul(&d, &d, &TORSION_ODD_MINUS);
    ibz_mod(&d, &d, &TORSION_D);
    ibz_invmod(&d, &d, &TORSION_D);

    fp2_copy(&EBAB.E1.A, &ct->EB_cof);
    fp2_set_one(&EBAB.E1.C);
    EBAB.E1.is_A24_computed_and_normalized = false;
    fp2_copy(&EBAB.E2.A, &ct->EAB_cof);
    fp2_set_one(&EBAB.E2.C);
    EBAB.E2.is_A24_computed_and_normalized = false;
    ibz_to_digits(dTORSION_D, &TORSION_D);
    ibz_to_digits(dTORSION_PLUS_2POWER, &TORSION_PLUS_2POWER);

    fp2_copy(&T1.P1.x, &ct->xPpls_B);
    fp2_set_one(&T1.P1.z);
    fp2_copy(&T2.P1.x, &ct->xQpls_B);
    fp2_set_one(&T2.P1.z);
    ec_mul(&T2.P1, &EBAB.E1, dTORSION_D, TORSION_D->_mp_size, &T2.P1);

    fp2_mul(&fp2inv, &T1.P1.z, &T2.P1.z);
    fp2_inv(&fp2inv);
    fp2_mul(&T1.P1.x, &fp2inv, &T1.P1.x);
    fp2_mul(&T1.P1.x, &T2.P1.z, &T1.P1.x);
    fp2_mul(&T2.P1.x, &fp2inv, &T2.P1.x);
    fp2_mul(&T2.P1.x, &T1.P1.z, &T2.P1.x);
    fp2_set_one(&T1.P1.z);
    fp2_set_one(&T2.P1.z);
    difference_point(&T1m2.P1, &T1.P1, &T2.P1, &EBAB.E1);

    fp2_copy(&T1.P2.x, &ct->xPpls_AB);
    fp2_set_one(&T1.P2.z);
    fp2_copy(&T2.P2.x, &ct->xQpls_AB);
    fp2_set_one(&T2.P2.z);
    ec_mul(&T1.P2, &EBAB.E2, dTORSION_D, TORSION_D->_mp_size, &T1.P2);

    fp2_mul(&fp2inv, &T1.P2.z, &T2.P2.z);
    fp2_inv(&fp2inv);
    fp2_mul(&T1.P2.x, &fp2inv, &T1.P2.x);
    fp2_mul(&T1.P2.x, &T2.P2.z, &T1.P2.x);
    fp2_mul(&T2.P2.x, &fp2inv, &T2.P2.x);
    fp2_mul(&T2.P2.x, &T1.P2.z, &T2.P2.x);
    fp2_set_one(&T1.P2.z);
    fp2_set_one(&T2.P2.z);
    difference_point(&T1m2.P2, &T1.P2, &T2.P2, &EBAB.E2);

    ibz_to_digits(T1_scalar, &deg_alpha_inv);
    ibz_to_digits(T2_scalar, &deg_beta_inv);
    xDBLMUL_bounded(&T1m2.P2, &T1.P2, T1_scalar, &T2.P2, T2_scalar, &T1m2.P2, &EBAB.E2, TORSION_PLUS_2POWER->_mp_size);
    ec_mul(&T1.P2, &EBAB.E2, T1_scalar, TORSION_PLUS_2POWER->_mp_size, &T1.P2);
    ec_mul(&T2.P2, &EBAB.E2, T2_scalar, TORSION_PLUS_2POWER->_mp_size, &T2.P2);
    AC_to_A24(&EBAB.E1.A24, &EBAB.E1);
    AC_to_A24(&EBAB.E2.A24, &EBAB.E2);
    fp2_mul(&fp2inv, &EBAB.E1.A24.z, &EBAB.E2.A24.z);
    fp2_inv(&fp2inv);
    fp2_mul(&EBAB.E1.A24.x, &EBAB.E1.A24.x, &fp2inv);
    fp2_mul(&EBAB.E1.A24.x, &EBAB.E2.A24.z, &EBAB.E1.A24.x);
    fp2_mul(&EBAB.E2.A24.x, &EBAB.E2.A24.x, &fp2inv);
    fp2_mul(&EBAB.E2.A24.x, &EBAB.E1.A24.z, &EBAB.E2.A24.x);
    fp2_set_one(&EBAB.E1.A24.z);
    fp2_set_one(&EBAB.E2.A24.z);
    EBAB.E1.is_A24_computed_and_normalized = true;
    EBAB.E2.is_A24_computed_and_normalized = true;
    // use tate pairing to identify T1m2.P2
    non_reduced_tate(&r1, TORSION_PLUS_EVEN_POWER, &T1.P1, &T2.P1, &T1m2.P1, &EBAB.E1.A24);
    non_reduced_tate(&r2, TORSION_PLUS_EVEN_POWER, &T1.P2, &T2.P2, &T1m2.P2, &EBAB.E2.A24);
    fp2_mul(&fp2inv, &r1, &r2);
    fp2_inv(&fp2inv);
    fp2_copy(&fp2tmp1, &r1);
    fp2_copy(&fp2tmp2, &r2);
    fp2_mul(&fp2tmp1, &r2, &fp2inv);
    fp2_mul(&fp2tmp2, &r1, &fp2inv);
    fp_neg(&r1.im, &r1.im);
    fp_neg(&r2.im, &r2.im);
    fp2_mul(&r1, &r1, &fp2tmp1);
    fp2_mul(&r2, &r2, &fp2tmp2);
    // final exponentiation
    fp2_exp(&r2, &r2, p_cofactor_for_2f, (P_COFACTOR_FOR_2F_BITLENGTH + 63) / 64);
    fp2_exp(&r1, &r1, p_cofactor_for_2f, (P_COFACTOR_FOR_2F_BITLENGTH + 63) / 64);

    fp_cswap(&r1.re, &r1.im, 0xFFFFFFFF);
    if(!fp2_is_equal(&r1, &r2)){
        fp2_add(&r1, &r1, &r2);
        if(!fp2_is_zero(&r1)){
            xADD(&T1m2.P2, &T1.P2, &T2.P2, &T1m2.P2);
        }
    }
    theta_chain_comput_strategy(&hd_isog, TORSION_PLUS_EVEN_POWER - 2, &EBAB, &T1, &T2, &T1m2, strategies[2], 1);

    fp2_copy(&tmp.P1.x, &ct->xQpls_B);
    fp2_set_one(&tmp.P1.z);
    ec_mul(&tmp.P1, &EBAB.E1, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &tmp.P1);
    ec_set_zero(&tmp.P2);
    theta_chain_eval_special_case(&tmp, &hd_isog, &tmp, &EBAB);
    copy_point(&Psmid, &tmp.P1);

    fp2_copy(&tmp.P2.x, &ct->xPpls_AB);
    fp2_set_one(&tmp.P2.z);
    ec_mul(&tmp.P2, &EBAB.E2, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &tmp.P2);
    ec_set_zero(&tmp.P1);
    theta_chain_eval_special_case(&tmp, &hd_isog, &tmp, &EBAB);
    copy_point(&Qsmid, &tmp.P1);

    fp2_mul(&fp2tmp1, &Psmid.z, &hd_isog.codomain.E1.C);
    fp2_mul(&fp2tmp2, &Qsmid.z, &fp2tmp1);
    fp2_inv(&fp2tmp2);
    fp2_mul(&fp2tmp1, &fp2tmp1, &fp2tmp2);
    fp2_mul(&Qsmid.x, &Qsmid.x, &fp2tmp1);
    fp2_mul(&fp2tmp2, &Qsmid.z, &fp2tmp2);
    fp2_mul(&fp2tmp1, &Psmid.z, &fp2tmp2);
    fp2_mul(&hd_isog.codomain.E1.A, &hd_isog.codomain.E1.A, &fp2tmp1);
    fp2_mul(&fp2tmp1, &hd_isog.codomain.E1.C, &fp2tmp2);
    fp2_mul(&Psmid.x, &Psmid.x, &fp2tmp1);
    fp2_set_one(&hd_isog.codomain.E1.C);
    fp2_set_one(&Psmid.z);
    fp2_set_one(&Qsmid.z);

    difference_point(&PmQsmid, &Psmid, &Qsmid, &hd_isog.codomain.E1);

    ibz_to_digits(exp, &d);
    ec_curve_normalize_A24(&hd_isog.codomain.E1);
    tate_odd_TORSION_D(&shared_sec, dTORSION_D, &Qsmid, &Psmid, &PmQsmid, &hd_isog.codomain.E1.A24);

    // compute the plaintext
    // compute the trace of the pairing
    fp_add(&shared_sec.re, &shared_sec.re, &shared_sec.re);
    // use Lucas sequences to perform the exponentation
    lucas_sequence(&shared_sec.re, &shared_sec.re, exp, TORSION_D->_mp_size);

    fp_encode(hash_input, &shared_sec.re);

    pike_xof(hash_output, sizeof(hash_output), hash_input, sizeof(hash_input));

    // m = ct->ct xor hash_output
    memset(m, 0, sizeof(hash_output));
    for (size_t i = 0; i < sizeof(hash_output); i++)
    {
        m[i] = ct->ct[i] ^ hash_output[i];
    }
    *m_len = sizeof(hash_output);

    ibz_finalize(&deg_alpha_inv);
    ibz_finalize(&deg_beta_inv);
    ibz_finalize(&deg);
    ibz_finalize(&iota);
    ibz_finalize(&A);
    ibz_finalize(&d);
    return 1;
}

////
//// Key Encapsulation Mechanism using Fujisaki-Okamoto transform
////

const unsigned char G_hash_str[9] = "encrypt_";
const size_t G_hash_str_len = 8;

static void encode_scalar_le(unsigned char *out, const digit_t *digits, size_t nbytes)
{
    for (size_t i = 0; i < nbytes; i++)
    {
        out[i] = (unsigned char)(digits[i / DIGIT_LEN] >> (8 * (i % DIGIT_LEN)));
    }
}

static void decode_scalar_le(digit_t *digits, size_t nwords, const unsigned char *in, size_t nbytes)
{
    memset(digits, 0, nwords * sizeof(*digits));
    for (size_t i = 0; i < nbytes; i++)
    {
        digits[i / DIGIT_LEN] |= ((digit_t)in[i]) << (8 * (i % DIGIT_LEN));
    }
}

int ct_encode(unsigned char *encoded_ct, pike_ct_t *ct)
{
    size_t offset = 0;

    memset(encoded_ct, 0, PIKE_CT_ENCODED_BYTES);
    fp2_encode(encoded_ct + offset, &ct->EB_cof);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->EAB_cof);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->xPpls_B);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->xQpls_B);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->xPpls_AB);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->xQpls_AB);
    offset += FP2_ENCODED_BYTES;
    memcpy(encoded_ct + offset, ct->ct, PIKE_SHARED_SECRET_BYTES);

    return 1;
}

int ct_decode(pike_ct_t *ct, const unsigned char *encoded_ct)
{
    size_t offset = 0;

    memset(ct, 0, sizeof(*ct));
    fp2_decode(&ct->EB_cof, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&ct->EAB_cof, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&ct->xPpls_B, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&ct->xQpls_B, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&ct->xPpls_AB, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&ct->xQpls_AB, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    memcpy(ct->ct, encoded_ct + offset, PIKE_SHARED_SECRET_BYTES);

    return 1;
}

int pk_encode(unsigned char *out, pike_pk_t *pk)
{
    size_t offset = 0;

    memset(out, 0, PIKE_PK_ENCODED_BYTES);
    fp2_encode(out + offset, &pk->xPpls);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(out + offset, &pk->xQpls);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(out + offset, &pk->xPmin);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(out + offset, &pk->xQmin);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(out + offset, &pk->xPQmin);
    offset += FP2_ENCODED_BYTES;
    out[offset++] = pk->label_pls ? 1 : 0;

    return 1;
}

int pk_decode(pike_pk_t *pk, const unsigned char *in)
{
    size_t offset = 0;

    memset(pk, 0, sizeof(*pk));
    fp2_decode(&pk->xPpls, in + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&pk->xQpls, in + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&pk->xPmin, in + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&pk->xQmin, in + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&pk->xPQmin, in + offset);
    offset += FP2_ENCODED_BYTES;
    pk->label_pls = in[offset++] ? true : false;

    return 1;
}

int sk_encode(unsigned char *out, const pike_sk_t *sk)
{
    size_t offset = 0;

    encode_scalar_le(out + offset, sk->deg, PIKE_SEC_TWOPOW_BYTES);
    offset += PIKE_SEC_TWOPOW_BYTES;
    encode_scalar_le(out + offset, sk->alpha, PIKE_SEC_TWOPOW_BYTES);
    offset += PIKE_SEC_TWOPOW_BYTES;
    encode_scalar_le(out + offset, sk->beta, PIKE_SEC_TWOPOW_BYTES);
    offset += PIKE_SEC_TWOPOW_BYTES;
    encode_scalar_le(out + offset, sk->iota, PIKE_SEC_TORSION_D_BYTES);

    return 1;
}

int sk_decode(pike_sk_t *sk, const unsigned char *in)
{
    size_t offset = 0;

    memset(sk, 0, sizeof(*sk));
    decode_scalar_le(sk->deg, NWORDS_ORDER, in + offset, PIKE_SEC_TWOPOW_BYTES);
    offset += PIKE_SEC_TWOPOW_BYTES;
    decode_scalar_le(sk->alpha, NWORDS_ORDER, in + offset, PIKE_SEC_TWOPOW_BYTES);
    offset += PIKE_SEC_TWOPOW_BYTES;
    decode_scalar_le(sk->beta, NWORDS_ORDER, in + offset, PIKE_SEC_TWOPOW_BYTES);
    offset += PIKE_SEC_TWOPOW_BYTES;
    decode_scalar_le(sk->iota, NWORDS_ORDER, in + offset, PIKE_SEC_TORSION_D_BYTES);

    return 1;
}

int encaps(unsigned char *key, pike_ct_t *ct, const pike_pk_t *pk)
{
    unsigned char m[PIKE_SHARED_SECRET_BYTES];
    unsigned char gm[PIKE_SHARED_SECRET_BYTES];
    unsigned char encoded_ct[PIKE_SHARED_SECRET_BYTES + PIKE_CT_ENCODED_BYTES];

    randombytes(m, PIKE_SHARED_SECRET_BYTES);
    pike_xof(gm, PIKE_SHARED_SECRET_BYTES, m, PIKE_SHARED_SECRET_BYTES);
    encrypt(ct, pk, m, PIKE_SHARED_SECRET_BYTES, gm, PIKE_SHARED_SECRET_BYTES);
    memcpy(encoded_ct, m, PIKE_SHARED_SECRET_BYTES);
    ct_encode(encoded_ct + PIKE_SHARED_SECRET_BYTES, ct);
    pike_xof(key, PIKE_SHARED_SECRET_BYTES, encoded_ct, PIKE_SHARED_SECRET_BYTES + PIKE_CT_ENCODED_BYTES);
    return 1;
}

int decaps(unsigned char *key, pike_ct_t *ct, const pike_pk_t *pk, const pike_sk_t *sk, unsigned char *dummy_m)
{
    unsigned char m[PIKE_SHARED_SECRET_BYTES];
    unsigned char gm[PIKE_SHARED_SECRET_BYTES];
    unsigned char test_ct_bytes[PIKE_CT_ENCODED_BYTES];
    unsigned char ct_bytes[PIKE_SHARED_SECRET_BYTES + PIKE_CT_ENCODED_BYTES];
    size_t m_len;
    pike_ct_t test_ct = {0};

    decrypt(m, &m_len, ct, sk);
    pike_xof(gm, PIKE_SHARED_SECRET_BYTES, m, PIKE_SHARED_SECRET_BYTES);
    encrypt(&test_ct, pk, m, m_len, gm, PIKE_SHARED_SECRET_BYTES);
    ct_encode(test_ct_bytes, &test_ct);
    ct_encode(ct_bytes + PIKE_SHARED_SECRET_BYTES, ct);
    if (memcmp(ct_bytes + PIKE_SHARED_SECRET_BYTES, test_ct_bytes, PIKE_CT_ENCODED_BYTES) != 0)
    {
        memcpy(ct_bytes, dummy_m, PIKE_SHARED_SECRET_BYTES);
    }
    else
    {
        memcpy(ct_bytes, m, PIKE_SHARED_SECRET_BYTES);
    }
    pike_xof(key, PIKE_SHARED_SECRET_BYTES, ct_bytes, PIKE_SHARED_SECRET_BYTES + PIKE_CT_ENCODED_BYTES);

    return 1;
}
