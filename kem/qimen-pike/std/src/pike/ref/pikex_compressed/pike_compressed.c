#include <pike_compressed.h>
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

static void fp2_encode_curve_A_normalized(unsigned char *out, const ec_curve_t *curve)
{
    fp2_t A;
    fp2_t C_inv;

    fp2_copy(&A, &curve->A);
    fp2_copy(&C_inv, &curve->C);
    fp2_inv(&C_inv);
    fp2_mul(&A, &A, &C_inv);
    fp2_encode(out, &A);
}

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
    ibz_t q, alpha, beta, iota, gamma, rhs, deg, tmp1, tmp2, tmp3, tmp4, tmp5, scalar, remainder, A, q_bound, tmpTpls, tmpTplsmod, tmpTplsscl;
    quat_alg_elem_t tau;
    quat_left_ideal_t ideal;
    ec_point_t Ppls, Qpls, pointT, pointT1, pointT2, eval_points[3], Q2, QTpls, PmQtest;
    ec_basis_t E0_two, EA_Tmin;
    ec_basis_t PQTmin, PQpls, PQ2, PQTpls;
    ec_isog_odd_t isog;
    ec_curve_t curve = CURVE_E0, E1;
    digit_t d1[NWORDS_ORDER] = {0}, d2[NWORDS_ORDER] = {0}, d3[NWORDS_ORDER] = {0}, d4[NWORDS_ORDER] = {0}, dTORSION_PLUS_2POWER[NWORDS_ORDER] = {0}, dTORSION_D[NWORDS_ORDER] = {0}, dTORSION_ODD_PLUS[NWORDS_ORDER] = {0}, dalpha[NWORDS_ORDER] = {0}, dbeta[NWORDS_ORDER] = {0}, scltwo1[NWORDS_ORDER] = {0}, scltwo2[NWORDS_ORDER] = {0}, sclTpls1[NWORDS_ORDER] = {0}, sclTpls2[NWORDS_ORDER] = {0}, sclminP1[NWORDS_ORDER] = {0}, sclminP2[NWORDS_ORDER] = {0}, sclminQ1[NWORDS_ORDER] = {0}, sclminQ2[NWORDS_ORDER] = {0};
    theta_couple_curve_t E01;
    theta_couple_point_t T1, T2, T1m2, tmpS, tmpT1, tmpT2, tmpT3, output_points[3], input_points[3];
    theta_chain_t hd_isog;
    fp2_t fp2inv;

    ibz_init(&q);
    ibz_init(&alpha);
    ibz_init(&beta);
    ibz_init(&iota);
    ibz_init(&gamma);
    ibz_init(&rhs);
    ibz_init(&deg);
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    ibz_init(&tmp3);
    ibz_init(&tmp4);
    ibz_init(&tmp5);
    ibz_init(&A);
    ibz_init(&q_bound);
    ibz_init(&scalar);
    ibz_init(&remainder);
    ibz_init(&tmpTpls);
    ibz_init(&tmpTplsmod);
    ibz_init(&tmpTplsscl);
    quat_alg_elem_init(&tau);
    quat_left_ideal_init(&ideal);
    ibz_div_2exp(&A, &TORSION_PLUS_2POWER, 2);
    ibz_div_2exp(&q_bound, &TORSION_PLUS_2POWER, 4);
    ibz_to_digits(dTORSION_PLUS_2POWER, &TORSION_PLUS_2POWER);
    ibz_to_digits(dTORSION_ODD_PLUS, &TORSION_ODD_PLUS);
    ibz_to_digits(dTORSION_D, &TORSION_D);
    for (int i = 0; i < P_COFACTOR_FOR_TWOPOW_LEN; i++)
    {
        pk->scl2[i] = 0;
    }
    for (int i = 0; i < P_COFACTOR_FOR_TPLS_LEN; i++)
    {
        pk->sclTpls[i] = 0;
    }
    for (int i = 0; i < P_COFACTOR_FOR_TMIN_LEN; i++)
    {
        pk->sclmin1[i] = 0;
        pk->sclmin2[i] = 0;
        pk->sclmin3[i] = 0;
    }
    // Set q to a random value in the range [0, TORSION_PLUS_2POWER)
    // q(A-q) is coprime to 2 * TORSION_ODD_PLUS * TORSION_ODD_MINUS * TORSION_D
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
    ibz_random_unit(&gamma, &TORSION_ODD_PLUS, NULL);
    ibz_random_unit(&iota, &TORSION_D, NULL);
    memset(sk->deg, 0, sizeof(sk->deg));
    memset(sk->alpha, 0, sizeof(sk->alpha));
    memset(sk->beta, 0, sizeof(sk->beta));
    memset(sk->iota, 0, sizeof(sk->iota));
    ibz_to_digits(sk->deg, &q);
    ibz_to_digits(sk->alpha, &alpha);
    ibz_to_digits(sk->beta, &beta);
    ibz_to_digits(sk->iota, &iota);

    ibz_crt(&alpha, &alpha, &gamma, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    ibz_crt(&beta, &beta, &gamma, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);

    // generate the endomorphism tau, which has degree q * (A-q) * TORSION_ODD_MINUS^2
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

    // Evaluating the theta-based 2-dim isogeny
    E01.E1 = curve;
    E01.E2 = E1;
    T1.P1 = BASIS_EVEN.P;
    T2.P1 = BASIS_EVEN.Q;
    T1m2.P1 = BASIS_EVEN.PmQ;
    ibz_mul(&scalar, &TORSION_ODD_MINUS, &TORSION_ODD_PLUS);
    ibz_mul(&scalar, &q, &scalar);
    ibz_mod(&scalar, &scalar, &TORSION_PLUS_2POWER);
    ibz_to_digits(d1, &scalar);
    ec_mul(&T1.P1, &curve, d1, TORSION_PLUS_2POWER->_mp_size, &T1.P1);
    ec_mul(&T2.P1, &curve, d1, TORSION_PLUS_2POWER->_mp_size, &T2.P1);
    ec_mul(&T1m2.P1, &curve, d1, TORSION_PLUS_2POWER->_mp_size, &T1m2.P1);
    theta_chain_comput_strategy(&hd_isog, TORSION_PLUS_EVEN_POWER - 2, &E01, &T1, &T2, &T1m2, strategies[2], 1);

    copy_point(&EA_Tmin.P, &BASIS_ODD_MINUS.P);
    copy_point(&EA_Tmin.Q, &BASIS_ODD_MINUS.Q);
    copy_point(&EA_Tmin.PmQ, &BASIS_ODD_MINUS.PmQ);
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
    copy_point(&tmpS.P1, &EA_Tmin.P);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&EA_Tmin.P, &tmpS.P1);
    copy_point(&tmpS.P1, &EA_Tmin.Q);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&EA_Tmin.Q, &tmpS.P1);
    copy_point(&tmpS.P1, &EA_Tmin.PmQ);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&EA_Tmin.PmQ, &tmpS.P1);

    E01.E1 = hd_isog.codomain.E1;
    E01.E2 = hd_isog.codomain.E2;
    theta_chain_comput_strategy(&hd_isog, TORSION_PLUS_EVEN_POWER - 2, &E01, &output_points[0], &output_points[1], &output_points[2], strategies[2], 1);

    copy_point(&tmpS.P1, &EA_Tmin.P);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&EA_Tmin.P, &tmpS.P1);
    copy_point(&tmpS.P1, &EA_Tmin.Q);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&EA_Tmin.Q, &tmpS.P1);
    copy_point(&tmpS.P1, &EA_Tmin.PmQ);
    ec_set_zero(&tmpS.P2);
    theta_chain_eval_special_case(&tmpS, &hd_isog, &tmpS, &E01);
    copy_point(&EA_Tmin.PmQ, &tmpS.P1);
    copy_curve(&E1, &hd_isog.codomain.E1);
    fp2_inv(&E1.C);
    fp2_mul(&E1.A, &E1.A, &E1.C);
    fp2_set_one(&E1.C);
    ec_curve_normalize_A24(&E1);
    fp2_copy(&pk->EA_cof, &E1.A);

    // Now we compress the public key
    ec_curve_to_basis_Tmin_to_hint(&PQTmin, &E1, TORSION_MINUS_ODD_PRIMES, M_LEN, pk->hintmin);
    ec_dlog_Tmin_tate(sclminP1, sclminQ1, sclminP2, sclminQ2, &PQTmin, &EA_Tmin, &E1);

    ibz_copy_digits(&tmp1, sclminP1, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, sclminQ1, NWORDS_ORDER);
    ibz_copy_digits(&tmp3, sclminP2, NWORDS_ORDER);
    ibz_copy_digits(&tmp4, sclminQ2, NWORDS_ORDER);
    ibz_add(&tmp4, &tmp4, &TORSION_ODD_MINUS);
    ibz_sub(&tmp4, &tmp4, &tmp2);
    ibz_mod(&tmp4, &tmp4, &TORSION_ODD_MINUS);
    ibz_add(&tmp3, &tmp3, &TORSION_ODD_MINUS);
    ibz_sub(&tmp3, &tmp3, &tmp1);
    ibz_mod(&tmp3, &tmp3, &TORSION_ODD_MINUS);
    ibz_to_digits(d3, &tmp3);
    ibz_to_digits(d4, &tmp4);

    xDBLMUL_bounded(&PmQtest, &PQTmin.P, d3, &PQTmin.Q, d4, &PQTmin.PmQ, &E1, TORSION_ODD_MINUS->_mp_size);
    int sclminPmQ_label = 0;

    if (!ec_is_equal(&EA_Tmin.PmQ, &PmQtest))
    {
        sclminPmQ_label = 1;
    }

    ibz_copy_digits(&tmp1, sclminP1, NWORDS_ORDER);
    ibz_mod(&tmp1, &tmp1, &TORSION_MINUS_PRIME);

    // further compress the EA_Tmin information by inversing one of the scalars
    if (ibz_is_zero(&tmp1))
    {
        pk->sclmin_label = 1;
        ibz_copy_digits(&tmp1, sclminQ1, NWORDS_ORDER);
        ibz_invmod(&tmp1, &tmp1, &TORSION_ODD_MINUS);
        ibz_copy_digits(&tmp2, sclminP1, NWORDS_ORDER);
        ibz_mul(&tmp2, &tmp1, &tmp2);
        ibz_mod(&tmp2, &tmp2, &TORSION_ODD_MINUS);
        ibz_to_digits(pk->sclmin1, &tmp2);
    }
    else
    {
        pk->sclmin_label = 0;
        ibz_copy_digits(&tmp1, sclminP1, NWORDS_ORDER);
        ibz_invmod(&tmp1, &tmp1, &TORSION_ODD_MINUS);
        ibz_copy_digits(&tmp2, sclminQ1, NWORDS_ORDER);
        ibz_mul(&tmp2, &tmp1, &tmp2);
        ibz_mod(&tmp2, &tmp2, &TORSION_ODD_MINUS);
        ibz_to_digits(pk->sclmin1, &tmp2);
    }
    ibz_copy_digits(&tmp2, sclminP2, NWORDS_ORDER);
    if (sclminPmQ_label == 1)
    {
        ibz_sub(&tmp2, &TORSION_ODD_MINUS, &tmp2);
    }
    ibz_mul(&tmp2, &tmp1, &tmp2);
    ibz_mod(&tmp2, &tmp2, &TORSION_ODD_MINUS);
    ibz_to_digits(pk->sclmin2, &tmp2);
    ibz_copy_digits(&tmp2, sclminQ2, NWORDS_ORDER);
    if (sclminPmQ_label == 1)
    {
        ibz_sub(&tmp2, &TORSION_ODD_MINUS, &tmp2);
    }
    ibz_mul(&tmp2, &tmp1, &tmp2);
    ibz_mod(&tmp2, &tmp2, &TORSION_ODD_MINUS);
    ibz_to_digits(pk->sclmin3, &tmp2);

    ec_set_zero(&tmpT1.P2);
    theta_chain_eval_special_case(&tmpT1, &hd_isog, &tmpT1, &E01);
    ec_set_zero(&tmpT2.P2);
    theta_chain_eval_special_case(&tmpT2, &hd_isog, &tmpT2, &E01);
    ec_set_zero(&tmpT3.P2);
    theta_chain_eval_special_case(&tmpT3, &hd_isog, &tmpT3, &E01);

    ec_mul(&pointT, &E1, dTORSION_D, TORSION_D->_mp_size, &tmpT1.P1);
    xADD(&tmpT3.P1, &pointT, &tmpT2.P1, &tmpT3.P1);
    ibz_to_digits(dbeta, &beta);
    copy_point(&pointT1, &pointT);
    copy_point(&pointT2, &tmpT2.P1);
    ec_mul(&tmpT2.P1, &E1, dbeta, TORSION_PLUS_ODD_2POWER->_mp_size, &tmpT2.P1);

    copy_point(&Ppls, &tmpT1.P1);
    copy_point(&Qpls, &tmpT2.P1);

    ec_curve_to_basis_pls_to_hint(&PQpls, &E1, TORSION_PLUS_ODD_PRIMES, P_LEN, pk->hintpls);
    ec_mul(&PQ2.P, &E1, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &PQpls.P);
    ec_mul(&PQ2.Q, &E1, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &PQpls.Q);
    ec_mul(&PQ2.PmQ, &E1, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &PQpls.PmQ);
    ec_mul(&PQTpls.P, &E1, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &PQpls.P);
    ec_mul(&PQTpls.Q, &E1, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &PQpls.Q);
    ec_mul(&PQTpls.PmQ, &E1, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &PQpls.PmQ);

    copy_point(&Q2, &Qpls);
    copy_point(&QTpls, &Qpls);
    ec_mul(&Q2, &E1, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &Q2);
    ec_mul(&QTpls, &E1, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &QTpls);
    ec_dlog_2_weil_single(scltwo1, scltwo2, &PQ2, &Q2, &E1, TORSION_PLUS_EVEN_POWER);
    ec_dlog_Tpls_tate_single(sclTpls1, sclTpls2, &PQTpls, &QTpls, &E1);

    // further compress the power-of-2 torsion by inversion
    ibz_copy_digits(&tmp1, scltwo1, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, scltwo2, NWORDS_ORDER);
    ibz_copy_digits(&tmp3, sclTpls1, NWORDS_ORDER);
    ibz_copy_digits(&tmp4, sclTpls2, NWORDS_ORDER);
    ibz_crt(&tmp1, &tmp1, &tmp3, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    ibz_crt(&tmp2, &tmp2, &tmp4, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    memset(d1, 0, sizeof(d1));
    ibz_to_digits(d1, &tmp1);
    ibz_to_digits(d2, &tmp2);
    xDBLMUL_bounded(&pointT, &PQpls.P, d1, &PQpls.Q, d2, &PQpls.PmQ, &E1, TORSION_PLUS_ODD_2POWER->_mp_size);

    ibz_copy_digits(&tmp1, scltwo1, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, scltwo2, NWORDS_ORDER);
    if (!is_point_equal(&Qpls, &pointT))
    {
        ibz_sub(&tmp1, &TORSION_PLUS_2POWER, &tmp1);
        ibz_sub(&tmp2, &TORSION_PLUS_2POWER, &tmp2);
    }
    ibz_invmod(&tmp5, &tmp2, &TORSION_PLUS_2POWER);
    ibz_mul(&tmp1, &tmp5, &tmp1);
    ibz_mod(&tmp1, &tmp1, &TORSION_PLUS_2POWER);
    ibz_to_digits(pk->scl2, &tmp1);
    ibz_copy(&scalar, &tmp5);

    // further compress the Tpls torsion by inversion
    ibz_copy_digits(&tmp1, sclTpls1, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, sclTpls2, NWORDS_ORDER);
    pk->sclTpls_label = 0;
    for (int i = 0; i < P_LEN; i++)
    {
        ibz_copy_digits(&tmp4, &TORSION_ODD_PRIMES[i], 1);
        ibz_mod(&tmp4, &tmp1, &tmp4);
        if (ibz_is_zero(&tmp4))
        {
            pk->sclTpls_label = (1 << i) + pk->sclTpls_label;
            ibz_invmod(&tmp5, &tmp2, &TORSION_ODD_PRIMEPOWERS[i]);
            ibz_mul(&tmp3, &tmp5, &tmp1);
            ibz_mod(&tmp3, &tmp3, &TORSION_ODD_PRIMEPOWERS[i]);
        }
        else
        {
            ibz_invmod(&tmp5, &tmp1, &TORSION_ODD_PRIMEPOWERS[i]);
            ibz_mul(&tmp3, &tmp5, &tmp2);
            ibz_mod(&tmp3, &tmp3, &TORSION_ODD_PRIMEPOWERS[i]);
        }
        if (i == 0)
        {
            ibz_copy(&tmpTpls, &tmp3);
            ibz_copy(&tmpTplsscl, &tmp5);
            ibz_copy(&tmpTplsmod, &TORSION_ODD_PRIMEPOWERS[i]);
        }
        else
        {
            ibz_crt(&tmpTplsscl, &tmpTplsscl, &tmp5, &tmpTplsmod, &TORSION_ODD_PRIMEPOWERS[i]);
            ibz_crt(&tmpTpls, &tmpTpls, &tmp3, &tmpTplsmod, &TORSION_ODD_PRIMEPOWERS[i]);
            ibz_mul(&tmpTplsmod, &TORSION_ODD_PRIMEPOWERS[i], &tmpTplsmod);
        }
    }
    ibz_to_digits(pk->sclTpls, &tmpTpls);
    ibz_crt(&tmp5, &tmpTplsscl, &scalar, &TORSION_ODD_PLUS, &TORSION_PLUS_2POWER);

    ibz_mul(&tmp1, &alpha, &tmp5);
    ibz_mod(&tmp1, &tmp1, &TORSION_PLUS_ODD_2POWER);
    ibz_mul(&tmp2, &beta, &tmp5);
    ibz_mod(&tmp2, &tmp2, &TORSION_PLUS_ODD_2POWER);
    memset(d1, 0, sizeof(d1));
    memset(d2, 0, sizeof(d2));
    ibz_to_digits(d1, &tmp1);
    ibz_to_digits(d2, &tmp2);
    xDBLMUL_bounded(&tmpT3.P1, &pointT1, d1, &pointT2, d2, &tmpT3.P1, &E1, TORSION_PLUS_ODD_2POWER->_mp_size);

    ibz_crt(&tmp5, &tmp5, &ibz_const_one, &TORSION_PLUS_ODD_2POWER, &TORSION_D);
    ibz_crt(&alpha, &alpha, &iota, &TORSION_PLUS_ODD_2POWER, &TORSION_D);
    ibz_mul(&alpha, &alpha, &tmp5);
    ibz_mod(&alpha, &alpha, &TORSION_PLUS_ODD_D_2POWER);
    ibz_to_digits(dalpha, &alpha);
    ec_mul(&Ppls, &E1, dalpha, TORSION_PLUS_ODD_D_2POWER->_mp_size, &Ppls);
    ec_normalize_point(&Ppls);
    fp2_copy(&pk->xPpls, &Ppls.x);

    ec_mul(&tmpT1.P1, &E1, dTORSION_D, TORSION_D->_mp_size, &Ppls);

    ibz_copy_digits(&tmp1, pk->scl2, P_COFACTOR_FOR_TWOPOW_LEN);
    ibz_copy(&tmp2, &ibz_const_one);

    ibz_copy_digits(&tmpTpls, pk->sclTpls, P_COFACTOR_FOR_TPLS_LEN);
    for (int i = 0; i < P_LEN; i++)
    {
        if (i == 0)
        {
            if (pk->sclTpls_label & (1 << i))
            {
                ibz_copy(&tmp4, &ibz_const_one);
                ibz_mod(&tmp3, &tmpTpls, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_copy(&tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
            else
            {
                ibz_copy(&tmp3, &ibz_const_one);
                ibz_mod(&tmp4, &tmpTpls, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_copy(&tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
        }
        else
        {
            if (pk->sclTpls_label & (1 << i))
            {
                ibz_crt(&tmp4, &tmp4, &ibz_const_one, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_crt(&tmp3, &tmp3, &tmpTpls, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
            else
            {
                ibz_crt(&tmp3, &tmp3, &ibz_const_one, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_crt(&tmp4, &tmp4, &tmpTpls, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
            ibz_mul(&tmp5, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
        }
    }

    ibz_crt(&tmp1, &tmp1, &tmp3, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    ibz_crt(&tmp2, &tmp2, &tmp4, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    memset(d1, 0, sizeof(d1));
    memset(d2, 0, sizeof(d2));
    ibz_to_digits(d1, &tmp1);
    ibz_to_digits(d2, &tmp2);
    xDBLMUL_bounded(&tmpT2.P1, &PQpls.P, d1, &PQpls.Q, d2, &PQpls.PmQ, &E1, TORSION_PLUS_ODD_2POWER->_mp_size);

    fp2_mul(&fp2inv, &tmpT1.P1.z, &tmpT2.P1.z);
    fp2_inv(&fp2inv);
    fp2_mul(&tmpT1.P1.x, &fp2inv, &tmpT1.P1.x);
    fp2_mul(&tmpT1.P1.x, &tmpT2.P1.z, &tmpT1.P1.x);
    fp2_mul(&tmpT2.P1.x, &fp2inv, &tmpT2.P1.x);
    fp2_mul(&tmpT2.P1.x, &tmpT1.P1.z, &tmpT2.P1.x);
    fp2_set_one(&tmpT1.P1.z);
    fp2_set_one(&tmpT2.P1.z);
    difference_point(&pointT, &tmpT1.P1, &tmpT2.P1, &E1);
    pk->sclpls_label = is_point_equal(&pointT, &tmpT3.P1);

    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
    ibz_finalize(&q);
    ibz_finalize(&alpha);
    ibz_finalize(&beta);
    ibz_finalize(&iota);
    ibz_finalize(&gamma);
    ibz_finalize(&rhs);
    ibz_finalize(&deg);
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
    ibz_finalize(&tmp3);
    ibz_finalize(&tmp4);
    ibz_finalize(&tmp5);
    ibz_finalize(&tmpTpls);
    ibz_finalize(&tmpTplsmod);
    ibz_finalize(&tmpTplsscl);
    ibz_finalize(&A);
    ibz_finalize(&q_bound);
    quat_alg_elem_finalize(&tau);
    quat_left_ideal_finalize(&ideal);
    return 1;
}

int pike_encrypt(pike_ct_t *ct, const pike_pk_t *pk, const unsigned char *m, const size_t m_len, const unsigned char *seed, const size_t seed_len)
{
    ec_isog_odd_t isogB1, isogB2;
    ibz_t beta1, beta2, omega, omega_inv, A, t1, t2, t1t2, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
    ec_curve_t EB, EAB;
    ec_basis_t EA_Tpls, EA_Tmin;
    ec_basis_t PQ2_B, PQ2_AB, PQpls, PQTmin;
    ec_point_t eval_points[2], Ppls_B, Ppls_AB, Qpls, Qpls_B, Qpls_AB;
    pike_xof_ctx_t state;
    digit_t beta1_scalar[NWORDS_ORDER] = {0}, beta2_scalar[NWORDS_ORDER] = {0}, omega_scalar[NWORDS_ORDER] = {0}, omega_inv_scalar[NWORDS_ORDER] = {0}, t1_scalar[NWORDS_ORDER] = {0}, t2_scalar[NWORDS_ORDER] = {0}, dTORSION_ODD_PLUS[NWORDS_ORDER] = {0}, dTORSION_PLUS_2POWER[NWORDS_ORDER] = {0}, dTORSION_D[NWORDS_ORDER] = {0}, exp[NWORDS_ORDER] = {0}, d1[NWORDS_ORDER] = {0}, d2[NWORDS_ORDER] = {0}, d3[NWORDS_ORDER] = {0}, d4[NWORDS_ORDER] = {0}, dpls1t[NWORDS_ORDER] = {0}, dpls2t[NWORDS_ORDER] = {0};
    fp2_t fp2inv, shared_sec;

    ibz_init(&beta1);
    ibz_init(&beta2);
    ibz_init(&omega);
    ibz_init(&omega_inv);
    ibz_init(&A);
    ibz_init(&t1);
    ibz_init(&t2);
    ibz_init(&t1t2);
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    ibz_init(&tmp3);
    ibz_init(&tmp4);
    ibz_init(&tmp5);
    ibz_init(&tmp6);
    ibz_to_digits(dTORSION_PLUS_2POWER, &TORSION_PLUS_2POWER);
    ibz_to_digits(dTORSION_ODD_PLUS, &TORSION_ODD_PLUS);
    ibz_to_digits(dTORSION_D, &TORSION_D);

    memset(ct, 0, sizeof(*ct));
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

    fp2_inv(&EB.C);
    fp2_mul(&EB.A, &EB.A, &EB.C);
    fp2_set_one(&EB.C);
    fp2_copy(&ct->EB_cof, &EB.A);
    // Masking evaluated points
    ec_mul(&Ppls_B, &EB, omega_scalar, TORSION_PLUS_2POWER->_mp_size, &eval_points[0]);
    ec_curve_to_basis_2f_to_hint(&PQ2_B, &EB, TORSION_PLUS_EVEN_POWER, ct->hint_B);
    ec_dlog_2_weil_single(d1, d2, &PQ2_B, &Ppls_B, &EB, TORSION_PLUS_EVEN_POWER);
    ibz_copy_digits(&tmp1, d1, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, d2, NWORDS_ORDER);
    ibz_invmod(&tmp2, &tmp2, &TORSION_PLUS_2POWER);
    ibz_mul(&tmp1, &tmp1, &tmp2);
    ibz_mod(&tmp1, &tmp1, &TORSION_PLUS_2POWER);
    ibz_to_digits(ct->scl2_B, &tmp1);
    ibz_mul(&omega_inv, &omega_inv, &tmp2);

    ibz_crt(&t1, &t1, &omega_inv, &TORSION_D, &TORSION_PLUS_2POWER);
    ibz_to_digits(t1_scalar, &t1);
    ec_mul(&Qpls_B, &EB, t1_scalar, TORSION_PLUS_D_2POWER->_mp_size, &eval_points[1]);
    ec_normalize_point(&Qpls_B);
    fp2_copy(&ct->xQpls_B, &Qpls_B.x);

    // compute the isogeny from EA to EAB
    fp2_copy(&isogB2.curve.A, &pk->EA_cof);
    fp2_set_one(&isogB2.curve.C);
    isogB2.curve.is_A24_computed_and_normalized = false;
    ec_curve_normalize_A24(&isogB2.curve);
    ec_curve_to_basis_Tmin_from_hint(&PQTmin, &isogB2.curve, TORSION_MINUS_ODD_PRIMES, M_LEN, (int *)pk->hintmin);

    ibz_copy_digits(&tmp1, pk->sclmin1, P_COFACTOR_FOR_TMIN_LEN);
    ibz_copy_digits(&tmp2, pk->sclmin2, P_COFACTOR_FOR_TMIN_LEN);
    ibz_copy_digits(&tmp3, pk->sclmin3, P_COFACTOR_FOR_TMIN_LEN);

    ec_curve_to_basis_pls_from_hint(&PQpls, &isogB2.curve, TORSION_PLUS_ODD_PRIMES, P_LEN, (int *)pk->hintpls);
    // recover the Tmin-torsion
    ibz_to_digits(d2, &tmp2);
    ibz_to_digits(d3, &tmp3);
    xDBLMUL_bounded(&EA_Tmin.Q, &PQTmin.P, d2, &PQTmin.Q, d3, &PQTmin.PmQ, &isogB2.curve, TORSION_ODD_MINUS->_mp_size);
    if (pk->sclmin_label)
    {
        ibz_to_digits(d1, &tmp1);
        ec_ladder3pt_bounded(&EA_Tmin.P, d1, &PQTmin.Q, &PQTmin.P, &PQTmin.PmQ, &isogB2.curve, TORSION_ODD_MINUS->_mp_size);
        ibz_add(&tmp2, &tmp2, &TORSION_ODD_MINUS);
        ibz_sub(&tmp2, &tmp2, &tmp1);
        ibz_mod(&tmp2, &tmp2, &TORSION_ODD_MINUS);
        ibz_add(&tmp3, &tmp3, &TORSION_ODD_MINUS);
        ibz_sub(&tmp3, &tmp3, &ibz_const_one);
        ibz_mod(&tmp3, &tmp3, &TORSION_ODD_MINUS);
    }
    else
    {
        ibz_to_digits(d1, &tmp1);
        ec_ladder3pt_bounded(&EA_Tmin.P, d1, &PQTmin.P, &PQTmin.Q, &PQTmin.PmQ, &isogB2.curve, TORSION_ODD_MINUS->_mp_size);
        ibz_add(&tmp2, &tmp2, &TORSION_ODD_MINUS);
        ibz_sub(&tmp2, &tmp2, &ibz_const_one);
        ibz_mod(&tmp2, &tmp2, &TORSION_ODD_MINUS);
        ibz_add(&tmp3, &tmp3, &TORSION_ODD_MINUS);
        ibz_sub(&tmp3, &tmp3, &tmp1);
        ibz_mod(&tmp3, &tmp3, &TORSION_ODD_MINUS);
    }

    memset(d1, 0, sizeof(d1));
    memset(d2, 0, sizeof(d2));
    memset(d3, 0, sizeof(d3));
    ibz_to_digits(d1, &tmp2);
    ibz_to_digits(d2, &tmp3);
    xDBLMUL_bounded(&EA_Tmin.PmQ, &PQTmin.P, d1, &PQTmin.Q, d2, &PQTmin.PmQ, &isogB2.curve, TORSION_ODD_MINUS->_mp_size);
    for (int i = 0; i < P_LEN; i++)
    {
        isogB2.degree[i] = TORSION_PLUS_ODD_POWERS[i];
    }
    for (int i = 0; i < M_LEN; i++)
    {
        isogB2.degree[P_LEN + i] = TORSION_MINUS_ODD_POWERS[i];
    }

    fp2_copy(&Ppls_AB.x, &pk->xPpls);
    fp2_set_one(&Ppls_AB.z);

    // recover Qpls defined on EA
    ibz_copy_digits(&tmp1, pk->scl2, P_COFACTOR_FOR_TWOPOW_LEN);
    ibz_copy(&tmp2, &ibz_const_one);

    ibz_copy_digits(&tmp6, pk->sclTpls, P_COFACTOR_FOR_TPLS_LEN);
    for (int i = 0; i < P_LEN; i++)
    {
        if (i == 0)
        {
            if (pk->sclTpls_label & (1 << i))
            {
                ibz_copy(&tmp4, &ibz_const_one);
                ibz_mod(&tmp3, &tmp6, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_copy(&tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
            else
            {
                ibz_copy(&tmp3, &ibz_const_one);
                ibz_mod(&tmp4, &tmp6, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_copy(&tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
        }
        else
        {
            if (pk->sclTpls_label & (1 << i))
            {
                ibz_crt(&tmp4, &tmp4, &ibz_const_one, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_crt(&tmp3, &tmp3, &tmp6, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
            else
            {
                ibz_crt(&tmp3, &tmp3, &ibz_const_one, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
                ibz_crt(&tmp4, &tmp4, &tmp6, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
            }
            ibz_mul(&tmp5, &tmp5, &TORSION_ODD_PRIMEPOWERS[i]);
        }
    }

    ibz_crt(&tmp1, &tmp1, &tmp3, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    ibz_crt(&tmp2, &tmp2, &tmp4, &TORSION_PLUS_2POWER, &TORSION_ODD_PLUS);
    ibz_to_digits(dpls1t, &tmp1);
    ibz_to_digits(dpls2t, &tmp2);
    xDBLMUL_bounded(&Qpls, &PQpls.P, dpls1t, &PQpls.Q, dpls2t, &PQpls.PmQ, &isogB2.curve, TORSION_PLUS_ODD_2POWER->_mp_size);

    ec_mul(&EA_Tpls.P, &isogB2.curve, dTORSION_D, TORSION_D->_mp_size, &Ppls_AB);
    copy_point(&EA_Tpls.Q, &Qpls);

    fp2_mul(&fp2inv, &EA_Tpls.P.z, &EA_Tpls.Q.z);
    fp2_inv(&fp2inv);
    fp2_mul(&EA_Tpls.P.x, &fp2inv, &EA_Tpls.P.x);
    fp2_mul(&EA_Tpls.P.x, &EA_Tpls.Q.z, &EA_Tpls.P.x);
    fp2_mul(&EA_Tpls.Q.x, &fp2inv, &EA_Tpls.Q.x);
    fp2_mul(&EA_Tpls.Q.x, &EA_Tpls.P.z, &EA_Tpls.Q.x);
    fp2_set_one(&EA_Tpls.P.z);
    fp2_set_one(&EA_Tpls.Q.z);

    difference_point(&EA_Tpls.PmQ, &EA_Tpls.P, &EA_Tpls.Q, &isogB2.curve);
    if (pk->sclpls_label == 0)
    {
        xADD(&EA_Tpls.PmQ, &EA_Tpls.P, &EA_Tpls.Q, &EA_Tpls.PmQ);
    }

    ec_ladder3pt_bounded(&isogB2.ker_plus, beta1_scalar, &EA_Tpls.P, &EA_Tpls.Q, &EA_Tpls.PmQ, &isogB2.curve, TORSION_ODD_PLUS->_mp_size);
    ec_mul(&isogB2.ker_plus, &isogB2.curve, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &isogB2.ker_plus);

    ec_ladder3pt_bounded(&isogB2.ker_minus, beta2_scalar, &EA_Tmin.P, &EA_Tmin.Q, &EA_Tmin.PmQ, &isogB2.curve, TORSION_ODD_MINUS->_mp_size);
    ec_mul(&eval_points[0], &isogB2.curve, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &Ppls_AB);
    ec_mul(&eval_points[1], &isogB2.curve, dTORSION_ODD_PLUS, TORSION_ODD_PLUS->_mp_size, &Qpls);
    ec_eval_odd(&EAB, &isogB2, eval_points, 2);

    fp2_inv(&EAB.C);
    fp2_mul(&EAB.A, &EAB.A, &EAB.C);
    fp2_set_one(&EAB.C);
    fp2_copy(&ct->EAB_cof, &EAB.A);
    // Masking evaluated points
    ec_mul(&Qpls_AB, &EAB, omega_inv_scalar, TORSION_PLUS_2POWER->_mp_size, &eval_points[1]);

    ec_curve_to_basis_2f_to_hint(&PQ2_AB, &EAB, TORSION_PLUS_EVEN_POWER, ct->hint_AB);
    ec_dlog_2_weil_single(d3, d4, &PQ2_AB, &Qpls_AB, &EAB, TORSION_PLUS_EVEN_POWER);

    ibz_copy_digits(&tmp1, d3, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, d4, NWORDS_ORDER);
    ibz_invmod(&tmp1, &tmp1, &TORSION_PLUS_2POWER);
    ibz_mul(&tmp2, &tmp1, &tmp2);
    ibz_mod(&tmp2, &tmp2, &TORSION_PLUS_2POWER);
    ibz_to_digits(ct->scl2_AB, &tmp2);
    ibz_mul(&omega, &omega, &tmp1);
    ibz_crt(&t2, &t2, &omega, &TORSION_D, &TORSION_PLUS_2POWER);
    ibz_to_digits(t2_scalar, &t2);
    ec_mul(&Ppls_AB, &EAB, t2_scalar, TORSION_PLUS_D_2POWER->_mp_size, &eval_points[0]);
    ec_normalize_point(&Ppls_AB);
    fp2_copy(&ct->xPpls_AB, &Ppls_AB.x);

    // Compute the ciphertext
    unsigned char hash_input[FP_NBYTES] = {0};
    unsigned char hash_output[PIKE_COMPRESSED_SHARED_SECRET_BYTES] = {0};
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
    for (size_t i = 0; i < PIKE_COMPRESSED_SHARED_SECRET_BYTES; i++)
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
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
    ibz_finalize(&tmp3);
    ibz_finalize(&tmp4);
    ibz_finalize(&tmp5);
    ibz_finalize(&tmp6);
    ibz_finalize(&t1);
    ibz_finalize(&t2);
    ibz_finalize(&t1t2);
    ibz_finalize(&omega);
    ibz_finalize(&omega_inv);
    return 1;
}

int decrypt(unsigned char *m, size_t *m_len, const pike_ct_t *ct, const pike_sk_t *sk)
{
    unsigned char hash_input[FP_NBYTES] = {0};
    unsigned char hash_output[PIKE_COMPRESSED_SHARED_SECRET_BYTES] = {0};
    digit_t d1[NWORDS_ORDER] = {0}, d2[NWORDS_ORDER] = {0}, dTORSION_D[NWORDS_ORDER] = {0}, dTORSION_PLUS_2POWER[NWORDS_ORDER] = {0}, dscalar[NWORDS_ORDER] = {0}, exp[NWORDS_ORDER] = {0}, dres[NWORDS_ORDER] = {0};
    theta_chain_t hd_isog;
    theta_couple_curve_t EBAB;
    theta_couple_point_t T1, T2, T1m2, eval_couple_point;
    ibz_t deg_alpha_inv, deg_beta_inv, deg, iota, A, d, tmp, ressqr, res, restmp;
    ec_point_t Psmid, Qsmid, PmQsmid, Ppls_B, Qpls_B, Ppls_AB, Qpls_AB;
    fp2_t fp2inv, fp2tmp1, fp2tmp2, r1, r2, shared_sec;
    ec_basis_t PQ2_B, PQ2_AB;

    ibz_init(&deg_alpha_inv);
    ibz_init(&deg_beta_inv);
    ibz_init(&deg);
    ibz_init(&iota);
    ibz_init(&A);
    ibz_init(&d);
    ibz_init(&tmp);
    ibz_init(&ressqr);
    ibz_init(&res);
    ibz_init(&restmp);

    ibz_copy_digits(&deg, sk->deg, SECRET_FOR_TWOPOW_LEN);
    ibz_div_2exp(&A, &TORSION_PLUS_2POWER, 2);
    ibz_copy_digits(&deg_alpha_inv, sk->alpha, SECRET_FOR_TWOPOW_LEN);
    ibz_copy_digits(&deg_beta_inv, sk->beta, SECRET_FOR_TWOPOW_LEN);
    ibz_mul(&deg_alpha_inv, &deg, &deg_alpha_inv);
    ibz_mul(&deg_beta_inv, &deg, &deg_beta_inv);
    ibz_invmod(&deg_alpha_inv, &deg_alpha_inv, &TORSION_PLUS_2POWER);
    ibz_invmod(&deg_beta_inv, &deg_beta_inv, &TORSION_PLUS_2POWER);

    ibz_sub(&d, &A, &deg);
    ibz_mul(&d, &deg, &d);
    ibz_mod(&d, &d, &TORSION_D);
    ibz_copy_digits(&iota, sk->iota, SECRET_FOR_TORSION_D_LEN);
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

    ec_curve_to_basis_2f_from_hint(&PQ2_B, &EBAB.E1, TORSION_PLUS_EVEN_POWER, (int *)ct->hint_B);
    ibz_copy_digits(&tmp, ct->scl2_B, P_COFACTOR_FOR_TWOPOW_LEN);
    ibz_to_digits(dscalar, &tmp);
    ec_ladder3pt_bounded(&Ppls_B, dscalar, &PQ2_B.Q, &PQ2_B.P, &PQ2_B.PmQ, &EBAB.E1, TORSION_PLUS_2POWER->_mp_size);
    memset(dscalar, 0, sizeof(dscalar));
    copy_point(&T1.P1, &Ppls_B);

    fp2_copy(&Qpls_B.x, &ct->xQpls_B);
    fp2_set_one(&Qpls_B.z);
    ec_mul(&T2.P1, &EBAB.E1, dTORSION_D, TORSION_D->_mp_size, &Qpls_B);

    fp2_mul(&fp2inv, &T1.P1.z, &T2.P1.z);
    fp2_inv(&fp2inv);
    fp2_mul(&T1.P1.x, &fp2inv, &T1.P1.x);
    fp2_mul(&T1.P1.x, &T2.P1.z, &T1.P1.x);
    fp2_mul(&T2.P1.x, &fp2inv, &T2.P1.x);
    fp2_mul(&T2.P1.x, &T1.P1.z, &T2.P1.x);
    fp2_set_one(&T1.P1.z);
    fp2_set_one(&T2.P1.z);
    difference_point(&T1m2.P1, &T1.P1, &T2.P1, &EBAB.E1);

    fp2_copy(&Ppls_AB.x, &ct->xPpls_AB);
    fp2_set_one(&Ppls_AB.z);

    ec_curve_to_basis_2f_from_hint(&PQ2_AB, &EBAB.E2, TORSION_PLUS_EVEN_POWER, (int *)ct->hint_AB);
    ibz_copy_digits(&tmp, ct->scl2_AB, P_COFACTOR_FOR_TWOPOW_LEN);
    ibz_to_digits(dscalar, &tmp);
    ec_ladder3pt_bounded(&Qpls_AB, dscalar, &PQ2_AB.P, &PQ2_AB.Q, &PQ2_AB.PmQ, &EBAB.E2, TORSION_PLUS_2POWER->_mp_size);
    copy_point(&T2.P2, &Qpls_AB);
    ibz_to_digits(d2, &deg_beta_inv);
    ibz_mul(&tmp, &deg_alpha_inv, &TORSION_D);
    ibz_to_digits(d1, &tmp);
    ec_mul(&T1.P2, &EBAB.E2, d1, TORSION_PLUS_D_2POWER->_mp_size, &Ppls_AB);
    ec_mul(&T2.P2, &EBAB.E2, d2, TORSION_PLUS_2POWER->_mp_size, &Qpls_AB);

    fp2_mul(&fp2inv, &T1.P2.z, &T2.P2.z);
    fp2_inv(&fp2inv);
    fp2_mul(&T1.P2.x, &fp2inv, &T1.P2.x);
    fp2_mul(&T1.P2.x, &T2.P2.z, &T1.P2.x);
    fp2_mul(&T2.P2.x, &fp2inv, &T2.P2.x);
    fp2_mul(&T2.P2.x, &T1.P2.z, &T2.P2.x);
    fp2_set_one(&T1.P2.z);
    fp2_set_one(&T2.P2.z);
    difference_point(&T1m2.P2, &T1.P2, &T2.P2, &EBAB.E2);
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
    memset(dscalar, 0, sizeof(dscalar));
    fp2_dlog_2e(dscalar, &r2, &r1, TORSION_PLUS_EVEN_POWER);
    ibz_copy_digits(&ressqr, dscalar, NWORDS_ORDER);
    ibz_sqrt_mod_2e(&res, &ressqr, TORSION_PLUS_EVEN_POWER);

    ibz_copy(&restmp, &res);
    ibz_mul(&restmp, &restmp, &restmp);
    ibz_mod(&restmp, &restmp, &TORSION_PLUS_2POWER);
    int test = ibz_cmp(&restmp, &ressqr);
    if (test != 0)
    {
        ibz_sub(&ressqr, &TORSION_PLUS_2POWER, &ressqr);
        ibz_sqrt_mod_2e(&res, &ressqr, TORSION_PLUS_EVEN_POWER);
        xADD(&T1m2.P1, &T1.P1, &T2.P1, &T1m2.P1);
    }

    ibz_to_digits(dres, &res);
    ec_mul(&T1.P1, &EBAB.E1, dres, TORSION_PLUS_2POWER->_mp_size, &T1.P1);
    ec_mul(&T2.P1, &EBAB.E1, dres, TORSION_PLUS_2POWER->_mp_size, &T2.P1);
    ec_mul(&T1m2.P1, &EBAB.E1, dres, TORSION_PLUS_2POWER->_mp_size, &T1m2.P1);

    theta_chain_comput_strategy(&hd_isog, TORSION_PLUS_EVEN_POWER - 2, &EBAB, &T1, &T2, &T1m2, strategies[2], 1);

    ec_mul(&eval_couple_point.P1, &EBAB.E1, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &Qpls_B);
    ec_set_zero(&eval_couple_point.P2);
    theta_chain_eval_special_case(&eval_couple_point, &hd_isog, &eval_couple_point, &EBAB);
    copy_point(&Psmid, &eval_couple_point.P1);

    ec_mul(&eval_couple_point.P2, &EBAB.E2, dTORSION_PLUS_2POWER, TORSION_PLUS_2POWER->_mp_size, &Ppls_AB);
    ec_set_zero(&eval_couple_point.P1);
    theta_chain_eval_special_case(&eval_couple_point, &hd_isog, &eval_couple_point, &EBAB);
    copy_point(&Qsmid, &eval_couple_point.P1);

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
    // Compute the pairing defined on the middle curve
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
    ibz_finalize(&tmp);
    ibz_finalize(&ressqr);
    ibz_finalize(&restmp);
    ibz_finalize(&res);
    return 1;
}

////
//// Key Encapsulation Mechanism using Fujisaki-Okamoto transform
////

const unsigned char G_hash_str[9] = "encrypt_";
const size_t G_hash_str_len = 8;

void encode_int_le(unsigned char *out, int value)
{
    unsigned int v = (unsigned int)value;

    for (size_t j = 0; j < sizeof(int); j++)
    {
        out[j] = (unsigned char)(v >> (8 * j));
    }
}

int decode_int_le(const unsigned char *in)
{
    unsigned int v = 0;
    for (size_t j = 0; j < sizeof(int); j++)
    {
        v |= ((unsigned int)in[j]) << (8 * j);
    }
    return (int)v;
}

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

    memset(encoded_ct, 0, PIKE_COMPRESSED_CT_ENCODED_BYTES);

    fp2_encode(encoded_ct + offset, &ct->EB_cof);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->EAB_cof);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->xQpls_B);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(encoded_ct + offset, &ct->xPpls_AB);
    offset += FP2_ENCODED_BYTES;
    encode_int_le(encoded_ct + offset, ct->hint_B[0]);
    offset += sizeof(int);
    encode_int_le(encoded_ct + offset, ct->hint_B[1]);
    offset += sizeof(int);
    encode_int_le(encoded_ct + offset, ct->hint_AB[0]);
    offset += sizeof(int);
    encode_int_le(encoded_ct + offset, ct->hint_AB[1]);
    offset += sizeof(int);

    encode_scalar_le(encoded_ct + offset, ct->scl2_B, PIKE_COMPRESSED_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_TWOPOW_BYTES;
    encode_scalar_le(encoded_ct + offset, ct->scl2_AB, PIKE_COMPRESSED_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_TWOPOW_BYTES;

    memcpy(encoded_ct + offset, ct->ct, PIKE_COMPRESSED_SHARED_SECRET_BYTES);

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
    fp2_decode(&ct->xQpls_B, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&ct->xPpls_AB, encoded_ct + offset);
    offset += FP2_ENCODED_BYTES;
    ct->hint_B[0] = decode_int_le(&encoded_ct[offset]);
    offset += sizeof(int);
    ct->hint_B[1] = decode_int_le(&encoded_ct[offset]);
    offset += sizeof(int);
    ct->hint_AB[0] = decode_int_le(&encoded_ct[offset]);
    offset += sizeof(int);
    ct->hint_AB[1] = decode_int_le(&encoded_ct[offset]);
    offset += sizeof(int);

    decode_scalar_le(ct->scl2_B, P_COFACTOR_FOR_TWOPOW_LEN, encoded_ct + offset, PIKE_COMPRESSED_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_TWOPOW_BYTES;
    decode_scalar_le(ct->scl2_AB, P_COFACTOR_FOR_TWOPOW_LEN, encoded_ct + offset, PIKE_COMPRESSED_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_TWOPOW_BYTES;

    memcpy(ct->ct, encoded_ct + offset, PIKE_COMPRESSED_SHARED_SECRET_BYTES);

    return 1;
}

int pk_encode(unsigned char *out, pike_pk_t *pk)
{
    size_t offset = 0;

    memset(out, 0, PIKE_COMPRESSED_PK_ENCODED_BYTES);

    fp2_encode(out + offset, &pk->EA_cof);
    offset += FP2_ENCODED_BYTES;
    fp2_encode(out + offset, &pk->xPpls);
    offset += FP2_ENCODED_BYTES;
    encode_scalar_le(out + offset, pk->sclTpls, PIKE_COMPRESSED_TPLS_BYTES);
    offset += PIKE_COMPRESSED_TPLS_BYTES;
    encode_scalar_le(out + offset, pk->scl2, PIKE_COMPRESSED_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_TWOPOW_BYTES;
    encode_scalar_le(out + offset, pk->sclmin1, PIKE_COMPRESSED_TMIN_BYTES);
    offset += PIKE_COMPRESSED_TMIN_BYTES;
    encode_scalar_le(out + offset, pk->sclmin2, PIKE_COMPRESSED_TMIN_BYTES);
    offset += PIKE_COMPRESSED_TMIN_BYTES;
    encode_scalar_le(out + offset, pk->sclmin3, PIKE_COMPRESSED_TMIN_BYTES);
    offset += PIKE_COMPRESSED_TMIN_BYTES;
    encode_int_le(out + offset, pk->sclTpls_label);
    offset += sizeof(int);
    encode_int_le(out + offset, pk->hintpls[0]);
    offset += sizeof(int);
    encode_int_le(out + offset, pk->hintpls[1]);
    offset += sizeof(int);
    encode_int_le(out + offset, pk->hintmin[0]);
    offset += sizeof(int);
    encode_int_le(out + offset, pk->hintmin[1]);
    offset += sizeof(int);

    out[offset++] = pk->sclpls_label ? 1 : 0;
    out[offset++] = pk->sclmin_label ? 1 : 0;

    return 1;
}

int pk_decode(pike_pk_t *pk, const unsigned char *in)
{
    size_t offset = 0;

    memset(pk, 0, sizeof(*pk));

    fp2_decode(&pk->EA_cof, in + offset);
    offset += FP2_ENCODED_BYTES;
    fp2_decode(&pk->xPpls, in + offset);
    offset += FP2_ENCODED_BYTES;

    decode_scalar_le(pk->sclTpls, P_COFACTOR_FOR_TPLS_LEN, in + offset, PIKE_COMPRESSED_TPLS_BYTES);
    offset += PIKE_COMPRESSED_TPLS_BYTES;
    decode_scalar_le(pk->scl2, P_COFACTOR_FOR_TWOPOW_LEN, in + offset, PIKE_COMPRESSED_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_TWOPOW_BYTES;
    decode_scalar_le(pk->sclmin1, P_COFACTOR_FOR_TMIN_LEN, in + offset, PIKE_COMPRESSED_TMIN_BYTES);
    offset += PIKE_COMPRESSED_TMIN_BYTES;
    decode_scalar_le(pk->sclmin2, P_COFACTOR_FOR_TMIN_LEN, in + offset, PIKE_COMPRESSED_TMIN_BYTES);
    offset += PIKE_COMPRESSED_TMIN_BYTES;
    decode_scalar_le(pk->sclmin3, P_COFACTOR_FOR_TMIN_LEN, in + offset, PIKE_COMPRESSED_TMIN_BYTES);
    offset += PIKE_COMPRESSED_TMIN_BYTES;
    pk->sclTpls_label = decode_int_le(&in[offset]);
    offset += sizeof(int);
    pk->hintpls[0] = decode_int_le(&in[offset]);
    offset += sizeof(int);
    pk->hintpls[1] = decode_int_le(&in[offset]);
    offset += sizeof(int);
    pk->hintmin[0] = decode_int_le(&in[offset]);
    offset += sizeof(int);
    pk->hintmin[1] = decode_int_le(&in[offset]);
    offset += sizeof(int);

    pk->sclpls_label = in[offset++] ? true : false;
    pk->sclmin_label = in[offset++] ? true : false;

    return 1;
}

int sk_encode(unsigned char *out, const pike_sk_t *sk)
{
    size_t offset = 0;

    encode_scalar_le(out + offset, sk->deg, PIKE_COMPRESSED_SEC_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_SEC_TWOPOW_BYTES;
    encode_scalar_le(out + offset, sk->alpha, PIKE_COMPRESSED_SEC_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_SEC_TWOPOW_BYTES;
    encode_scalar_le(out + offset, sk->beta, PIKE_COMPRESSED_SEC_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_SEC_TWOPOW_BYTES;
    encode_scalar_le(out + offset, sk->iota, PIKE_COMPRESSED_SEC_TORSION_D_BYTES);

    return 1;
}

int sk_decode(pike_sk_t *sk, const unsigned char *in)
{
    size_t offset = 0;

    memset(sk, 0, sizeof(*sk));

    decode_scalar_le(sk->deg, SECRET_FOR_TWOPOW_LEN, in + offset, PIKE_COMPRESSED_SEC_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_SEC_TWOPOW_BYTES;
    decode_scalar_le(sk->alpha, SECRET_FOR_TWOPOW_LEN, in + offset, PIKE_COMPRESSED_SEC_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_SEC_TWOPOW_BYTES;
    decode_scalar_le(sk->beta, SECRET_FOR_TWOPOW_LEN, in + offset, PIKE_COMPRESSED_SEC_TWOPOW_BYTES);
    offset += PIKE_COMPRESSED_SEC_TWOPOW_BYTES;
    decode_scalar_le(sk->iota, SECRET_FOR_TORSION_D_LEN, in + offset, PIKE_COMPRESSED_SEC_TORSION_D_BYTES);

    return 1;
}

int encaps(unsigned char *key, pike_ct_t *ct, const pike_pk_t *pk)
{
    unsigned char m[PIKE_COMPRESSED_SHARED_SECRET_BYTES];
    unsigned char gm[PIKE_COMPRESSED_SHARED_SECRET_BYTES];
    unsigned char encoded_ct[PIKE_COMPRESSED_SHARED_SECRET_BYTES + PIKE_COMPRESSED_CT_ENCODED_BYTES];

    randombytes(m, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    pike_xof(gm, PIKE_COMPRESSED_SHARED_SECRET_BYTES, m, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    pike_encrypt(ct, pk, m, PIKE_COMPRESSED_SHARED_SECRET_BYTES, gm, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    memcpy(encoded_ct, m, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    ct_encode(encoded_ct + PIKE_COMPRESSED_SHARED_SECRET_BYTES, ct);
    pike_xof(key, PIKE_COMPRESSED_SHARED_SECRET_BYTES, encoded_ct, PIKE_COMPRESSED_SHARED_SECRET_BYTES + PIKE_COMPRESSED_CT_ENCODED_BYTES);
    return 1;
}

int decaps(unsigned char *key, pike_ct_t *ct, const pike_pk_t *pk, const pike_sk_t *sk, unsigned char *dummy_m)
{
    unsigned char m[PIKE_COMPRESSED_SHARED_SECRET_BYTES];
    unsigned char gm[PIKE_COMPRESSED_SHARED_SECRET_BYTES];
    unsigned char test_ct_bytes[PIKE_COMPRESSED_CT_ENCODED_BYTES];
    unsigned char ct_bytes[PIKE_COMPRESSED_SHARED_SECRET_BYTES + PIKE_COMPRESSED_CT_ENCODED_BYTES];
    size_t m_len;
    pike_ct_t test_ct = {0};

    decrypt(m, &m_len, ct, sk);
    pike_xof(gm, PIKE_COMPRESSED_SHARED_SECRET_BYTES, m, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    pike_encrypt(&test_ct, pk, m, m_len, gm, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    ct_encode(test_ct_bytes, &test_ct);
    ct_encode(ct_bytes + PIKE_COMPRESSED_SHARED_SECRET_BYTES, ct);
    if (memcmp(ct_bytes + PIKE_COMPRESSED_SHARED_SECRET_BYTES, test_ct_bytes, PIKE_COMPRESSED_CT_ENCODED_BYTES) != 0)
    {
        memcpy(ct_bytes, dummy_m, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    }
    else
    {
        memcpy(ct_bytes, m, PIKE_COMPRESSED_SHARED_SECRET_BYTES);
    }
    pike_xof(key, PIKE_COMPRESSED_SHARED_SECRET_BYTES, ct_bytes, PIKE_COMPRESSED_SHARED_SECRET_BYTES + PIKE_COMPRESSED_CT_ENCODED_BYTES);

    return 1;
}
