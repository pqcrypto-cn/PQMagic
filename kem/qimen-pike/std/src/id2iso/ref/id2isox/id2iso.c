#include <quaternion.h>
#include <ec.h>
#include <endomorphism_action.h>
#include <id2iso.h>
#include <inttypes.h>
#include <locale.h>
#include <bench.h>
#include <curve_extras.h>
#include <biextension.h>

static __inline__ uint64_t
rdtsc(void)
{
    return (uint64_t)cpucycles();
}

// helper function to apply a matrix to a basis of E[2^f]
// works in place
void matrix_application_even_basis(ec_basis_t *bas, const ec_curve_t *E, ibz_mat_2x2_t *mat, int f)
{
    digit_t scalars[2][NWORDS_FIELD] = {0};

    ibz_t tmp, pow_two;
    ibz_init(&tmp);
    ibz_init(&pow_two);
    ibz_pow(&pow_two, &ibz_const_two, f);

    ec_basis_t tmp_bas;
    copy_point(&tmp_bas.P, &bas->P);
    copy_point(&tmp_bas.Q, &bas->Q);
    copy_point(&tmp_bas.PmQ, &bas->PmQ);

    // reduction mod 2f
    ibz_mod(&(*mat)[0][0], &(*mat)[0][0], &pow_two);
    ibz_mod(&(*mat)[0][1], &(*mat)[0][1], &pow_two);
    ibz_mod(&(*mat)[1][0], &(*mat)[1][0], &pow_two);
    ibz_mod(&(*mat)[1][1], &(*mat)[1][1], &pow_two);

    // first basis element
    ibz_to_digit_array(scalars[0], &(*mat)[0][0]);
    // ibz_set(&mat[0][1],0);
    ibz_to_digit_array(scalars[1], &(*mat)[1][0]);
    ec_biscalar_mul_bounded(&bas->P, E, scalars[0], scalars[1], &tmp_bas, f);
    ibz_to_digit_array(scalars[0], &(*mat)[0][1]);
    ibz_to_digit_array(scalars[1], &(*mat)[1][1]);
    ec_biscalar_mul_bounded(&bas->Q, E, scalars[0], scalars[1], &tmp_bas, f);

    ibz_sub(&tmp, &(*mat)[0][0], &(*mat)[0][1]);
    ibz_mod(&tmp, &tmp, &pow_two);
    ibz_to_digit_array(scalars[0], &tmp);
    ibz_sub(&tmp, &(*mat)[1][0], &(*mat)[1][1]);
    ibz_mod(&tmp, &tmp, &pow_two);
    ibz_to_digit_array(scalars[1], &tmp);
    ec_biscalar_mul_bounded(&bas->PmQ, E, scalars[0], scalars[1], &tmp_bas, f);

    ibz_finalize(&tmp);
    ibz_finalize(&pow_two);
}

// helper function to apply some endomorphism of E0 on the precomputed basis of E[2^f]
// works in place
void endomorphism_application_even_basis(ec_basis_t *bas,
                                         const ec_curve_t *E,
                                         quat_alg_elem_t *theta,
                                         int f)
{
    ibz_t tmp;
    ibz_init(&tmp);
    ibz_vec_4_t coeffs;
    ibz_vec_4_init(&coeffs);
    ibz_mat_2x2_t mat;
    ibz_mat_2x2_init(&mat);

    ibz_t content;
    ibz_init(&content);

    // // decomposing theta on the basis
    quat_alg_make_primitive(&coeffs, &content, theta, &MAXORD_O0, &QUATALG_PINFTY);
    assert(ibz_get(&content) % 2 == 1);

    ibz_set(&mat[0][0], 0);
    ibz_set(&mat[0][1], 0);
    ibz_set(&mat[1][0], 0);
    ibz_set(&mat[1][1], 0);

    // computing the matrix
    for (unsigned i = 0; i < 2; ++i)
    {
        ibz_add(&mat[i][i], &mat[i][i], &coeffs[0]);
        for (unsigned j = 0; j < 2; ++j)
        {
            ibz_mul(&tmp, &ACTION_GEN2[i][j], &coeffs[1]);
            ibz_add(&mat[i][j], &mat[i][j], &tmp);
            ibz_mul(&tmp, &ACTION_GEN3[i][j], &coeffs[2]);
            ibz_add(&mat[i][j], &mat[i][j], &tmp);
            ibz_mul(&tmp, &ACTION_GEN4[i][j], &coeffs[3]);
            ibz_add(&mat[i][j], &mat[i][j], &tmp);
            ibz_mul(&mat[i][j], &mat[i][j], &content);
            // ibz_mod(&mat[i][j],&mat[i][j],&twopow);
        }
    }

    // and now we apply it
    matrix_application_even_basis(bas, E, &mat, f);

    ibz_vec_4_finalize(&coeffs);
    ibz_mat_2x2_finalize(&mat);
    ibz_finalize(&content);
}

void id2iso_ideal_to_kernel_dlogs_odd(ibz_vec_2_t *vec,
                                      ec_degree_odd_t *deg,
                                      const quat_left_ideal_t *lideal)
{
    ibz_t tmp;
    ibz_init(&tmp);

    ibz_mat_2x2_t mat;
    ibz_mat_2x2_init(&mat);

    // construct the matrix of the dual of alpha on the T-torsion
    {
        quat_alg_elem_t alpha;
        quat_alg_elem_init(&alpha);

        int lideal_generator_ok;
        lideal_generator_ok = quat_lideal_generator(&alpha, lideal, &QUATALG_PINFTY, 0);
        assert(lideal_generator_ok);
        assert(
            ibz_divides(&ibz_const_two, &alpha.denom)); // denominator is invertible mod T, ignore

        for (unsigned i = 0; i < 2; ++i)
        {
            ibz_add(&mat[i][i], &mat[i][i], &alpha.coord[0]);
            for (unsigned j = 0; j < 2; ++j)
            {
                ibz_mul(&tmp, &ACTION_I[i][j], &alpha.coord[1]);
                ibz_sub(&mat[i][j], &mat[i][j], &tmp);
                ibz_mul(&tmp, &ACTION_J[i][j], &alpha.coord[2]);
                ibz_sub(&mat[i][j], &mat[i][j], &tmp);
                ibz_mul(&tmp, &ACTION_K[i][j], &alpha.coord[3]);
                ibz_sub(&mat[i][j], &mat[i][j], &tmp);
                //                ibz_mod(&mat[i][j], &mat[i][j], &TORSION_ODD);
            }
        }

        quat_alg_elem_finalize(&alpha);
    }

    // determine prime powers in the norm of the ideal
    size_t numpp = 0;
#define NUMPP (sizeof(TORSION_ODD_PRIMEPOWERS) / sizeof(*TORSION_ODD_PRIMEPOWERS))
    ibz_t pps[NUMPP];
    ibz_vec_2_t vs[NUMPP];
    {
        ibz_t const *const norm = &lideal->norm;

        for (size_t i = 0; i < NUMPP; ++i)
        {
            ibz_gcd(&tmp, norm, &TORSION_ODD_PRIMEPOWERS[i]);
            (*deg)[i] = 0;
            if (!ibz_is_one(&tmp))
            {
                ibz_init(&pps[numpp]);
                ibz_copy(&pps[numpp], &tmp);
                ibz_vec_2_init(&vs[numpp]);
                ++numpp;

                // compute valuation
                ibz_t l, r;
                ibz_init(&l);
                ibz_init(&r);
                ibz_set(&l, TORSION_ODD_PRIMES[i]);
                do
                {
                    ++(*deg)[i];
                    ibz_div(&tmp, &r, &tmp, &l);
                    assert(!ibz_is_zero(&tmp) && ibz_is_zero(&r));
                } while (!ibz_is_one(&tmp));
                ibz_finalize(&r);
                ibz_finalize(&l);
            }
        }
    }
#undef NUMPP

    // find the kernel of alpha modulo each prime power
    {
        for (size_t i = 0; i < numpp; ++i)
        {
            ibz_mod(&vs[i][0], &mat[0][0], &pps[i]);
            ibz_mod(&vs[i][1], &mat[1][0], &pps[i]);
            ibz_gcd(&tmp, &vs[i][0], &pps[i]);
            ibz_gcd(&tmp, &vs[i][1], &tmp);
            if (ibz_cmp(&tmp, &ibz_const_one))
            {
                ibz_mod(&vs[i][0], &mat[0][1], &pps[i]);
                ibz_mod(&vs[i][1], &mat[1][1], &pps[i]);
            }
#ifndef NDEBUG
            ibz_gcd(&tmp, &vs[i][0], &pps[i]);
            ibz_gcd(&tmp, &vs[i][1], &tmp);
            assert(!ibz_cmp(&tmp, &ibz_const_one));
#endif
        }
    }

    // now CRT them together
    {
        // TODO use a product tree instead
        ibz_t mod;
        ibz_init(&mod);
        ibz_set(&mod, 1);
        ibz_set(&(*vec)[0], 0);
        ibz_set(&(*vec)[1], 0);
        for (size_t i = 0; i < numpp; ++i)
        {
            // TODO use vector CRT
            ibz_crt(&(*vec)[0], &(*vec)[0], &vs[i][0], &mod, &pps[i]);
            ibz_crt(&(*vec)[1], &(*vec)[1], &vs[i][1], &mod, &pps[i]);
            // TODO optionally return lcm from CRT and use it
            ibz_mul(&mod, &mod, &pps[i]);
            ibz_finalize(&pps[i]);
        }
        ibz_finalize(&mod);
    }

    for (size_t i = 0; i < numpp; ++i)
        ibz_vec_2_finalize(&vs[i]);

    ibz_mat_2x2_finalize(&mat);

    ibz_finalize(&tmp);
}

/**
 * @brief Translating an ideal of odd norm dividing p²-1 into the corresponding isogeny
 *
 * @param isog Output : the output isogeny
 * @param basis_minus : a basis of ec points
 * @param basis_plus : a basis of ec points
 * @param domain : an elliptic curve
 * @param lideal_input : O0-ideal corresponding to the ideal to be translated
 *
 * compute  the isogeny starting from domain corresponding to ideal_input
 * the coefficients extracted from the ideal are to be applied to basis_minus and basis_plus to
 * compute the kernel of the isogeny.
 *
 */

void id2iso_ideal_to_isogeny_odd(ec_isog_odd_t *isog,
                                 const ec_curve_t *domain,
                                 const ec_basis_t *basis_plus,
                                 const ec_basis_t *basis_minus,
                                 const quat_left_ideal_t *lideal_input)
{
    digit_t scalars_plus[2][NWORDS_ORDER] = {0}, scalars_minus[2][NWORDS_ORDER] = {0};
    {
        ibz_vec_2_t vec;
        ibz_vec_2_init(&vec);

        id2iso_ideal_to_kernel_dlogs_odd(&vec, &isog->degree, lideal_input);

        ibz_t tmp;
        ibz_init(&tmp);

        // multiply out unnecessary cofactor from T-torsion basis
        assert(sizeof(isog->degree) / sizeof(*isog->degree) ==
               sizeof(TORSION_ODD_PRIMEPOWERS) / sizeof(*TORSION_ODD_PRIMEPOWERS));
        for (size_t i = 0; i < sizeof(isog->degree) / sizeof(*isog->degree); ++i)
        {
            assert(isog->degree[i] <= TORSION_ODD_POWERS[i]);
            if (isog->degree[i] == TORSION_ODD_POWERS[i])
                continue;
            ibz_set(&tmp, TORSION_ODD_PRIMES[i]);
            ibz_pow(&tmp, &tmp, TORSION_ODD_POWERS[i] - isog->degree[i]);
            ibz_mul(&vec[0], &vec[0], &tmp);
            ibz_mul(&vec[1], &vec[1], &tmp);
        }

        ibz_mod(&tmp, &vec[0], &TORSION_ODD_PLUS);
        ibz_to_digit_array(scalars_plus[0], &tmp);
        ibz_mod(&tmp, &vec[1], &TORSION_ODD_PLUS);
        ibz_to_digit_array(scalars_plus[1], &tmp);
        ibz_mod(&tmp, &vec[0], &TORSION_ODD_MINUS);
        // ibz_printf("> %Zx\n", &tmp);
        ibz_to_digit_array(scalars_minus[0], &tmp);
        ibz_mod(&tmp, &vec[1], &TORSION_ODD_MINUS);
        // ibz_printf("> %Zx\n", &tmp);
        ibz_to_digit_array(scalars_minus[1], &tmp);

        ibz_finalize(&tmp);

        ibz_vec_2_finalize(&vec);
    }

    isog->curve = *domain;
    ec_biscalar_mul_bounded(&isog->ker_plus, domain, scalars_plus[0], scalars_plus[1], basis_plus, TORSION_ODD_PLUS->_mp_size);

    ec_biscalar_mul_bounded(&isog->ker_minus, domain, scalars_minus[0], scalars_minus[1], basis_minus, TORSION_ODD_MINUS->_mp_size);
    // TODO: the case scalars_minus = (0,0) seems to bug
}
