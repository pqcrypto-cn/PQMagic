#include <gmp.h>
#include <quaternion.h>
#include <klpt.h>
#include "tools.h"
#include <tools.h>

/** @file
 *
 * @authors Antonin Leroux
 *
 * @brief the eichler norm equation implementation
 */

void
quat_alg_elem_copy(quat_alg_elem_t *copy, const quat_alg_elem_t *copied)
{
    ibz_copy(&copy->denom, &copied->denom);
    ibz_copy(&copy->coord[0], &copied->coord[0]);
    ibz_copy(&copy->coord[1], &copied->coord[1]);
    ibz_copy(&copy->coord[2], &copied->coord[2]);
    ibz_copy(&copy->coord[3], &copied->coord[3]);
}
void
quat_left_ideal_copy(quat_left_ideal_t *copy, const quat_left_ideal_t *copied)
{
    copy->parent_order = copied->parent_order;
    ibz_copy(&copy->norm, &copied->norm);
    ibz_copy(&copy->lattice.denom, &copied->lattice.denom);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&copy->lattice.basis[i][j], &copied->lattice.basis[i][j]);
        }
    }
}

/**
 * @brief Create an element of a extremal maximal order from its coefficients
 *
 * @param elem Output: the quaternion element
 * @param order the order
 * @param coeffs the vector of 4 ibz coefficients
 * @param Bpoo quaternion algebra
 *
 * elem = x + i*y + j*z + j*i*t
 * where coeffs = [x,y,z,t] and i = order.i, j = order.j
 *
 */
void
order_elem_create(quat_alg_elem_t *elem,
                  const quat_p_extremal_maximal_order_t *order,
                  const quat_alg_coord_t *coeffs,
                  const quat_alg_t *Bpoo)
{

    // var dec
    quat_alg_elem_t quat_temp;

    // var init
    quat_alg_elem_init(&quat_temp);

    // elem = x
    quat_alg_scalar(elem, &(*coeffs)[0], &ibz_const_one);

    // quat_temp = i*y
    quat_alg_scalar(&quat_temp, &((*coeffs)[1]), &ibz_const_one);
    quat_alg_mul(&quat_temp, &order->i, &quat_temp, Bpoo);

    // elem = x + i*y
    quat_alg_add(elem, elem, &quat_temp);

    // quat_temp = z * j
    quat_alg_scalar(&quat_temp, &(*coeffs)[2], &ibz_const_one);
    quat_alg_mul(&quat_temp, &order->j, &quat_temp, Bpoo);

    // elem = x + i* + z*j
    quat_alg_add(elem, elem, &quat_temp);

    // quat_temp = t * j * i
    quat_alg_scalar(&quat_temp, &(*coeffs)[3], &ibz_const_one);
    quat_alg_mul(&quat_temp, &order->j, &quat_temp, Bpoo);
    quat_alg_mul(&quat_temp, &quat_temp, &order->i, Bpoo);

    // elem =  x + i*y + j*z + j*i*t
    quat_alg_add(elem, elem, &quat_temp);

    quat_alg_elem_finalize(&quat_temp);
}

/**
 * @brief Representing an integer by the quadratic norm form of a maximal extremal order
 *
 * @param gamma Output: a quaternion element
 * @param n_gamma Outut: norm of gamma (also part of the input, it is the target norm a multiple of
 * the final norm)
 * @param Bpoo the quaternion algebra
 * @return 1 if the computation succeeded
 *
 * This algorithm finds a primitive quaternion element gamma of n_gamma inside the standard maximal
 * extremal order
 */
int
represent_integer(quat_alg_elem_t *gamma, ibz_t *n_gamma, const quat_alg_t *Bpoo)
{
    // var dec
    int found;
    int cnt;
    ibz_t cornacchia_target;
    ibz_t adjusted_n_gamma;
    ibz_t bound, sq_bound, temp;
    quat_alg_coord_t coeffs; // coeffs = [x,y,z,t]
    quat_alg_elem_t quat_temp;
    int prime_list_length;
    short prime_list[1];
    ibz_t prod_bad_primes; // TODO adapt
    prime_list[0] = 5;
    prime_list_length = 1;
    ibz_init(&prod_bad_primes);
    ibz_copy(&prod_bad_primes, &ibz_const_one);

    // var init
    found = 0;
    cnt = 0;
    ibz_init(&bound);
    ibz_init(&temp);
    ibz_init(&sq_bound);
    quat_alg_coord_init(&coeffs);
    quat_alg_elem_init(&quat_temp);
    ibz_init(&adjusted_n_gamma);
    ibz_init(&cornacchia_target);

    // adjusting the norm of gamma (multiplied by 4 to find a solution in the full maximal order)
    ibz_mul(&adjusted_n_gamma, n_gamma, &ibz_const_two);
    ibz_mul(&adjusted_n_gamma, &adjusted_n_gamma, &ibz_const_two);

    // computation of the first bound = sqrt (adjust_n_gamma / p )
    ibz_div(&sq_bound, &bound, &adjusted_n_gamma, &Bpoo->p);
    ibz_sqrt_floor(&bound, &sq_bound);
    // entering the main loop
    while (!found && cnt < KLPT_repres_num_gamma_trial) {
        cnt++;
        // we start by sampling the first coordinate
        ibz_rand_interval(&coeffs[2], &ibz_const_one, &bound);
        // then, we sample the second coordinate
        // computing the second bound in temp as sqrt( (adjust_n_gamma - coeffs[2]²)/p )
        ibz_mul(&cornacchia_target, &coeffs[2], &coeffs[2]);
        ibz_sub(&temp, &sq_bound, &cornacchia_target);
        ibz_sqrt_floor(&temp, &temp);
        if (ibz_cmp(&temp, &ibz_const_zero) == 0) {
            continue;
        }
        // sampling the second value
        ibz_rand_interval(&coeffs[3], &ibz_const_one, &temp);

        // compute cornacchia_target = n_gamma - p * (z² + t²)
        ibz_mul(&temp, &coeffs[3], &coeffs[3]);
        ibz_add(&cornacchia_target, &cornacchia_target, &temp);
        ibz_mul(&cornacchia_target, &cornacchia_target, &Bpoo->p);
        ibz_sub(&cornacchia_target, &adjusted_n_gamma, &cornacchia_target);
        // applying cornacchia extended
        found = ibz_cornacchia_extended(&coeffs[0],
                                        &coeffs[1],
                                        &cornacchia_target,
                                        prime_list,
                                        prime_list_length,
                                        KLPT_primality_num_iter,
                                        &prod_bad_primes);

        // check that we can divide by two at least once
        // we must have x = t mod  2 and y = z mod 2
        found = found && (ibz_get(&coeffs[0]) % 2 == ibz_get(&coeffs[3]) % 2) &&
                (ibz_get(&coeffs[1]) % 2 == ibz_get(&coeffs[2]) % 2);
    }
    if (found) {
        // translate x,y,z,t into the quaternion element gamma
        order_elem_create(gamma, &STANDARD_EXTREMAL_ORDER, &coeffs, Bpoo);
        // making gamma primitive
        // coeffs contains the coefficients of primitivized gamma in the basis of order
        quat_alg_make_primitive(&coeffs, &temp, gamma, &STANDARD_EXTREMAL_ORDER.order, Bpoo);

        // new gamma
        ibz_mat_4x4_eval(&coeffs, &STANDARD_EXTREMAL_ORDER.order.basis, &coeffs);
        ibz_copy(&gamma->coord[0], &coeffs[0]);
        ibz_copy(&gamma->coord[1], &coeffs[1]);
        ibz_copy(&gamma->coord[2], &coeffs[2]);
        ibz_copy(&gamma->coord[3], &coeffs[3]);
        ibz_copy(&gamma->denom, &STANDARD_EXTREMAL_ORDER.order.denom);

        // adjust the norm of gamma by dividing by the scalar temp²
        ibz_mul(&temp, &temp, &temp);
        ibz_div(n_gamma, &bound, &adjusted_n_gamma, &temp);
    }
    // var finalize
    ibz_finalize(&bound);
    ibz_finalize(&temp);
    ibz_finalize(&sq_bound);
    quat_alg_coord_finalize(&coeffs);
    quat_alg_elem_finalize(&quat_temp);
    ibz_finalize(&adjusted_n_gamma);
    ibz_finalize(&cornacchia_target);
    ibz_finalize(&prod_bad_primes);

    return found;
}
