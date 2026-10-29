#include <quaternion.h>
#include "internal.h"

// internal helpers, also for other files
void
ibz_vec_2_set(ibz_vec_2_t *vec, int a0, int a1)
{
    ibz_set(&((*vec)[0]), a0);
    ibz_set(&((*vec)[1]), a1);
}
void
ibz_mat_2x2_set(ibz_mat_2x2_t *mat, int a00, int a01, int a10, int a11)
{
    ibz_set(&((*mat)[0][0]), a00);
    ibz_set(&((*mat)[0][1]), a01);
    ibz_set(&((*mat)[1][0]), a10);
    ibz_set(&((*mat)[1][1]), a11);
}

void
ibz_mat_2x2_copy(ibz_mat_2x2_t *new, const ibz_mat_2x2_t *mat)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ibz_copy(&((*new)[i][j]), &((*mat)[i][j]));
        }
    }
}

void
ibz_mat_2x2_det_from_ibz(ibz_t *det,
                         const ibz_t *a11,
                         const ibz_t *a12,
                         const ibz_t *a21,
                         const ibz_t *a22)
{
    ibz_t prod;
    ibz_init(&prod);
    ibz_mul(&prod, a12, a21);
    ibz_mul(det, a11, a22);
    ibz_sub(det, det, &prod);
    ibz_finalize(&prod);
}

void
ibz_mat_2x2_eval(ibz_vec_2_t *res, const ibz_mat_2x2_t *mat, const ibz_vec_2_t *vec)
{
    ibz_t prod;
    ibz_vec_2_t matvec;
    ibz_init(&prod);
    ibz_vec_2_init(&matvec);
    ibz_mul(&prod, &((*mat)[0][0]), &((*vec)[0]));
    ibz_copy(&(matvec[0]), &prod);
    ibz_mul(&prod, &((*mat)[0][1]), &((*vec)[1]));
    ibz_add(&(matvec[0]), &(matvec[0]), &prod);
    ibz_mul(&prod, &((*mat)[1][0]), &((*vec)[0]));
    ibz_copy(&(matvec[1]), &prod);
    ibz_mul(&prod, &((*mat)[1][1]), &((*vec)[1]));
    ibz_add(&(matvec[1]), &(matvec[1]), &prod);
    ibz_copy(&((*res)[0]), &(matvec[0]));
    ibz_copy(&((*res)[1]), &(matvec[1]));
    ibz_finalize(&prod);
    ibz_vec_2_finalize(&matvec);
}

void
ibz_mat_2x2_add(ibz_mat_2x2_t *sum, const ibz_mat_2x2_t *mat_a, const ibz_mat_2x2_t *mat_b)
{
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ibz_add(&((*sum)[i][j]), &((*mat_a)[i][j]), &((*mat_b)[i][j]));
        }
    }
}

// modular 2x2 operations

void
ibz_2x2_mul_mod(ibz_mat_2x2_t *prod,
                const ibz_mat_2x2_t *mat_a,
                const ibz_mat_2x2_t *mat_b,
                const ibz_t *m)
{
    ibz_t mul;
    ibz_mat_2x2_t sums;
    ibz_init(&mul);
    ibz_mat_2x2_init(&sums);
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ibz_set(&(sums[i][j]), 0);
        }
    }
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            for (int k = 0; k < 2; k++) {
                ibz_mul(&mul, &((*mat_a)[i][k]), &((*mat_b)[k][j]));
                ibz_add(&(sums[i][j]), &(sums[i][j]), &mul);
                ibz_mod(&(sums[i][j]), &(sums[i][j]), m);
            }
        }
    }
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ibz_copy(&((*prod)[i][j]), &(sums[i][j]));
        }
    }
    ibz_finalize(&mul);
    ibz_mat_2x2_finalize(&sums);
}

int
ibz_2x2_inv_mod(ibz_mat_2x2_t *inv, const ibz_mat_2x2_t *mat, const ibz_t *m)
{
    ibz_t det, prod;
    ibz_init(&det);
    ibz_init(&prod);
    ibz_mul(&det, &((*mat)[0][0]), &((*mat)[1][1]));
    ibz_mod(&det, &det, m);
    ibz_mul(&prod, &((*mat)[0][1]), &((*mat)[1][0]));
    ibz_sub(&det, &det, &prod);
    ibz_mod(&det, &det, m);
    int res = ibz_invmod(&det, &det, m);
    if (res) {
        ibz_copy(&prod, &((*mat)[0][0]));
        ibz_copy(&((*inv)[0][0]), &((*mat)[1][1]));
        ibz_copy(&((*inv)[1][1]), &prod);
        ibz_neg(&((*inv)[1][0]), &((*mat)[1][0]));
        ibz_neg(&((*inv)[0][1]), &((*mat)[0][1]));
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                ibz_mul(&((*inv)[i][j]), &((*inv)[i][j]), &det);
                ibz_mod(&((*inv)[i][j]), &((*inv)[i][j]), m);
            }
        }
    }
    ibz_finalize(&det);
    ibz_finalize(&prod);
    return (res);
}

// helper for cvp
int
quat_dim2_lattice_contains(ibz_mat_2x2_t *basis, ibz_t *coord1, ibz_t *coord2)
{
    int res = 1;
    ibz_t prod, sum, det, r;
    ibz_init(&det);
    ibz_init(&r);
    ibz_init(&sum);
    ibz_init(&prod);
    // compute det, then both coordinates (inverse*det)*vec, where vec is (coord1, coord2) and check
    // wthether det divides both results
    ibz_mat_2x2_det_from_ibz(
        &det, &((*basis)[0][0]), &((*basis)[0][1]), &((*basis)[1][0]), &((*basis)[1][1]));
    ibz_mul(&sum, coord1, &((*basis)[1][1]));
    ibz_mul(&prod, coord2, &((*basis)[0][1]));
    ibz_sub(&sum, &sum, &prod);
    ibz_div(&prod, &r, &sum, &det);
    res = res && ibz_is_zero(&r);
    ibz_mul(&sum, coord2, &((*basis)[0][0]));
    ibz_mul(&prod, coord1, &((*basis)[1][0]));
    ibz_sub(&sum, &sum, &prod);
    ibz_div(&prod, &r, &sum, &det);
    res = res && ibz_is_zero(&r);
    ibz_finalize(&det);
    ibz_finalize(&r);
    ibz_finalize(&sum);
    ibz_finalize(&prod);
    return (res);
}

void
quat_dim2_lattice_norm(ibz_t *norm, const ibz_t *coord1, const ibz_t *coord2, const ibz_t *norm_q)
{
    ibz_t prod, sum;
    ibz_init(&prod);
    ibz_init(&sum);
    ibz_mul(&sum, coord1, coord1);
    ibz_mul(&prod, coord2, coord2);
    ibz_mul(&prod, &prod, norm_q);
    ibz_add(norm, &sum, &prod);
    ibz_finalize(&prod);
    ibz_finalize(&sum);
}

void
quat_dim2_lattice_bilinear(ibz_t *res,
                           const ibz_t *v11,
                           const ibz_t *v12,
                           const ibz_t *v21,
                           const ibz_t *v22,
                           const ibz_t *norm_q)
{
    ibz_t prod, sum;
    ibz_init(&prod);
    ibz_init(&sum);
    ibz_mul(&sum, v11, v21);
    ibz_mul(&prod, v12, v22);
    ibz_mul(&prod, &prod, norm_q);
    ibz_add(res, &sum, &prod);
    ibz_finalize(&prod);
    ibz_finalize(&sum);
}

// algo 3.1.14 Cohen (exact solution for shortest vector in dimension 2, than take a second,
// orthogonal vector)
void
quat_dim2_lattice_short_basis(ibz_mat_2x2_t *reduced,
                              const ibz_mat_2x2_t *basis,
                              const ibz_t *norm_q)
{
    ibz_vec_2_t a, b, t;
    ibz_t prod, sum, norm_a, norm_b, r, norm_t, n;
    ibz_vec_2_init(&a);
    ibz_vec_2_init(&b);
    ibz_vec_2_init(&t);
    ibz_init(&prod);
    ibz_init(&sum);
    ibz_init(&r);
    ibz_init(&n);
    ibz_init(&norm_t);
    ibz_init(&norm_a);
    ibz_init(&norm_b);
    // init a,b
    ibz_copy(&(a[0]), &((*basis)[0][0]));
    ibz_copy(&(a[1]), &((*basis)[1][0]));
    ibz_copy(&(b[0]), &((*basis)[0][1]));
    ibz_copy(&(b[1]), &((*basis)[1][1]));
    // compute initial norms
    quat_dim2_lattice_norm(&norm_a, &(a[0]), &(a[1]), norm_q);
    quat_dim2_lattice_norm(&norm_b, &(b[0]), &(b[1]), norm_q);
    // exchange if needed
    if (ibz_cmp(&norm_a, &norm_b) < 0) {
        ibz_copy(&sum, &(a[0]));
        ibz_copy(&(a[0]), &(b[0]));
        ibz_copy(&(b[0]), &sum);
        ibz_copy(&sum, &(a[1]));
        ibz_copy(&(a[1]), &(b[1]));
        ibz_copy(&(b[1]), &sum);
        ibz_copy(&sum, &norm_a);
        ibz_copy(&norm_a, &norm_b);
        ibz_copy(&norm_b, &sum);
    }
    int test = 1;
    while (test) {
        // compute n
        quat_dim2_lattice_bilinear(&n, &(a[0]), &(a[1]), &(b[0]), &(b[1]), norm_q);
        // set r
        ibz_rounded_div(&r, &n, &norm_b);
        // compute t_norm
        ibz_set(&prod, 2);
        ibz_mul(&prod, &prod, &n);
        ibz_mul(&prod, &prod, &r);
        ibz_sub(&sum, &norm_a, &prod);
        ibz_mul(&prod, &r, &r);
        ibz_mul(&prod, &prod, &norm_b);
        ibz_add(&norm_t, &sum, &prod);
        // test:
        if (ibz_cmp(&norm_b, &norm_t) > 0) {
            // compute t, a, b
            ibz_copy(&norm_a, &norm_b);
            ibz_copy(&norm_b, &norm_t);
            // t is a -rb, a is b, b is t
            ibz_mul(&prod, &r, &(b[0]));
            ibz_sub(&(t[0]), &(a[0]), &prod);
            ibz_mul(&prod, &r, &(b[1]));
            ibz_sub(&(t[1]), &(a[1]), &prod);
            ibz_copy(&(a[0]), &(b[0]));
            ibz_copy(&(a[1]), &(b[1]));
            ibz_copy(&(b[0]), &(t[0]));
            ibz_copy(&(b[1]), &(t[1]));
        } else {
            test = 0;
        }
    }
    // output : now b is short: need to get 2nd short vector: idea: take shortest among t and a
    if (ibz_cmp(&norm_t, &norm_a) < 0) {
        ibz_mul(&prod, &r, &(b[0]));
        ibz_sub(&(a[0]), &(a[0]), &prod);
        ibz_mul(&prod, &r, &(b[1]));
        ibz_sub(&(a[1]), &(a[1]), &prod);
    }
    ibz_copy(&((*reduced)[0][0]), &(b[0]));
    ibz_copy(&((*reduced)[1][0]), &(b[1]));
    ibz_copy(&((*reduced)[0][1]), &(a[0]));
    ibz_copy(&((*reduced)[1][1]), &(a[1]));

    ibz_finalize(&prod);
    ibz_finalize(&sum);
    ibz_finalize(&norm_a);
    ibz_finalize(&norm_b);
    ibz_finalize(&norm_t);
    ibz_vec_2_finalize(&a);
    ibz_vec_2_finalize(&b);
    ibz_vec_2_finalize(&t);
    ibz_finalize(&r);
    ibz_finalize(&n);
}

// compute the rounded value of <a*,t>/<a*,a*>, where a* is a orthogonalised with respect to b
void
quat_dim2_lattice_get_coefficient_with_orthogonalisation(ibz_t *res,
                                                         const ibz_t *a0,
                                                         const ibz_t *a1,
                                                         const ibz_t *b0,
                                                         const ibz_t *b1,
                                                         const ibz_t *t0,
                                                         const ibz_t *t1,
                                                         const ibz_t *norm_q)
{
    ibz_t norm_b, bilinear, astar1, astar0, prod, norm_astar;
    ibz_init(&norm_b);
    ibz_init(&norm_astar);
    ibz_init(&bilinear);
    ibz_init(&prod);
    ibz_init(&astar0);
    ibz_init(&astar1);
    quat_dim2_lattice_norm(&norm_b, b0, b1, norm_q);
    quat_dim2_lattice_bilinear(&bilinear, a0, a1, b0, b1, norm_q);
    ibz_mul(&astar0, a0, &norm_b);
    ibz_mul(&prod, b0, &bilinear);
    ibz_sub(&astar0, &astar0, &prod);
    ibz_mul(&astar1, a1, &norm_b);
    ibz_mul(&prod, b1, &bilinear);
    ibz_sub(&astar1, &astar1, &prod);
    quat_dim2_lattice_norm(&norm_astar, &astar0, &astar1, norm_q);
    quat_dim2_lattice_bilinear(&bilinear, &astar0, &astar1, t0, t1, norm_q);
    ibz_mul(&bilinear, &bilinear, &norm_b);
    ibz_rounded_div(res, &bilinear, &norm_astar);
    ibz_finalize(&norm_b);
    ibz_finalize(&norm_astar);
    ibz_finalize(&bilinear);
    ibz_finalize(&prod);
    ibz_finalize(&astar0);
    ibz_finalize(&astar1);
}

// find a closest vector to target in lattice, using a reduced basis given as argument basis.
// nearest plane algo as in https://cims.nyu.edu/~regev/teaching/lattices_fall_2004/ln/cvp.pdf, but
// without basis: basicallly just a projection
void
quat_dim2_lattice_closest_vector(ibz_vec_2_t *target_minus_closest,
                                 ibz_vec_2_t *closest_coords_in_basis,
                                 const ibz_mat_2x2_t *reduced_basis,
                                 const ibz_vec_2_t *target,
                                 const ibz_t *norm_q)
{
    ibz_vec_2_t coords, work;
    ibz_t prod, sum, norm_a, norm_b, r;
    ibz_vec_2_init(&coords);
    ibz_vec_2_init(&work);
    ibz_init(&prod);
    ibz_init(&sum);
    ibz_init(&norm_a);
    ibz_init(&norm_b);
    ibz_init(&r);
    // init work
    ibz_copy(&(work[0]), &((*target)[0]));
    ibz_copy(&(work[1]), &((*target)[1]));
    // norm a,b
    quat_dim2_lattice_norm(&norm_a, &((*reduced_basis)[0][0]), &((*reduced_basis)[1][0]), norm_q);
    quat_dim2_lattice_norm(&norm_b, &((*reduced_basis)[0][1]), &((*reduced_basis)[1][1]), norm_q);
    // use 2nd basis vector (the larger one), and orthogonalise it with respect to the first one
    quat_dim2_lattice_get_coefficient_with_orthogonalisation(&(coords[1]),
                                                             &((*reduced_basis)[0][1]),
                                                             &((*reduced_basis)[1][1]),
                                                             &((*reduced_basis)[0][0]),
                                                             &((*reduced_basis)[1][0]),
                                                             &(work[0]),
                                                             &(work[1]),
                                                             norm_q);
    // sustract projection from vector
    ibz_mul(&prod, &((*reduced_basis)[0][1]), &(coords[1]));
    ibz_sub(&(work[0]), &(work[0]), &prod);
    ibz_mul(&prod, &((*reduced_basis)[1][1]), &(coords[1]));
    ibz_sub(&(work[1]), &(work[1]), &prod);
    // use 1st basis vector (the smaller one)
    quat_dim2_lattice_bilinear(&(coords[0]),
                               &(work[0]),
                               &(work[1]),
                               &((*reduced_basis)[0][0]),
                               &((*reduced_basis)[1][0]),
                               norm_q);
    ibz_rounded_div(&(coords[0]), &(coords[0]), &norm_a);
    // substract projection from vector
    ibz_mul(&prod, &((*reduced_basis)[0][0]), &(coords[0]));
    ibz_sub(&(work[0]), &(work[0]), &prod);
    ibz_mul(&prod, &((*reduced_basis)[1][0]), &(coords[0]));
    ibz_sub(&(work[1]), &(work[1]), &prod);
    // copy results to output
    ibz_copy(&((*target_minus_closest)[0]), &(work[0]));
    ibz_copy(&((*target_minus_closest)[1]), &(work[1]));
    ibz_copy(&((*closest_coords_in_basis)[0]), &(coords[0]));
    ibz_copy(&((*closest_coords_in_basis)[1]), &(coords[1]));

    ibz_vec_2_finalize(&coords);
    ibz_vec_2_finalize(&work);
    ibz_finalize(&prod);
    ibz_finalize(&sum);
    ibz_finalize(&norm_a);
    ibz_finalize(&norm_b);
    ibz_finalize(&r);
}

// give a,b,c such that ax^2 + bxy + cy^2 = N(Bz), where B is the basis, z the vector x,y and N the
// quadratic form (coord1^2 + q coord2^2)
void
quat_dim2_lattice_get_qf_on_lattice(ibz_t *qf_a,
                                    ibz_t *qf_b,
                                    ibz_t *qf_c,
                                    const ibz_mat_2x2_t *basis,
                                    const ibz_t *norm_q)
{
    ibz_t a, b, c;
    ibz_init(&a);
    ibz_init(&b);
    ibz_init(&c);
    quat_dim2_lattice_bilinear(
        &b, &((*basis)[0][0]), &((*basis)[1][0]), &((*basis)[0][1]), &((*basis)[1][1]), norm_q);
    ibz_set(&a, 2);
    ibz_mul(&b, &b, &a);
    quat_dim2_lattice_norm(&a, &((*basis)[0][0]), &((*basis)[1][0]), norm_q);
    quat_dim2_lattice_norm(&c, &((*basis)[0][1]), &((*basis)[1][1]), norm_q);
    ibz_copy(qf_a, &a);
    ibz_copy(qf_b, &b);
    ibz_copy(qf_c, &c);
    ibz_finalize(&a);
    ibz_finalize(&b);
    ibz_finalize(&c);
}

int
quat_dim2_lattice_test_cvp_condition(quat_alg_elem_t *elem,
                                     const ibz_vec_2_t *vec,
                                     const void *params)
{
    ibz_t *p = ((ibz_t *)params);
    ibz_t sum, two;
    ibz_init(&sum);
    ibz_init(&two);
    ibz_set(&two, 2);
    ibz_add(&sum, &((*vec)[0]), &((*vec)[1]));
    ibz_mod(&sum, &sum, p);
    int res = (0 == ibz_cmp(&sum, &two));
    if (res) {
        quat_alg_elem_copy_ibz(elem, &two, &((*vec)[0]), &((*vec)[1]), &((*vec)[0]), &((*vec)[1]));
    }
    ibz_finalize(&sum);
    ibz_finalize(&two);
    return (res);
}

int
quat_dim2_lattice_bound_and_condition(quat_alg_elem_t *res,
                                      const ibz_t *x,
                                      const ibz_t *y,
                                      int (*condition)(quat_alg_elem_t *,
                                                       const ibz_vec_2_t *,
                                                       const void *),
                                      const void *params,
                                      const ibz_vec_2_t *target_minus_closest,
                                      const ibz_mat_2x2_t *lat_basis,
                                      const ibz_t *norm_q,
                                      const ibz_t *norm_bound)
{
    ibz_vec_2_t sum, proposal;
    ibz_t norm;
    int ok = 0;
    ibz_init(&norm);
    ibz_vec_2_init(&sum);
    ibz_vec_2_init(&proposal);
    // put x,y from lattice basis in canonical basis
    ibz_copy(&(proposal[0]), x);
    ibz_copy(&(proposal[1]), y);
    ibz_mat_2x2_eval(&proposal, lat_basis, &proposal);
    // compute norm of target -closest-proposal
    ibz_sub(&(sum[0]), &((*target_minus_closest)[0]), &((proposal)[0]));
    ibz_sub(&(sum[1]), &((*target_minus_closest)[1]), &((proposal)[1]));
    quat_dim2_lattice_norm(&norm, &(sum[0]), &(sum[1]), norm_q);
    // test
    if (ibz_cmp(&norm, norm_bound) <= 0) {
        ok = condition(res, &sum, params);
    }
    ibz_finalize(&norm);
    ibz_vec_2_finalize(&sum);
    ibz_vec_2_finalize(&proposal);
    return (ok);
}

int
quat_dim2_lattice_qf_value_bound_generation(ibz_t *res,
                                            const ibz_t *num_a,
                                            const ibz_t *denom_a,
                                            const ibz_t *num_b,
                                            const ibz_t *denom_b)
{
    int ok = 1;
    ibz_t sqrt_num, sqrt_denom, one, zero, common_denom, r;
    ibz_init(&sqrt_num);
    ibz_init(&sqrt_denom);
    ibz_init(&one);
    ibz_init(&zero);
    ibz_init(&common_denom);
    ibz_init(&r);
    ibz_set(&zero, 0);
    ibz_set(&one, 1);
    ibz_mul(&r, num_a, denom_a);
    if ((ibz_cmp(denom_a, &zero) < 0) || ibz_is_zero(denom_a) || ibz_is_zero(denom_b)) {
        ok = 0;
    }
    if (ok) {
        ibz_sqrt_floor(&sqrt_num, num_a);
        ibz_add(&sqrt_num, &sqrt_num, &one);
        ibz_sqrt_floor(&sqrt_denom, denom_a);

        ibz_mul(&common_denom, denom_b, &sqrt_denom);
        ibz_mul(&sqrt_num, &sqrt_num, denom_b);
        ibz_mul(&r, &sqrt_denom, num_b);
        ibz_add(&sqrt_num, &sqrt_num, &r);
        ibz_div(res, &r, &sqrt_num, &common_denom);
        ibz_add(res, res, &one);
    }
    ibz_finalize(&sqrt_num);
    ibz_finalize(&sqrt_denom);
    ibz_finalize(&one);
    ibz_finalize(&zero);
    ibz_finalize(&common_denom);
    ibz_finalize(&r);
    return (ok);
}

// Uses algorithm 2.7.5 (Fincke-Pohst) from Henri Cohen's "A Course in Computational Algebraic
// Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993 Slightly
// adapted to work without rational numbers and their square roots Therefore needing a test to make
// sure the bounds are respected
int
quat_dim2_lattice_qf_enumerate_short_vec(quat_alg_elem_t *res,
                                         int (*condition)(quat_alg_elem_t *,
                                                          const ibz_vec_2_t *,
                                                          const void *),
                                         const void *params,
                                         const ibz_vec_2_t *target_minus_closest,
                                         const ibz_mat_2x2_t *lat_basis,
                                         const ibz_t *norm_q,
                                         const ibz_t *norm_bound,
                                         const int max_tries)
{
    int ok = 1;
    int found = 0;
    int tries = 0;
    int stop = 0;
    ibz_t bound_y, bound_x, x, y, disc, prod, var, one, four_a2, four_a2_norm_bound,
        four_a2_c_minus_b2, four_a3, two_a, zero, y2, qf_a, qf_b, qf_c, norm_bound_for_enumeration;
    ibz_init(&bound_y);
    ibz_init(&bound_x);
    ibz_init(&y);
    ibz_init(&y2);
    ibz_init(&x);
    ibz_init(&qf_a);
    ibz_init(&qf_b);
    ibz_init(&qf_c);
    ibz_init(&var);
    ibz_init(&one);
    ibz_init(&zero);
    ibz_init(&disc);
    ibz_init(&prod);
    ibz_init(&four_a2);
    ibz_init(&two_a);
    ibz_init(&norm_bound_for_enumeration);
    ibz_init(&four_a2_norm_bound);
    ibz_init(&four_a2_c_minus_b2);
    ibz_init(&four_a3);
    ibz_set(&one, 1);
    ibz_set(&zero, 0);
    // substract norm of distance from bound to not enumerate too large vectors at beginning
    // this is an heuristic which can fail, so in case it is really bad, we do not do it
    quat_dim2_lattice_norm(&norm_bound_for_enumeration,
                           &((*target_minus_closest)[0]),
                           &((*target_minus_closest)[1]),
                           norm_q);
    ibz_sub(&norm_bound_for_enumeration, norm_bound, &norm_bound_for_enumeration);
    if (ibz_cmp(&norm_bound_for_enumeration, &zero) <= 0) {
        ibz_copy(&norm_bound_for_enumeration, norm_bound);
    }
    // Set qf_a, qf_b, qf_c such that for x,y, a vector represented in lat_basis, ax^2 + bxy + cy^2
    // is the norm defined by norm_q
    quat_dim2_lattice_get_qf_on_lattice(&qf_a, &qf_b, &qf_c, lat_basis, norm_q);
    // discriminant computation
    ibz_mul(&disc, &qf_a, &qf_c);
    ibz_set(&var, 4);
    ibz_mul(&disc, &disc, &var);
    ibz_mul(&prod, &qf_b, &qf_b);
    ibz_sub(&disc, &disc, &prod);
    // only continue if disc is not zero nor negative
    if (ibz_cmp(&disc, &zero) <= 0) {
        ok = 0;
    }
    if (ok) {
        // precomputations
        ibz_set(&var, 2);
        ibz_mul(&two_a, &var, &qf_a);                                        // 2a init
        ibz_mul(&four_a2, &two_a, &two_a);                                   // 4a^2 init
        ibz_mul(&four_a2_norm_bound, &four_a2, &norm_bound_for_enumeration); // 4a^2*norm_bound init
        ibz_mul(&four_a3, &four_a2, &qf_a);                                  // 4a^3 init
        ibz_copy(&four_a2_c_minus_b2, &prod); // equals b^2 now, since prod was not reused since
        ibz_mul(&prod, &four_a2, &qf_c);
        ibz_sub(&four_a2_c_minus_b2, &prod, &four_a2_c_minus_b2); // now has correct value
        // y bound generation
        quat_dim2_lattice_qf_value_bound_generation(
            &bound_y, &four_a2_norm_bound, &four_a2_c_minus_b2, &zero, &one);
        ibz_neg(&y, &bound_y);
        ibz_sub(&y, &y, &one); // y is set
        while ((!found) && (!stop) && (ibz_cmp(&y, &bound_y) < 0) && (tries < max_tries)) {
            ibz_add(&y, &y, &one);
            ibz_mul(&y2, &y, &y);
            ibz_mul(&prod, &qf_b, &y);
            ibz_neg(&var, &prod); // var = -by
            ibz_mul(&prod, &y2, &four_a2_c_minus_b2);
            ibz_add(&prod, &prod, &four_a2_norm_bound); // prod = 4a^2*norm_bound + (4ca^2 - b^2)y^2
            quat_dim2_lattice_qf_value_bound_generation(&bound_x, &prod, &four_a3, &var, &two_a);
            ibz_neg(&var, &var);
            quat_dim2_lattice_qf_value_bound_generation(&x, &prod, &four_a3, &var, &two_a);
            ibz_neg(&x, &x);
            ibz_sub(&x, &x, &one); // x is set
            while ((!found) && (!stop) && (ibz_cmp(&x, &bound_x) < 0) && (tries < max_tries)) {
                tries += 1;
                ibz_add(&x, &x, &one);
                found = quat_dim2_lattice_bound_and_condition(res,
                                                              &x,
                                                              &y,
                                                              condition,
                                                              params,
                                                              target_minus_closest,
                                                              lat_basis,
                                                              norm_q,
                                                              norm_bound);
                stop = (ibz_is_zero(&x) && ibz_is_zero(&y));
            }
        }
    }
    ibz_finalize(&norm_bound_for_enumeration);
    ibz_finalize(&bound_y);
    ibz_finalize(&bound_x);
    ibz_finalize(&y);
    ibz_finalize(&y2);
    ibz_finalize(&x);
    ibz_finalize(&qf_a);
    ibz_finalize(&qf_b);
    ibz_finalize(&qf_c);
    ibz_finalize(&var);
    ibz_finalize(&one);
    ibz_finalize(&zero);
    ibz_finalize(&disc);
    ibz_finalize(&prod);
    ibz_finalize(&four_a2);
    ibz_finalize(&four_a2_norm_bound);
    ibz_finalize(&four_a2_c_minus_b2);
    ibz_finalize(&four_a3);
    ibz_finalize(&two_a);
    return (ok && found);
}

int
quat_2x2_lattice_enumerate_cvp_filter(quat_alg_elem_t *res,
                                      const ibz_mat_2x2_t *lat_basis,
                                      const ibz_vec_2_t *target,
                                      unsigned int qf,
                                      unsigned int dist_bound,
                                      int (*condition)(quat_alg_elem_t *,
                                                       const ibz_vec_2_t *,
                                                       const void *),
                                      const void *params,
                                      unsigned int max_tries)
{
    int found = 0;
    unsigned int counter = 0;
    ibz_t norm_q, norm_bound;
    ibz_mat_2x2_t reduced;
    ibz_vec_2_t closest_coords, target_minus_closest;
    ibz_init(&norm_q);
    ibz_init(&norm_bound);
    ibz_mat_2x2_init(&reduced);
    ibz_vec_2_init(&target_minus_closest);
    ibz_vec_2_init(&closest_coords);

    ibz_set(&norm_q, qf);
    ibz_set(&norm_bound, 2);
    ibz_pow(&norm_bound, &norm_bound, dist_bound);
    // reduce lattice basis
    quat_dim2_lattice_short_basis(&reduced, lat_basis, &norm_q);

    // find closest vector
    quat_dim2_lattice_closest_vector(
        &target_minus_closest, &closest_coords, &reduced, target, &norm_q);

    // enumerate short vector and test
    found = quat_dim2_lattice_qf_enumerate_short_vec(
        res, condition, params, &target_minus_closest, &reduced, &norm_q, &norm_bound, max_tries);

    ibz_finalize(&norm_q);
    ibz_finalize(&norm_bound);
    ibz_mat_2x2_finalize(&reduced);
    ibz_vec_2_finalize(&target_minus_closest);
    ibz_vec_2_finalize(&closest_coords);
    return (found);
}
