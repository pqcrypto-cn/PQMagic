#include <quaternion.h>
#include <rng.h>
#include "internal.h"

// helper functions
int
quat_lattice_equal(const quat_lattice_t *lat1, const quat_lattice_t *lat2)
{
    int equal;
    ibz_t abs_denom1, abs_denom2;
    ibz_mat_4x4_t m1, m2;
    ibz_init(&abs_denom1);
    ibz_init(&abs_denom2);
    ibz_mat_4x4_init(&m1);
    ibz_mat_4x4_init(&m2);
    // test if both are in HNF as needed
    assert(ibz_mat_4x4_is_hnf(&(lat1->basis)));
    assert(ibz_mat_4x4_is_hnf(&(lat2->basis)));
    // get absolute values of denominators
    ibz_neg(&abs_denom1, &(lat1->denom));
    if (ibz_cmp(&abs_denom1, &(lat1->denom)) < 0) {
        ibz_neg(&abs_denom1, &abs_denom1);
    }
    ibz_neg(&abs_denom2, &(lat2->denom));
    if (ibz_cmp(&abs_denom2, &(lat2->denom)) < 0) {
        ibz_neg(&abs_denom2, &abs_denom2);
    }
    // cross-multiply by denomiators to get both basis on same denominators
    ibz_mat_4x4_scalar_mul(&m1, &abs_denom2, &(lat1->basis));
    ibz_mat_4x4_scalar_mul(&m2, &abs_denom1, &(lat2->basis));
    // baoth are still HNF, so simply test for equality
    equal = ibz_mat_4x4_equal(&m1, &m2);
    ibz_finalize(&abs_denom1);
    ibz_finalize(&abs_denom2);
    ibz_mat_4x4_finalize(&m1);
    ibz_mat_4x4_finalize(&m2);
    return (equal);
}

void
quat_lattice_reduce_denom(quat_lattice_t *reduced, const quat_lattice_t *lat)
{
    ibz_t gcd;
    ibz_init(&gcd);
    ibz_mat_4x4_gcd(&gcd, &(lat->basis));
    ibz_gcd(&gcd, &gcd, &(lat->denom));
    ibz_mat_4x4_scalar_div(&(reduced->basis), &gcd, &(lat->basis));
    ibz_div(&(reduced->denom), &gcd, &(lat->denom), &gcd);
    ibz_finalize(&gcd);
}

// This function returns a lattice not under HNF. For careful internal use only
// method described in https://cseweb.ucsd.edu/classes/sp14/cse206A-a/lec4.pdf consulted on 19 of
// May 2023, 12h40 CEST
void
quat_lattice_dual_without_hnf(quat_lattice_t *dual, const quat_lattice_t *lat)
{
    ibz_mat_4x4_t inv;
    ibz_t det;
    ibz_init(&det);
    ibz_mat_4x4_init(&inv);
    ibz_mat_4x4_transpose(&inv, &(lat->basis));
    ibz_mat_4x4_inv_with_det_as_denom(&inv, &det, &inv);
    // dual_denom = det/lat_denom
    ibz_mat_4x4_scalar_mul(&(dual->basis), &(lat->denom), &inv);
    ibz_copy(&(dual->denom), &det);

    ibz_finalize(&det);
    ibz_mat_4x4_finalize(&inv);
}

void
quat_lattice_add(quat_lattice_t *res, const quat_lattice_t *lat1, const quat_lattice_t *lat2)
{
    ibz_mat_4x8_t hnf_input;
    ibz_mat_4x4_t tmp;
    ibz_mat_4x4_init(&tmp);
    ibz_mat_4x8_init(&hnf_input);
    ibz_mat_4x4_scalar_mul(&tmp, &(lat1->denom), &(lat2->basis));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&(hnf_input[i][j]), &(tmp[i][j]));
        }
    }
    ibz_mat_4x4_scalar_mul(&tmp, &(lat2->denom), &(lat1->basis));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&(hnf_input[i][4 + j]), &(tmp[i][j]));
        }
    }
    ibz_mat_4x8_hnf_core(&(res->basis), &hnf_input);
    ibz_mul(&(res->denom), &(lat1->denom), &(lat2->denom));
    quat_lattice_reduce_denom(res, res);
    ibz_mat_4x8_finalize(&hnf_input);
    ibz_mat_4x4_finalize(&tmp);
}

// method described in https://cseweb.ucsd.edu/classes/sp14/cse206A-a/lec4.pdf consulted on 19 of
// May 2023, 12h40 CEST
void
quat_lattice_intersect(quat_lattice_t *res, const quat_lattice_t *lat1, const quat_lattice_t *lat2)
{
    quat_lattice_t dual1, dual2, dual_res;
    quat_lattice_init(&dual1);
    quat_lattice_init(&dual2);
    quat_lattice_init(&dual_res);
    quat_lattice_dual_without_hnf(&dual1, lat1);

    quat_lattice_dual_without_hnf(&dual2, lat2);
    quat_lattice_add(&dual_res, &dual1, &dual2);
    quat_lattice_dual_without_hnf(res, &dual_res);
    quat_lattice_hnf(res);
    quat_lattice_finalize(&dual1);
    quat_lattice_finalize(&dual2);
    quat_lattice_finalize(&dual_res);
}

void
quat_lattice_mul(quat_lattice_t *res,
                 const quat_lattice_t *lat1,
                 const quat_lattice_t *lat2,
                 const quat_alg_t *alg)
{
    ibz_t denom, d, r;
    ibz_mat_4x8_t hnf_input;
    ibz_mat_4x4_t tmp1, tmp2;
    quat_alg_elem_t elem1, elem2, elem_res;
    quat_lattice_t lat_res;
    ibz_init(&denom);
    ibz_init(&d);
    ibz_init(&r);
    quat_lattice_init(&lat_res);
    ibz_mat_4x4_init(&tmp1);
    ibz_mat_4x4_init(&tmp2);
    quat_alg_elem_init(&elem1);
    quat_alg_elem_init(&elem2);
    quat_alg_elem_init(&elem_res);
    ibz_mat_4x8_init(&hnf_input);
    ibz_mul(&denom, &(lat1->denom), &(lat2->denom));
    for (int k = 0; k < 2; k++) {
        quat_alg_elem_copy_ibz(&elem1,
                               &(lat1->denom),
                               &(lat1->basis[0][k]),
                               &(lat1->basis[1][k]),
                               &(lat1->basis[2][k]),
                               &(lat1->basis[3][k]));
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ibz_copy(&(elem2.coord[j]), &(lat2->basis[i][j]));
            }
            quat_alg_elem_copy_ibz(&elem2,
                                   &(lat2->denom),
                                   &(lat2->basis[0][i]),
                                   &(lat2->basis[1][i]),
                                   &(lat2->basis[2][i]),
                                   &(lat2->basis[3][i]));
            quat_alg_mul(&elem_res, &elem1, &elem2, alg);
            // should check that denom is as expected (product of both), otherwise set it to that to
            // avoid issues
            if (0 != ibz_cmp(&denom, &(elem_res.denom))) {
                ibz_div(&d, &r, &denom, &(elem_res.denom));
                quat_alg_elem_mul_by_scalar(&elem_res, &d, &elem_res);
            }
            for (int j = 0; j < 4; j++) {
                ibz_copy(&(hnf_input[j][4 * k + i]), &(elem_res.coord[j]));
            }
        }
    }
    ibz_mat_4x8_hnf_core(&tmp1, &hnf_input);

    for (int k = 0; k < 2; k++) {
        quat_alg_elem_copy_ibz(&elem1,
                               &(lat1->denom),
                               &(lat1->basis[0][2 + k]),
                               &(lat1->basis[1][2 + k]),
                               &(lat1->basis[2][2 + k]),
                               &(lat1->basis[3][2 + k]));
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                ibz_copy(&(elem2.coord[j]), &(lat2->basis[i][j]));
            }
            quat_alg_elem_copy_ibz(&elem2,
                                   &(lat2->denom),
                                   &(lat2->basis[0][i]),
                                   &(lat2->basis[1][i]),
                                   &(lat2->basis[2][i]),
                                   &(lat2->basis[3][i]));
            quat_alg_mul(&elem_res, &elem1, &elem2, alg);
            // should check that denom is as expected (product of both), otherwise set it to that to
            // avoid issues
            if (0 != ibz_cmp(&denom, &(elem_res.denom))) {
                ibz_div(&d, &r, &denom, &(elem_res.denom));
                quat_alg_elem_mul_by_scalar(&elem_res, &d, &elem_res);
            }
            for (int j = 0; j < 4; j++) {
                ibz_copy(&(hnf_input[j][4 * k + i]), &(elem_res.coord[j]));
            }
        }
    }
    ibz_mat_4x8_hnf_core(&tmp2, &hnf_input);

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&(hnf_input[i][j]), &(tmp1[i][j]));
            ibz_copy(&(hnf_input[i][4 + j]), &(tmp2[i][j]));
        }
    }
    ibz_mat_4x8_hnf_core(&(res->basis), &hnf_input);

    ibz_copy(&(res->denom), &denom);
    quat_lattice_reduce_denom(res, res);

    ibz_mat_4x8_finalize(&hnf_input);
    ibz_mat_4x4_finalize(&tmp1);
    ibz_mat_4x4_finalize(&tmp2);
    quat_alg_elem_finalize(&elem1);
    quat_alg_elem_finalize(&elem2);
    quat_alg_elem_finalize(&elem_res);
    quat_lattice_finalize(&lat_res);
    ibz_finalize(&denom);
    ibz_finalize(&d);
    ibz_finalize(&r);
}

// lattice assumed of full rank and under HNF, none of both is tested so far
int
quat_lattice_contains_without_alg(quat_alg_coord_t *coord,
                                  const quat_lattice_t *lat,
                                  const quat_alg_elem_t *x)
{
    int res = 1;
    ibz_vec_4_t work_coord, work_x, column;
    ibz_t r, prod, one;
    ibz_init(&r);
    ibz_init(&prod);
    ibz_init(&one);
    ibz_vec_4_init(&work_coord);
    ibz_vec_4_init(&work_x);
    ibz_vec_4_init(&column);
    // test if rank 4 lattice under HNF
    assert(ibz_mat_4x4_is_hnf(&(lat->basis)));
    for (int i = 0; i < 4; i++) {
        assert(!ibz_is_zero(&(lat->basis[i][i])));
    }
    ibz_set(&one, 1);
    for (int i = 0; i < 4; i++) {
        // put on same denominator, 1st part
        ibz_mul(&(work_x[i]), &(x->coord[i]), &(lat->denom));
    }
    for (int i = 0; i < 4; i++) {
        if (res) {
            // put on same denominator, 2nd part
            ibz_mul(&prod, &(x->denom), &(lat->basis[3 - i][3 - i]));
            ibz_div(&(work_coord[3 - i]), &r, &(work_x[3 - i]), &prod);
            if (ibz_is_zero(&r)) {
                for (int j = 0; j < 4; j++) {
                    // put on same denominator here also
                    ibz_mul(&(column[j]), &(lat->basis[j][3 - i]), &(x->denom));
                }
                // negate quotient
                ibz_neg(&r, &(work_coord[3 - i]));
                ibz_vec_4_linear_combination(&work_x, &one, &work_x, &r, &column);
            } else {
                res = 0;
            }
        }
    }
    // final test
    for (int i = 0; i < 4; i++) {
        // now x should be 0 if it is in lattice
        res = res && ibz_is_zero(&(work_x[i]));
    }

    // copy result
    if (res && (coord != NULL)) {
        for (int i = 0; i < 4; i++) {
            ibz_copy(&((*coord)[i]), &(work_coord[i]));
        }
    }
    ibz_finalize(&r);
    ibz_finalize(&prod);
    ibz_finalize(&one);
    ibz_vec_4_finalize(&work_coord);
    ibz_vec_4_finalize(&work_x);
    ibz_vec_4_finalize(&column);
    return (res);
}

// lattice assumed of full rank and under HNF, none of both is tested so far
int
quat_lattice_contains(quat_alg_coord_t *coord,
                      const quat_lattice_t *lat,
                      const quat_alg_elem_t *x,
                      const quat_alg_t *alg)
{
    return (quat_lattice_contains_without_alg(coord, lat, x));
}

void
quat_lattice_index(ibz_t *index, const quat_lattice_t *sublat, const quat_lattice_t *overlat)
{
    ibz_t tmp;
    ibz_init(&tmp);

    // index = (overlat->denom)⁴
    ibz_mul(index, &overlat->denom, &overlat->denom);
    ibz_mul(index, index, index);
    // index = (overlat->denom)⁴ · det(sublat->basis)
    for (int i = 0; i < 4; i++) {
        ibz_mul(index, index, &sublat->basis[i][i]);
    }
    // tmp = (sublat->denom)⁴
    ibz_mul(&tmp, &sublat->denom, &sublat->denom);
    ibz_mul(&tmp, &tmp, &tmp);
    // tmp = (sublat->denom)⁴ · det(overlat->basis)
    for (int i = 0; i < 4; i++) {
        ibz_mul(&tmp, &tmp, &overlat->basis[i][i]);
    }
    // index = index / tmp
    ibz_div(index, &tmp, index, &tmp);
    assert(ibz_is_zero(&tmp));
    // index = |index|
    ibz_abs(index, index);

    ibz_finalize(&tmp);
}

void
quat_lattice_hnf(quat_lattice_t *lat)
{
    ibz_mat_4x8_t hnf_input;
    ibz_mat_4x8_init(&hnf_input);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_set(&(hnf_input[i][j]), 0);
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&(hnf_input[i][4 + j]), &(lat->basis[i][j]));
        }
    }
    ibz_mat_4x8_hnf_core(&(lat->basis), &hnf_input);
    quat_lattice_reduce_denom(lat, lat);
    ibz_mat_4x8_finalize(&hnf_input);
}

int
quat_lattice_random_elem(quat_alg_elem_t *elem, const quat_lattice_t *lattice, unsigned char n)
{
    assert(n <= 64);

    // Set elem to 0
    for (int i = 0; i < 4; i++)
        ibz_set(&elem->coord[i], 0);
    ibz_set(&elem->denom, 1);

    // Take random coefficients
    int64_t rand[4];
    int randret = randombytes((unsigned char *)rand, 4 * sizeof(uint64_t));
    if (randret != 0)
        return 0;

    // Make the linear combination
    quat_alg_elem_t tmp;
    quat_alg_elem_init(&tmp);
    for (int j = 0; j < 4; j++) {
        rand[j] >>= (64 - n);
        for (int i = 0; i < 4; i++) {
            ibz_set(&tmp.coord[i], rand[j]);
            ibz_mul(&tmp.coord[i], &tmp.coord[i], &lattice->basis[i][j]);
        }
        quat_alg_add(elem, elem, &tmp);
    }
    quat_alg_elem_finalize(&tmp);

    // Set the denominator
    ibz_copy(&elem->denom, &lattice->denom);

    return 1;
}

/** Right transporter **/

/** @brief to[to_row] = (-1)^neg · c · from[from_row]
 *
 * c may be NULL, in which case c = 1
 */
static inline void
copy_row(ibz_mat_4x4_t to,
         int to_row,
         int neg,
         const ibz_t *c,
         const ibz_mat_4x4_t from,
         int from_row)
{
    for (int j = 0; j < 4; j++) {
        if (c)
            ibz_mul(&to[to_row][j], c, &from[from_row][j]);
        else
            ibz_copy(&to[to_row][j], &from[from_row][j]);
        if (neg)
            ibz_neg(&to[to_row][j], &to[to_row][j]);
    }
}

/** @brief copy matrix into columns of cols
 */
static inline void
mat_to_col_16x4(ibz_t (*cols)[16][4], int col, const ibz_mat_4x4_t *mat)
{
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            ibz_copy(&((*cols)[j + 4 * i][col]), &((*mat)[i][j]));
}

/** @brief take the gcd of content with all entries
 */
static inline void
mat_16x4_content(ibz_t *content, const ibz_t (*mat)[16][4])
{
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 4; j++)
            ibz_gcd(content, content, &((*mat)[i][j]));
}

/** @brief take the gcd of content with all entries
 */
static inline void
mat_16x4_mul_by_scalar(ibz_t (*prod)[16][4], const ibz_t (*mat)[16][4], const ibz_t *scalar)
{
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 4; j++)
            ibz_mul(&((*prod)[i][j]), scalar, &((*mat)[i][j]));
}

/** @brief take the gcd of content with all entries
 */
static inline int
mat_16x4_div_by_scalar(ibz_t (*quot)[16][4], const ibz_t (*mat)[16][4], const ibz_t *scalar)
{
    int ok = 1;
    ibz_t r;
    ibz_init(&r);
    for (int i = 0; i < 16; i++)
        for (int j = 0; j < 4; j++)
            ibz_div(&((*quot)[i][j]), &r, &((*mat)[i][j]), scalar);
    ok = ok && (ibz_is_zero(&r));
    ibz_finalize(&r);
    return (ok);
}

void
quat_lattice_right_transporter(quat_lattice_t *trans,
                               const quat_lattice_t *lat1,
                               const quat_lattice_t *lat2,
                               const quat_alg_t *alg)
{
    ibz_t det1, det2, tmp, thrash, content;
    ibz_mat_4x4_t lat2_inv, tmpmat;
    ibz_t work[16][4];
    ibz_init(&det1);
    ibz_init(&det2);
    ibz_init(&tmp);
    ibz_init(&thrash);
    ibz_init(&content);
    ibz_mat_4x4_init(&lat2_inv);
    ibz_mat_4x4_init(&tmpmat);
    ibz_mat_init(16, 4, work);

    // Compute the dual lattice Λ₂* of Λ₂ = num(lat2)
    // Could be optimized, given it's triangular
    // M₂ = Λ₂*/det₂
    int invertible = ibz_mat_4x4_inv_with_det_as_denom(&lat2_inv, &det2, &lat2->basis);
    assert(invertible);

    // WARNING: hard-cording right multiplication table of "standard" basis
    // Prone to breakage if the basis changes
    //
    // M = d₂/(d₁ det₂) · table
    //
    // Λ₂* Id Λ₁
    ibz_mat_4x4_mul(&tmpmat, &lat2_inv, &lat1->basis);
    mat_to_col_16x4(&work, 0, &tmpmat);
    // Λ₂* [0 -1 0 0 ; 1 0 0 0 ; 0 0 0 1 ; 0 0 -1 0] Λ₁
    copy_row(tmpmat, 0, 1, NULL, lat1->basis, 1);
    copy_row(tmpmat, 1, 0, NULL, lat1->basis, 0);
    copy_row(tmpmat, 2, 0, NULL, lat1->basis, 3);
    copy_row(tmpmat, 3, 1, NULL, lat1->basis, 2);
    ibz_mat_4x4_mul(&tmpmat, &lat2_inv, &tmpmat);
    mat_to_col_16x4(&work, 1, &tmpmat);
    // Λ₂* [0 0 -p 0 ; 0 0 0 -p ; 1 0 0 0 ; 0 1 0 0] Λ₁
    copy_row(tmpmat, 0, 1, &alg->p, lat1->basis, 2);
    copy_row(tmpmat, 1, 1, &alg->p, lat1->basis, 3);
    copy_row(tmpmat, 2, 0, NULL, lat1->basis, 0);
    copy_row(tmpmat, 3, 0, NULL, lat1->basis, 1);
    ibz_mat_4x4_mul(&tmpmat, &lat2_inv, &tmpmat);
    mat_to_col_16x4(&work, 2, &tmpmat);
    // Λ₂*[0 0 0 -p ; 0 0 p 0 ; 0 -1 0 0 ; 1 0 0 0] Λ₁
    copy_row(tmpmat, 0, 1, &alg->p, lat1->basis, 3);
    copy_row(tmpmat, 1, 0, &alg->p, lat1->basis, 2);
    copy_row(tmpmat, 2, 1, NULL, lat1->basis, 1);
    copy_row(tmpmat, 3, 0, NULL, lat1->basis, 0);
    ibz_mat_4x4_mul(&tmpmat, &lat2_inv, &tmpmat);
    mat_to_col_16x4(&work, 3, &tmpmat);

    ibz_mul(&det1, &lat1->basis[0][0], &lat1->basis[1][1]);
    ibz_mul(&tmp, &lat1->basis[2][2], &lat1->basis[3][3]);
    ibz_mul(&det1, &det1, &tmp);
    ibz_mul(&det1, &det1, &lat2->denom);
    ibz_gcd(&tmp, &det1, &lat1->denom);
    ibz_div(&det1, &thrash, &det1, &tmp);

    {
        int ok = 1;
        mat_16x4_content(&content, &work);
        ok &= mat_16x4_div_by_scalar(&work, &work, &content);
        assert(ok);

        ibz_mul(&content, &content, &lat2->denom);
        ibz_mul(&det2, &det2, &lat1->denom);
        ibz_gcd(&tmp, &det2, &content);
        ibz_div(&det2, &thrash, &det2, &tmp);
        ibz_div(&content, &thrash, &content, &tmp);
        mat_16x4_mul_by_scalar(&work, &work, &content);
        ibz_mul(&det2, &det2, &det1);

        ibz_mat_right_ker_mod(16, 4, trans->basis, work, &det2);
        ibz_mat_4x4_hnf_mod(&trans->basis, &trans->basis, &det2);
        ibz_copy(&trans->denom, &det1);
        quat_lattice_reduce_denom(trans, trans);
    }

    ibz_mat_finalize(16, 4, work);
    ibz_finalize(&det1);
    ibz_finalize(&det2);
    ibz_finalize(&tmp);
    ibz_finalize(&thrash);
    ibz_finalize(&content);
    ibz_mat_4x4_finalize(&lat2_inv);
    ibz_mat_4x4_finalize(&tmpmat);
}
