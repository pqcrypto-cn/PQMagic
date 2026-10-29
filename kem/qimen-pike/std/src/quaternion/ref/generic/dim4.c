#include <quaternion.h>
#include "internal.h"

// internal helper functions
void
ibz_mat_4x4_mul(ibz_mat_4x4_t *res, const ibz_mat_4x4_t *a, const ibz_mat_4x4_t *b)
{
    ibz_mat_4x4_t mat;
    ibz_t prod;
    ibz_init(&prod);
    ibz_mat_4x4_init(&mat);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_set(&(mat[i][j]), 0);
            for (int k = 0; k < 4; k++) {
                ibz_mul(&prod, &((*a)[i][k]), &((*b)[k][j]));
                ibz_add(&(mat[i][j]), &(mat[i][j]), &prod);
            }
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&((*res)[i][j]), &(mat[i][j]));
        }
    }
    ibz_mat_4x4_finalize(&mat);
    ibz_finalize(&prod);
}

// helper functions for lattices
void
ibz_vec_4_set(ibz_vec_4_t *vec, int64_t coord0, int64_t coord1, int64_t coord2, int64_t coord3)
{
    ibz_set(&((*vec)[0]), coord0);
    ibz_set(&((*vec)[1]), coord1);
    ibz_set(&((*vec)[2]), coord2);
    ibz_set(&((*vec)[3]), coord3);
}

void
ibz_vec_4_copy(ibz_vec_4_t *new, const ibz_vec_4_t *vec)
{
    for (int i = 0; i < 4; i++) {
        ibz_copy(&((*new)[i]), &((*vec)[i]));
    }
}

void
ibz_vec_4_negate(ibz_vec_4_t *neg, const ibz_vec_4_t *vec)
{
    for (int i = 0; i < 4; i++) {
        ibz_neg(&((*neg)[i]), &((*vec)[i]));
    }
}

void
ibz_vec_4_linear_combination(ibz_vec_4_t *lc,
                             const ibz_t *coeff_a,
                             const ibz_vec_4_t *vec_a,
                             const ibz_t *coeff_b,
                             const ibz_vec_4_t *vec_b)
{
    ibz_t prod;
    ibz_vec_4_t sums;
    ibz_vec_4_init(&sums);
    ibz_init(&prod);
    for (int i = 0; i < 4; i++) {
        ibz_mul(&(sums[i]), coeff_a, &((*vec_a)[i]));
        ibz_mul(&prod, coeff_b, &((*vec_b)[i]));
        ibz_add(&(sums[i]), &(sums[i]), &prod);
    }
    for (int i = 0; i < 4; i++) {
        ibz_copy(&((*lc)[i]), &(sums[i]));
    }
    ibz_finalize(&prod);
    ibz_vec_4_finalize(&sums);
}

int
ibz_vec_4_scalar_div(ibz_vec_4_t *quot, const ibz_t *scalar, const ibz_vec_4_t *vec)
{
    int res = 1;
    ibz_t r;
    ibz_init(&r);
    for (int i = 0; i < 4; i++) {
        ibz_div(&((*quot)[i]), &r, &((*vec)[i]), scalar);
        res = res && ibz_is_zero(&r);
    }
    ibz_finalize(&r);
    return (res);
}

void
ibz_mat_4x4_copy(ibz_mat_4x4_t *new, const ibz_mat_4x4_t *mat)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&((*new)[i][j]), &((*mat)[i][j]));
        }
    }
}

void
ibz_mat_4x4_negate(ibz_mat_4x4_t *neg, const ibz_mat_4x4_t *mat)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_neg(&((*neg)[i][j]), &((*mat)[i][j]));
        }
    }
}

void
ibz_mat_4x4_transpose(ibz_mat_4x4_t *transposed, const ibz_mat_4x4_t *mat)
{
    ibz_mat_4x4_t work;
    ibz_mat_4x4_init(&work);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&(work[i][j]), &((*mat)[j][i]));
        }
    }
    ibz_mat_4x4_copy(transposed, &work);
    ibz_mat_4x4_finalize(&work);
}

void
ibz_mat_4x4_zero(ibz_mat_4x4_t *zero)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_set(&((*zero)[i][j]), 0);
        }
    }
}

void
ibz_mat_4x4_identity(ibz_mat_4x4_t *id)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_set(&((*id)[i][j]), 0);
        }
        ibz_set(&((*id)[i][i]), 1);
    }
}

int
ibz_mat_4x4_is_identity(const ibz_mat_4x4_t *mat)
{
    int res = 1;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            res = res && (ibz_get(&((*mat)[i][j])) == (i == j));
        }
    }
    return (res);
}

int
ibz_mat_4x4_equal(const ibz_mat_4x4_t *mat1, const ibz_mat_4x4_t *mat2)
{
    int res = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            res = res || ibz_cmp(&((*mat1)[i][j]), &((*mat2)[i][j]));
        }
    }
    return (!res);
}

void
ibz_mat_4x4_scalar_mul(ibz_mat_4x4_t *prod, const ibz_t *scalar, const ibz_mat_4x4_t *mat)
{
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_mul(&((*prod)[i][j]), &((*mat)[i][j]), scalar);
        }
    }
}

void
ibz_mat_4x4_gcd(ibz_t *gcd, const ibz_mat_4x4_t *mat)
{
    ibz_t d;
    ibz_init(&d);
    ibz_copy(&d, &((*mat)[0][0]));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_gcd(&d, &d, &((*mat)[i][j]));
        }
    }
    ibz_copy(gcd, &d);
    ibz_finalize(&d);
}

int
ibz_mat_4x4_scalar_div(ibz_mat_4x4_t *quot, const ibz_t *scalar, const ibz_mat_4x4_t *mat)
{
    int res = 1;
    ibz_t r;
    ibz_init(&r);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_div(&((*quot)[i][j]), &r, &((*mat)[i][j]), scalar);
            res = res && ibz_is_zero(&r);
        }
    }
    ibz_finalize(&r);
    return (res);
}

int
ibz_mat_4x4_is_hnf(const ibz_mat_4x4_t *mat)
{
    int res = 1;
    int found = 0;
    int ind = 0;
    ibz_t zero;
    ibz_init(&zero);
    // upper triangular
    for (int i = 0; i < 4; i++) {
        // upper triangular
        for (int j = 0; j < i; j++) {
            res = res && ibz_is_zero(&((*mat)[i][j]));
        }
        // find first non 0 element of line
        found = 0;
        for (int j = i; j < 4; j++) {
            if (found) {
                // all values are positive, and first non-0 is the largest of that line
                res = res && (ibz_cmp(&((*mat)[i][j]), &zero) >= 0);
                res = res && (ibz_cmp(&((*mat)[i][ind]), &((*mat)[i][j])) > 0);
            } else {
                if (!ibz_is_zero(&((*mat)[i][j]))) {
                    found = 1;
                    ind = j;
                    // mustbe non-negative
                    res = res && (ibz_cmp(&((*mat)[i][j]), &zero) > 0);
                }
            }
        }
    }
    // check that first nom-zero elements ndex per column is strictly increasing
    int linestart = -1;
    int i = 0;
    for (int j = 0; j < 4; j++) {
        while ((i < 4) && (ibz_is_zero(&((*mat)[i][j])))) {
            i = i + 1;
        }
        if (i != 4) {
            res = res && (linestart < i);
        }
        i = 0;
    }
    ibz_finalize(&zero);
    return res;
}

// Algorithm used is the one at number 2.4.5 in Henri Cohen's "A Course in Computational Algebraic
// Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993
//  assumes ibz_xgcd outputs u,v which are small in absolute value (as described in the book)void
//  ibz_mat_4x8_hnf_core(ibz_mat_4x4_t *hnf, const ibz_mat_4x8_t *generators)
void
ibz_mat_4x8_hnf_core(ibz_mat_4x4_t *hnf, const ibz_mat_4x8_t *generators)
{
    int i = 3;
    int j = 7;
    int k = 7;
    ibz_t b, u, v, d, zero, coeff_1, coeff_2, r;
    ibz_vec_4_t c;
    ibz_vec_4_t a[8];
    ibz_init(&b);
    ibz_init(&d);
    ibz_init(&u);
    ibz_init(&v);
    ibz_init(&r);
    ibz_init(&coeff_1);
    ibz_init(&coeff_2);
    ibz_init(&zero);
    ibz_set(&zero, 0);
    ibz_vec_4_init(&c);
    for (int h = 0; h < 8; h++) {
        ibz_vec_4_init(&(a[h]));
        ibz_copy(&(a[h][0]), &((*generators)[0][h]));
        ibz_copy(&(a[h][1]), &((*generators)[1][h]));
        ibz_copy(&(a[h][2]), &((*generators)[2][h]));
        ibz_copy(&(a[h][3]), &((*generators)[3][h]));
    }
    while (i != -1) {
        while (j != 0) {
            j = j - 1;
            if (!ibz_is_zero(&(a[j][i]))) {
                // assumtion that ibz_xgcd outputs u,v which are small in absolute value is needed
                // here
                ibz_xgcd(&d, &u, &v, &(a[k][i]), &(a[j][i]));
                // also, needs u non 0, but v can be 0 if needed
                if (ibz_is_zero(&u)) {
                    ibz_div(&v, &r, &(a[k][i]), &(a[j][i]));
                    ibz_set(&u, 1);
                    ibz_sub(&v, &u, &v);
                }
                ibz_vec_4_linear_combination(&c, &u, &(a[k]), &v, &(a[j]));
                ibz_div(&coeff_1, &r, &(a[k][i]), &d);
                ibz_div(&coeff_2, &r, &(a[j][i]), &d);
                ibz_neg(&coeff_2, &coeff_2);
                ibz_vec_4_linear_combination(&(a[j]), &coeff_1, &(a[j]), &coeff_2, &(a[k]));
                ibz_vec_4_copy(&(a[k]), &c);
            }
        }
        ibz_copy(&b, &(a[k][i]));
        if (ibz_cmp(&b, &zero) < 0) {
            ibz_vec_4_negate(&(a[k]), &(a[k]));
            ibz_neg(&b, &b);
        }
        if (ibz_is_zero(&b)) {
            k = k + 1;
        } else {
            for (j = k + 1; j < 8; j++) {
                ibz_div(&d, &r, &(a[j][i]), &b);
                if (ibz_cmp(&r, &zero) < 0) {
                    ibz_set(&r, 1);
                    ibz_sub(&d, &d, &r);
                }
                ibz_set(&r, 1);
                ibz_neg(&d, &d);
                ibz_vec_4_linear_combination(&(a[j]), &r, &(a[j]), &d, &(a[k]));
            }
        }
        if (i != 0) {
            k = k - 1;
            j = k;
        }
        i = i - 1;
    }
    for (j = 4; j < 8; j++) {
        for (i = 0; i < 4; i++) {
            ibz_copy(&((*hnf)[i][j - 4]), &(a[j][i]));
        }
    }

    ibz_finalize(&b);
    ibz_finalize(&d);
    ibz_finalize(&u);
    ibz_finalize(&v);
    ibz_finalize(&r);
    ibz_finalize(&coeff_1);
    ibz_finalize(&coeff_2);
    ibz_finalize(&zero);
    ibz_vec_4_finalize(&c);
    for (int h = 0; h < 8; h++) {
        ibz_vec_4_finalize(&(a[h]));
    }
}

void
ibz_mat_4x4_hnf_mod(ibz_mat_4x4_t *hnf, const ibz_mat_4x4_t *mat, const ibz_t *mod)
{
    ibz_mat_4x8_t input;
    ibz_mat_4x8_init(&input);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_copy(&(input[i][j]), &((*mat)[i][j]));
            ibz_set(&(input[i][j + 4]), 0);
        }
        ibz_copy(&(input[i][i + 4]), mod);
    }
    ibz_mat_4x8_hnf_core(hnf, &input);
    ibz_mat_4x8_finalize(&input);
}

// functions to verify lll
void
ibq_vec_4_copy_ibz(ibq_t (*vec)[4],
                   const ibz_t *coeff0,
                   const ibz_t *coeff1,
                   const ibz_t *coeff2,
                   const ibz_t *coeff3)
{
    ibz_t one;
    ibz_init(&one);
    ibz_set(&one, 1);
    ibq_set(&((*vec)[0]), coeff0, &one);
    ibq_set(&((*vec)[1]), coeff1, &one);
    ibq_set(&((*vec)[2]), coeff2, &one);
    ibq_set(&((*vec)[3]), coeff3, &one);
    ibz_finalize(&one);
}

void
quat_dim4_lll_bilinear(ibq_t *b, const ibq_t (*vec0)[4], const ibq_t (*vec1)[4], const ibz_t *q)
{
    ibq_t sum, prod, norm_q;
    ibz_t one;
    ibz_init(&one);
    ibz_set(&one, 1);
    ibq_init(&sum);
    ibq_init(&prod);
    ibq_init(&norm_q);
    ibq_set(&norm_q, q, &one);

    ibq_mul(&sum, &((*vec0)[0]), &((*vec1)[0]));
    ibq_mul(&prod, &((*vec0)[1]), &((*vec1)[1]));
    ibq_add(&sum, &sum, &prod);
    ibq_mul(&prod, &((*vec0)[2]), &((*vec1)[2]));
    ibq_mul(&prod, &prod, &norm_q);
    ibq_add(&sum, &sum, &prod);
    ibq_mul(&prod, &((*vec0)[3]), &((*vec1)[3]));
    ibq_mul(&prod, &prod, &norm_q);
    ibq_add(b, &sum, &prod);

    ibz_finalize(&one);
    ibq_finalize(&sum);
    ibq_finalize(&prod);
    ibq_finalize(&norm_q);
}

void
quat_dim4_gram_schmidt_transposed_with_ibq(ibq_t (*orthogonalised_transposed)[4][4],
                                           const ibz_mat_4x4_t *mat,
                                           const ibz_t *q)
{
    ibq_t work[4][4];
    ibq_t vec[4];
    ibq_t norm, b, coeff, prod;
    ibq_init(&norm);
    ibq_init(&coeff);
    ibq_init(&prod);
    ibq_init(&b);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibq_init(&(work[i][j]));
        }
        ibq_init(&(vec[i]));
    }
    // transpose the input matrix to be able to work on vectors
    for (int i = 0; i < 4; i++) {
        ibq_vec_4_copy_ibz(
            &(work[i]), &((*mat)[0][i]), &((*mat)[1][i]), &((*mat)[2][i]), &((*mat)[3][i]));
    }

    for (int i = 0; i < 4; i++) {
        quat_dim4_lll_bilinear(&norm, &(work[i]), &(work[i]), q);
        ibq_inv(&norm, &norm);
        for (int j = i + 1; j < 4; j++) {
            ibq_vec_4_copy_ibz(
                &vec, &((*mat)[0][j]), &((*mat)[1][j]), &((*mat)[2][j]), &((*mat)[3][j]));
            quat_dim4_lll_bilinear(&b, &(work[i]), &vec, q);
            ibq_mul(&coeff, &norm, &b);
            for (int k = 0; k < 4; k++) {
                ibq_mul(&prod, &coeff, &(work[i][k]));
                ibq_sub(&(work[j][k]), &(work[j][k]), &prod);
            }
        }
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibq_copy(&((*orthogonalised_transposed)[i][j]), &(work[i][j]));
        }
    }

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibq_finalize(&(work[i][j]));
        }
        ibq_finalize(&(vec[i]));
    }
    ibq_finalize(&norm);
    ibq_finalize(&coeff);
    ibq_finalize(&prod);
    ibq_finalize(&b);
}

int
quat_dim4_lll_verify(const ibz_mat_4x4_t *mat, const ibq_t *coeff, const ibz_t *q)
{
    int res = 1;
    ibq_t orthogonalised_transposed[4][4];
    ibq_t tmp_vec[4];
    ibq_t div, tmp, mu, two, norm, b;
    ibz_t mu2_floored, num, denom;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibq_init(&(orthogonalised_transposed[i][j]));
        }
        ibq_init(&(tmp_vec[i]));
    }
    ibq_init(&div);
    ibq_init(&tmp);
    ibq_init(&norm);
    ibq_init(&b);
    ibq_init(&mu);
    ibq_init(&two);
    ibz_init(&mu2_floored);
    ibz_init(&num);
    ibz_init(&denom);
    ibz_set(&num, 2);
    ibz_set(&denom, 1);
    ibq_set(&two, &num, &denom);

    quat_dim4_gram_schmidt_transposed_with_ibq(&orthogonalised_transposed, mat, q);
    // check small bilinear products/norms
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < i; j++) {
            ibq_vec_4_copy_ibz(
                &tmp_vec, &((*mat)[0][i]), &((*mat)[1][i]), &((*mat)[2][i]), &((*mat)[3][i]));
            quat_dim4_lll_bilinear(&b, &(orthogonalised_transposed[j]), &tmp_vec, q);
            quat_dim4_lll_bilinear(
                &norm, &(orthogonalised_transposed[j]), &(orthogonalised_transposed[j]), q);
            ibq_inv(&tmp, &norm);
            ibq_mul(&mu, &b, &tmp);
            // mu contains 2mu from now on
            ibq_mul(&tmp, &mu, &two);
            ibq_num(&num, &tmp);
            ibq_denom(&denom, &tmp);
            // assume rounding to 0
            ibz_div(&mu2_floored, &denom, &num, &denom);
            // 2*mu floores is 0 or mu is exactly 1/2, so (2mu)^2 is exactly 1
            ibq_mul(&tmp, &tmp, &tmp);
            res = res && (ibz_is_zero(&mu2_floored) || ibq_is_one(&tmp));
        }
    }
    for (int i = 1; i < 4; i++) {
        ibq_vec_4_copy_ibz(
            &tmp_vec, &((*mat)[0][i]), &((*mat)[1][i]), &((*mat)[2][i]), &((*mat)[3][i]));
        quat_dim4_lll_bilinear(&b, &(orthogonalised_transposed[i - 1]), &tmp_vec, q);
        quat_dim4_lll_bilinear(
            &norm, &(orthogonalised_transposed[i - 1]), &(orthogonalised_transposed[i - 1]), q);
        ibq_inv(&tmp, &norm);
        ibq_mul(&mu, &b, &tmp);
        // tmp is mu^2
        ibq_mul(&tmp, &mu, &mu);
        // mu is coeff-mu^2
        ibq_sub(&mu, coeff, &tmp);
        quat_dim4_lll_bilinear(
            &tmp, &(orthogonalised_transposed[i]), &(orthogonalised_transposed[i]), q);
        // get (3/4-mu^2)norm(i-1)
        ibq_mul(&div, &norm, &mu);
        res = res && (ibq_cmp(&tmp, &div) >= 0);
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibq_finalize(&(orthogonalised_transposed[i][j]));
        }
        ibq_finalize(&(tmp_vec[i]));
    }
    ibq_finalize(&div);
    ibq_finalize(&norm);
    ibq_finalize(&b);
    ibq_finalize(&tmp);
    ibq_finalize(&mu);
    ibq_finalize(&two);
    ibz_finalize(&mu2_floored);
    ibz_finalize(&num);
    ibz_finalize(&denom);
    return (res);
}

// 4x4 inversion helper functions
void
ibz_inv_dim4_make_coeff_pmp(ibz_t *coeff,
                            const ibz_t *a1,
                            const ibz_t *a2,
                            const ibz_t *b1,
                            const ibz_t *b2,
                            const ibz_t *c1,
                            const ibz_t *c2)
{
    ibz_t prod, sum;
    ibz_init(&prod);
    ibz_init(&sum);
    ibz_mul(&sum, a1, a2);
    ibz_mul(&prod, b1, b2);
    ibz_sub(&sum, &sum, &prod);
    ibz_mul(&prod, c1, c2);
    ibz_add(coeff, &sum, &prod);
    ibz_finalize(&prod);
    ibz_finalize(&sum);
}

void
ibz_inv_dim4_make_coeff_mpm(ibz_t *coeff,
                            const ibz_t *a1,
                            const ibz_t *a2,
                            const ibz_t *b1,
                            const ibz_t *b2,
                            const ibz_t *c1,
                            const ibz_t *c2)
{
    ibz_t prod, sum;
    ibz_init(&prod);
    ibz_init(&sum);
    ibz_mul(&sum, b1, b2);
    ibz_mul(&prod, a1, a2);
    ibz_sub(&sum, &sum, &prod);
    ibz_mul(&prod, c1, c2);
    ibz_sub(coeff, &sum, &prod);
    ibz_finalize(&prod);
    ibz_finalize(&sum);
}

// Method from https://www.geometrictools.com/Documentation/LaplaceExpansionTheorem.pdf 3rd of May
// 2023, 16h15 CEST
int
ibz_mat_4x4_inv_with_det_as_denom(ibz_mat_4x4_t *inv, ibz_t *det, const ibz_mat_4x4_t *mat)
{
    ibz_t prod, work_det;
    ibz_mat_4x4_t work;
    ibz_t s[6];
    ibz_t c[6];
    for (int i = 0; i < 6; i++) {
        ibz_init(&(s[i]));
        ibz_init(&(c[i]));
    }
    ibz_mat_4x4_init(&work);
    ibz_init(&prod);
    ibz_init(&work_det);

    // compute some 2x2 minors, store them in s and c
    for (int i = 0; i < 3; i++) {
        ibz_mat_2x2_det_from_ibz(
            &(s[i]), &((*mat)[0][0]), &((*mat)[0][i + 1]), &((*mat)[1][0]), &((*mat)[1][i + 1]));
        ibz_mat_2x2_det_from_ibz(
            &(c[i]), &((*mat)[2][0]), &((*mat)[2][i + 1]), &((*mat)[3][0]), &((*mat)[3][i + 1]));
    }
    for (int i = 0; i < 2; i++) {
        ibz_mat_2x2_det_from_ibz(&(s[3 + i]),
                                 &((*mat)[0][1]),
                                 &((*mat)[0][2 + i]),
                                 &((*mat)[1][1]),
                                 &((*mat)[1][2 + i]));
        ibz_mat_2x2_det_from_ibz(&(c[3 + i]),
                                 &((*mat)[2][1]),
                                 &((*mat)[2][2 + i]),
                                 &((*mat)[3][1]),
                                 &((*mat)[3][2 + i]));
    }
    ibz_mat_2x2_det_from_ibz(
        &(s[5]), &((*mat)[0][2]), &((*mat)[0][3]), &((*mat)[1][2]), &((*mat)[1][3]));
    ibz_mat_2x2_det_from_ibz(
        &(c[5]), &((*mat)[2][2]), &((*mat)[2][3]), &((*mat)[3][2]), &((*mat)[3][3]));

    // compute det
    ibz_set(&work_det, 0);
    for (int i = 0; i < 6; i++) {
        ibz_mul(&prod, &(s[i]), &(c[5 - i]));
        if ((i != 1) && (i != 4)) {
            ibz_add(&work_det, &work_det, &prod);
        } else {
            ibz_sub(&work_det, &work_det, &prod);
        }
    }
    if (!ibz_is_zero(&work_det)) {
        // compute transposed adjugate
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 2; k++) {
                if ((k + j + 1) % 2 == 1) {
                    ibz_inv_dim4_make_coeff_pmp(&(work[j][k]),
                                                &((*mat)[1 - k][(j == 0)]),
                                                &(c[6 - j - (j == 0)]),
                                                &((*mat)[1 - k][2 - (j > 1)]),
                                                &(c[4 - j - (j == 1)]),
                                                &((*mat)[1 - k][3 - (j == 3)]),
                                                &(c[3 - j - (j == 1) - (j == 2)]));
                } else {
                    ibz_inv_dim4_make_coeff_mpm(&(work[j][k]),
                                                &((*mat)[1 - k][(j == 0)]),
                                                &(c[6 - j - (j == 0)]),
                                                &((*mat)[1 - k][2 - (j > 1)]),
                                                &(c[4 - j - (j == 1)]),
                                                &((*mat)[1 - k][3 - (j == 3)]),
                                                &(c[3 - j - (j == 1) - (j == 2)]));
                }
            }
            for (int k = 2; k < 4; k++) {
                if ((k + j + 1) % 2 == 1) {
                    ibz_inv_dim4_make_coeff_pmp(&(work[j][k]),
                                                &((*mat)[3 - (k == 3)][(j == 0)]),
                                                &(s[6 - j - (j == 0)]),
                                                &((*mat)[3 - (k == 3)][2 - (j > 1)]),
                                                &(s[4 - j - (j == 1)]),
                                                &((*mat)[3 - (k == 3)][3 - (j == 3)]),
                                                &(s[3 - j - (j == 1) - (j == 2)]));
                } else {
                    ibz_inv_dim4_make_coeff_mpm(&(work[j][k]),
                                                &((*mat)[3 - (k == 3)][(j == 0)]),
                                                &(s[6 - j - (j == 0)]),
                                                &((*mat)[3 - (k == 3)][2 - (j > 1)]),
                                                &(s[4 - j - (j == 1)]),
                                                &((*mat)[3 - (k == 3)][3 - (j == 3)]),
                                                &(s[3 - j - (j == 1) - (j == 2)]));
                }
            }
        }
        // put transposed adjugate in result
        if (inv != NULL)
            ibz_mat_4x4_copy(inv, &work);
    }
    // output det in any case
    if (det != NULL)
        ibz_copy(det, &work_det);
    for (int i = 0; i < 6; i++) {
        ibz_finalize(&s[i]);
        ibz_finalize(&c[i]);
    }
    ibz_mat_4x4_finalize(&work);
    ibz_finalize(&work_det);
    ibz_finalize(&prod);
    return (!ibz_is_zero(det));
}

// larger matrix modular kernel

// Algorithm used is the one at number 2.3.1 in Henri Cohen's "A Course in Computational Algebraic
// Number Theory" (Springer Verlag, in series "Graduate texts in Mathematics") from 1993 most
// notations also are from there, except their r becoming kernel_dimension here and prod being used
// instaed of d as temporary variable.
int
ibz_4x5_right_ker_mod_prime(ibz_vec_5_t *ker, const ibz_mat_4x5_t *mat, const ibz_t *p)
{
    int k, i, j, kernel_dim, columns, rows;
    int c[4] = { 0, 0, 0, 0 };
    int d[5];
    ibz_mat_4x5_t work_mat;
    ibz_t prod, var;
    ibz_init(&prod);
    ibz_init(&var);
    k = 0;
    columns = 5;
    rows = 4;
    j = 0;
    kernel_dim = 0;
    ibz_mat_4x5_init(&work_mat);
    for (int s = 0; s < rows; s++) {
        for (int t = 0; t < columns; t++) {
            ibz_mod(&(work_mat[s][t]), &((*mat)[s][t]), p);
        }
    }
    while (k < columns) {
        j = 0;
        while ((j < rows) && (ibz_is_zero(&(work_mat[j][k])) || (c[j] != 0))) {
            j = j + 1;
        }
        // found none
        if (j == rows) {
            kernel_dim = kernel_dim + 1;
            d[k] = 0;
            k = k + 1;
        } else { // found such a j
            ibz_invmod(&prod, &(work_mat[j][k]), p);
            ibz_neg(&prod, &prod);
            ibz_mod(&prod, &prod, p);
            ibz_set(&(work_mat[j][k]), -1);
            ibz_mod(&(work_mat[j][k]), &(work_mat[j][k]), p);
            for (int s = k + 1; s < columns; s++) {
                ibz_mul(&(work_mat[j][s]), &(work_mat[j][s]), &prod);
                ibz_mod(&(work_mat[j][s]), &(work_mat[j][s]), p);
            }
            for (i = 0; i < rows; i++) {
                if (i != j) {
                    ibz_copy(&var, &(work_mat[i][k]));
                    ibz_set(&(work_mat[i][k]), 0);
                    for (int s = k + 1; s < columns; s++) {
                        ibz_mul(&prod, &(work_mat[j][s]), &var);
                        ibz_add(&(work_mat[i][s]), &(work_mat[i][s]), &prod);
                        ibz_mod(&(work_mat[i][s]), &(work_mat[i][s]), p);
                    }
                }
            }
            c[j] = k + 1;
            d[k] = j + 1;
            k = k + 1;
        }
    }
    // create output
    if (kernel_dim == 1) {
        for (k = 0; k < columns; k++) {
            // should be true exactly for 1 k, since kernel_dim = 1
            if (d[k] == 0) {
                for (int s = 0; s < columns; s++) {
                    ibz_set(&((*ker)[s]), 0);
                    if (s == k) {
                        ibz_set(&((*ker)[s]), 1);
                    }
                    if (d[s] > 0) {
                        ibz_mod(&((*ker)[s]), &(work_mat[d[s] - 1][k]), p);
                    }
                }
            }
        }
    }
    ibz_finalize(&prod);
    ibz_finalize(&var);
    ibz_mat_4x5_finalize(&work_mat);
    return (kernel_dim == 1);
}

// same algo as ibz_4x5_right_ker_mod_prime, same notations, just the column number changes
int
ibz_4x4_right_ker_mod_prime(ibz_vec_4_t *ker, const ibz_mat_4x4_t *mat, const ibz_t *p)
{
    int k, i, j, kernel_dim, columns, rows;
    int c[4] = { 0, 0, 0, 0 };
    int d[4];
    ibz_mat_4x4_t work_mat;
    ibz_t prod, var;
    ibz_init(&prod);
    ibz_init(&var);
    k = 0;
    columns = 4;
    rows = 4;
    j = 0;
    kernel_dim = 0;
    ibz_mat_4x4_init(&work_mat);
    for (int s = 0; s < rows; s++) {
        for (int t = 0; t < columns; t++) {
            ibz_mod(&(work_mat[s][t]), &((*mat)[s][t]), p);
        }
    }
    while (k < columns) {
        j = 0;
        while ((j < rows) && (ibz_is_zero(&(work_mat[j][k])) || (c[j] != 0))) {
            j = j + 1;
        }
        // found none
        if (j == rows) {
            kernel_dim = kernel_dim + 1;
            d[k] = 0;
            k = k + 1;
        } else { // found such a j
            ibz_invmod(&prod, &(work_mat[j][k]), p);
            ibz_neg(&prod, &prod);
            ibz_mod(&prod, &prod, p);
            ibz_set(&(work_mat[j][k]), -1);
            ibz_mod(&(work_mat[j][k]), &(work_mat[j][k]), p);
            for (int s = k + 1; s < columns; s++) {
                ibz_mul(&(work_mat[j][s]), &(work_mat[j][s]), &prod);
                ibz_mod(&(work_mat[j][s]), &(work_mat[j][s]), p);
            }
            for (i = 0; i < rows; i++) {
                if (i != j) {
                    ibz_copy(&var, &(work_mat[i][k]));
                    ibz_set(&(work_mat[i][k]), 0);
                    for (int s = k + 1; s < columns; s++) {
                        ibz_mul(&prod, &(work_mat[j][s]), &var);
                        ibz_add(&(work_mat[i][s]), &(work_mat[i][s]), &prod);
                        ibz_mod(&(work_mat[i][s]), &(work_mat[i][s]), p);
                    }
                }
            }
            c[j] = k + 1;
            d[k] = j + 1;
            k = k + 1;
        }
    }
    // create output
    if (kernel_dim == 1) {
        for (k = 0; k < columns; k++) {
            // should be true exactly for 1 k, since kernel_dim = 1
            if (d[k] == 0) {
                for (int s = 0; s < columns; s++) {
                    ibz_set(&((*ker)[s]), 0);
                    if (s == k) {
                        ibz_set(&((*ker)[s]), 1);
                    }
                    if (d[s] > 0) {
                        ibz_mod(&((*ker)[s]), &(work_mat[d[s] - 1][k]), p);
                    }
                }
            }
        }
    }
    ibz_finalize(&prod);
    ibz_finalize(&var);
    ibz_mat_4x4_finalize(&work_mat);
    return (kernel_dim == 1);
}

int
ibz_4x4_right_ker_mod_power_of_2(ibz_vec_4_t *ker, const ibz_mat_4x4_t *mat, unsigned short exp)
{
    ibz_mat_4x4_t full_ker;
    ibz_mat_4x5_t howell;
    ibz_t pow2;
    ibz_mat_4x4_init(&full_ker);
    ibz_mat_4x5_init(&howell);
    ibz_init(&pow2);

    // 2^exp
    ibz_set(&pow2, 1);
    ibz_mul_2exp(&pow2, &pow2, exp);

    ibz_mat_right_ker_mod(4, 4, full_ker, *mat, &pow2);
    int zeros = ibz_mat_howell(4, 4, howell, NULL, full_ker, &pow2);

    int dim = 0;
    for (int j = zeros; j < 5; j++) {
        int primitive = 0;
        for (int i = 0; i < 4; i++)
            primitive |= !ibz_is_even(&howell[i][j]);
        if (primitive) {
            for (int i = 0; i < 4; i++)
                ibz_copy(&(*ker)[i], &howell[i][j]);
            dim++;
        }
    }

    ibz_mat_4x4_finalize(&full_ker);
    ibz_mat_4x5_finalize(&howell);
    ibz_finalize(&pow2);

    return dim == 1;
}

// matrix evaluation

void
ibz_mat_4x4_eval(quat_alg_coord_t *res, const ibz_mat_4x4_t *mat, const quat_alg_coord_t *vec)
{
    quat_alg_coord_t sum;
    ibz_t prod;
    ibz_init(&prod);
    quat_alg_coord_init(&sum);
    for (int i = 0; i < 4; i++) {
        ibz_set(&(sum[i]), 0);
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ibz_mul(&prod, &(*mat)[i][j], &(*vec)[j]);
            ibz_add(&(sum[i]), &(sum[i]), &prod);
        }
    }
    for (int i = 0; i < 4; i++) {
        ibz_copy(&(*res)[i], &(sum[i]));
    }
    ibz_finalize(&prod);
    quat_alg_coord_finalize(&sum);
}

// quadratic forms

void
quat_qf_eval(ibz_t *res, const ibz_mat_4x4_t *qf, const quat_alg_coord_t *coord)
{
    quat_alg_coord_t sum;
    ibz_t prod;
    ibz_init(&prod);
    quat_alg_coord_init(&sum);
    ibz_mat_4x4_eval(&sum, qf, coord);
    for (int i = 0; i < 4; i++) {
        ibz_mul(&prod, &(sum[i]), &(*coord)[i]);
        if (i > 0) {
            ibz_add(&(sum[0]), &(sum[0]), &prod);
        } else {
            ibz_copy(&sum[0], &prod);
        }
    }
    ibz_copy(res, &sum[0]);
    ibz_finalize(&prod);
    quat_alg_coord_finalize(&sum);
}

// Defined in headerfile
// static void ibz_content(ibz_t *content, const quat_alg_coord_t *v) {
//   ibz_gcd(content, v[0], v[1]);
//   ibz_gcd(content, v[2], content);
//   ibz_gcd(content, v[3], content);
// }
