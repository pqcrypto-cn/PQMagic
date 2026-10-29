#include "internal.h"

/***************** Howell form **********************/

/** @brief Compute u s.t. gcd(u, mod) = 1 and ux = gcd(x, mod)
 */
static int
unit(ibz_t *unit, ibz_t *gcd, const ibz_t *x, const ibz_t *mod)
{
    if (ibz_is_zero(x))
        return 0;
    ibz_t stab, nmod, nmod2, thrash, tmp;
    ibz_init(&stab);
    ibz_init(&nmod);
    ibz_init(&nmod2);
    ibz_init(&thrash);
    ibz_init(&tmp);
    ibz_xgcd(gcd, unit, &thrash, x, mod);
    ibz_div(&nmod, &thrash, mod, gcd);
    // Stabilizer(unit, nmod)
    ibz_gcd(&stab, unit, &nmod);
    ibz_div(&nmod2, &thrash, mod, &stab);
    ibz_div(&stab, &thrash, unit, &stab);
    // Split(nmod2, stab)
    for (int i = ibz_bitsize(&nmod2); i > 0; i >>= 1) {
        ibz_mul(&stab, &stab, &stab);
        ibz_mod(&stab, &stab, &nmod2);
    }
    ibz_gcd(&stab, &stab, &nmod2);
    ibz_div(&stab, &thrash, &nmod2, &stab);
#ifndef NDEBUG
    ibz_mul(&thrash, &stab, &nmod);
    ibz_add(&thrash, unit, &thrash);
    ibz_gcd(&thrash, &thrash, mod);
    ibz_gcd(&tmp, unit, &nmod);
    assert(ibz_cmp(&thrash, &tmp) == 0);
#endif
    // Finish off
    ibz_mul(&stab, &stab, &nmod);
    ibz_add(unit, unit, &stab);
    ibz_mod(unit, unit, mod);
#ifndef NDEBUG
    ibz_gcd(&stab, unit, mod);
    assert(ibz_is_one(&stab));
    ibz_mul(&stab, unit, x);
    ibz_mod(&stab, &stab, mod);
    assert(ibz_cmp(&stab, gcd) == 0);
#endif
    ibz_finalize(&stab);
    ibz_finalize(&nmod);
    ibz_finalize(&nmod2);
    ibz_finalize(&thrash);
    ibz_finalize(&tmp);
    return 1;
}

/** @brief Linear combination of two columns
 *
 * (mat[][j] | mat[][k]) <- (mat[][j] | mat[][k]) * U    (mod)
 *
 * only update columns between start (included) and end (excluded)
 */
static void
gen_elem(int rows,
         int cols,
         ibz_t mat[rows][cols],
         int j,
         int k,
         int start,
         int end,
         const ibz_mat_2x2_t *U,
         const ibz_t *mod)
{
    ibz_t tmp1, tmp2;
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    for (int i = start; i < end; i++) {
        ibz_mul(&tmp1, &mat[i][j], &(*U)[0][0]);
        ibz_mul(&tmp2, &mat[i][k], &(*U)[1][0]);
        ibz_add(&tmp1, &tmp1, &tmp2);

        ibz_mul(&tmp2, &mat[i][j], &(*U)[0][1]);
        ibz_mul(&mat[i][k], &mat[i][k], &(*U)[1][1]);
        ibz_add(&mat[i][k], &tmp2, &mat[i][k]);

        ibz_mod(&mat[i][j], &tmp1, mod);
        ibz_mod(&mat[i][k], &mat[i][k], mod);
    }
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
}

/** @brief Swap columns j and k of mat
 */
static inline void
swap_col(int rows, int cols, ibz_t mat[rows][cols], int j, int k)
{
    ibz_t tmp;
    ibz_init(&tmp);
    for (int i = 0; i < rows; i++) {
        ibz_copy(&tmp, &mat[i][j]);
        ibz_copy(&mat[i][j], &mat[i][k]);
        ibz_copy(&mat[i][k], &tmp);
    }
    ibz_finalize(&tmp);
}

/** @brief Check if column is all zeros
 */
static inline int
is_col_zero(int rows, int cols, ibz_t mat[rows][cols], int j)
{
    int is_zero = 1;
    for (int i = 0; i < rows; i++)
        is_zero &= ibz_is_zero(&mat[i][j]);
    return is_zero;
}

/** Check that mat * trans = howell
 */
static int
howell_check_matrices(int rows,
                      int cols,
                      const ibz_t howell[rows][rows + 1],
                      const ibz_t trans[rows + 1][rows + 1],
                      const ibz_t mat[rows][cols],
                      ibz_t *mod)
{
    const int extra = rows + 1 - cols;
    ibz_t test[rows][rows + 1], res[rows][rows + 1];
    ibz_mat_init(rows, rows + 1, test);
    ibz_mat_init(rows, rows + 1, res);

    // copy mat to the right of test
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < cols; j++)
            ibz_mod(&test[i][j + extra], &mat[i][j], mod);

    ibz_mat_mulmod(rows, rows + 1, rows + 1, res, test, trans, mod);

    int ok = 1;
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < rows + 1; j++)
            ok &= ibz_cmp(&howell[i][j], &res[i][j]) == 0;

    ibz_mat_finalize(rows, rows + 1, res);
    ibz_mat_finalize(rows, rows + 1, test);

    return ok;
}

void
ibz_mat_mulmod(int from,
               int through,
               int to,
               ibz_t res[from][to],
               const ibz_t A[from][through],
               const ibz_t B[through][to],
               const ibz_t *mod)
{
    ibz_t tmp;
    ibz_init(&tmp);
    for (int i = 0; i < from; i++) {
        for (int j = 0; j < to; j++) {
            ibz_set(&res[i][j], 0);
            for (int k = 0; k < through; k++) {
                ibz_mul(&tmp, &A[i][k], &B[k][j]);
                ibz_add(&res[i][j], &res[i][j], &tmp);
                ibz_mod(&res[i][j], &res[i][j], mod);
            }
        }
    }
    ibz_finalize(&tmp);
}

int
ibz_mat_howell(int rows,
               int cols,
               ibz_t howell[rows][rows + 1],
               ibz_t trans[rows + 1][rows + 1],
               const ibz_t mat[rows][cols],
               ibz_t *mod)
{
    assert(cols <= rows);
    const int extra = rows + 1 - cols;

    ibz_mat_2x2_t U;
    ibz_t gcd, u, q;
    ibz_mat_2x2_init(&U);
    ibz_init(&gcd);
    ibz_init(&u);
    ibz_init(&q);

    // copy mat to the right of howell
    for (int i = 0; i < rows; i++) {
        for (int j = cols; j < rows + 1; j++)
            ibz_set(&howell[i][j - cols], 0);
        for (int j = 0; j < cols; j++)
            ibz_mod(&howell[i][j + extra], &mat[i][j], mod);
    }
    // initialize trans to identity
    if (trans) {
        for (int i = 0; i < rows + 1; i++) {
            for (int j = 0; j < rows + 1; j++)
                if (j != i)
                    ibz_set(&trans[i][j], 0);
            ibz_set(&trans[i][i], 1);
        }
        assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
    }

    // Put in upper triangular form
    for (int i = rows - 1; i >= extra - 1; i--) {
        for (int j = extra; j <= i; j++) {
            if (ibz_is_zero(&howell[i][j]))
                continue;
            ibz_xgcd_ann(
                &gcd, &U[0][0], &U[1][0], &U[0][1], &U[1][1], &howell[i][j], &howell[i][i + 1]);
            gen_elem(rows, rows + 1, howell, j, i + 1, 0, i, &U, mod);
            ibz_set(&howell[i][j], 0);
            ibz_copy(&howell[i][i + 1], &gcd);
            //
            if (trans) {
                gen_elem(rows + 1, rows + 1, trans, j, i + 1, 0, rows + 1, &U, mod);
                assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
            }
        }
    }

    // Put in reduced Howell form
    for (int i = rows - 1; i >= 0; i--) {
        /* normalize diagonal coefficient */
        if (unit(&u, &gcd, &howell[i][i + 1], mod)) {
            for (int k = 0; k < i; k++) {
                ibz_mul(&howell[k][i + 1], &howell[k][i + 1], &u);
                ibz_mod(&howell[k][i + 1], &howell[k][i + 1], mod);
            }
            ibz_copy(&howell[i][i + 1], &gcd);
            //
            if (trans) {
                for (int k = 0; k < rows + 1; k++) {
                    ibz_mul(&trans[k][i + 1], &trans[k][i + 1], &u);
                    ibz_mod(&trans[k][i + 1], &trans[k][i + 1], mod);
                }
                assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
            }
        }

        /* reduce right of the diagonal */
        ibz_t *pivot = &howell[i][i + 1];
        if (!ibz_is_zero(pivot)) {
            for (int j = i + 2; j < rows + 1; j++) {
                assert(ibz_cmp(pivot, &ibz_const_zero) > 0);
                ibz_div(&q, &howell[i][j], &howell[i][j], pivot);
                // howell[][j] -= q howell[][i+1]
                for (int k = 0; k < i; k++) {
                    ibz_mul(&u, &q, &howell[k][i + 1]);
                    ibz_sub(&howell[k][j], &howell[k][j], &u);
                    ibz_mod(&howell[k][j], &howell[k][j], mod);
                }
                // trans[][j] -= q trans[][i+1]
                if (trans) {
                    for (int k = 0; k < rows + 1; k++) {
                        ibz_mul(&u, &q, &trans[k][i + 1]);
                        ibz_sub(&trans[k][j], &trans[k][j], &u);
                        ibz_mod(&trans[k][j], &trans[k][j], mod);
                    }
                    assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
                }
            }
        }

        /* ensure Howell property */
        if (i > 0) {
            ibz_gcd(&gcd, pivot, mod);
            if (!ibz_is_one(&gcd)) {
                // Ann(pivot)
                ibz_div(&u, &gcd, mod, &gcd);
                for (int k = 0; k < rows; k++) {
                    if (k < i) {
                        ibz_mul(&howell[k][0], &howell[k][i + 1], &u);
                        ibz_mod(&howell[k][0], &howell[k][0], mod);
                    } else {
                        ibz_set(&howell[k][0], 0);
                    }
                }
                // trans[][0] += u trans[][i+1]
                if (trans) {
                    for (int k = 0; k < rows + 1; k++) {
                        ibz_mul(&q, &u, &trans[k][i + 1]);
                        ibz_add(&trans[k][0], &trans[k][0], &q);
                        ibz_mod(&trans[k][0], &trans[k][0], mod);
                    }
                    assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
                }

                for (int i2 = i - 1; i2 >= 0; i2--) {
                    if (ibz_is_zero(&howell[i2][0]))
                        continue;
                    if (ibz_is_zero(&howell[i2][i2 + 1])) {
                        swap_col(rows, rows + 1, howell, 0, i2 + 1);
                        if (trans) {
                            swap_col(rows + 1, rows + 1, trans, 0, i2 + 1);
                            assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
                        }
                        continue;
                    }
                    ibz_xgcd_ann(&gcd,
                                 &U[0][0],
                                 &U[1][0],
                                 &U[0][1],
                                 &U[1][1],
                                 &howell[i2][0],
                                 &howell[i2][i2 + 1]);
                    gen_elem(rows, rows + 1, howell, 0, i2 + 1, 0, i2, &U, mod);
                    ibz_set(&howell[i2][0], 0);
                    ibz_copy(&howell[i2][i2 + 1], &gcd);
                    //
                    if (trans) {
                        gen_elem(rows, rows + 1, trans, 0, i2 + 1, 0, rows + 1, &U, mod);
                        assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
                    }
                }
            }
        }
    }

    /* put zero columns first */
    int read, write;
    for (read = rows, write = rows; read >= 1; read--) {
        if (!is_col_zero(rows, rows + 1, howell, read)) {
            if (read < write) {
                swap_col(rows, rows + 1, howell, read, write);
                if (trans) {
                    swap_col(rows + 1, rows + 1, trans, read, write);
                    assert(howell_check_matrices(rows, cols, howell, trans, mat, mod));
                }
            }
            write--;
        }
    }

    // Finalize
    ibz_mat_2x2_finalize(&U);
    ibz_finalize(&gcd);
    ibz_finalize(&u);
    ibz_finalize(&q);

    return write + 1;
}

void
ibz_mat_right_ker_mod(int rows,
                      int cols,
                      ibz_t ker[cols][cols],
                      const ibz_t mat[rows][cols],
                      ibz_t *mod)
{
    assert(cols <= rows);
    const int extra = rows + 1 - cols;

    ibz_t tmp;
    ibz_mat_2x2_t U;
    ibz_t howell[rows][rows + 1], trans[rows + 1][rows + 1], preker[rows + 1][rows + 1],
        near_ker[cols][rows + 1];

    ibz_init(&tmp);
    ibz_mat_2x2_init(&U);
    ibz_mat_init(rows, rows + 1, howell);
    ibz_mat_init(rows + 1, rows + 1, trans);
    ibz_mat_init(rows + 1, rows + 1, preker);
    ibz_mat_init(cols, rows + 1, near_ker);

    // Compute Howell form of mat
    int zeros = ibz_mat_howell(rows, cols, howell, trans, mat, mod);

    // Compute right kernel of Howell form
    for (int j = rows, i = rows - 1; j >= 0; j--) {
        while (i >= 0 && ibz_is_zero(&howell[i][j]))
            i--;
        if (i < 0) {
            ibz_set(&preker[j][j], 1);
            continue;
        }
        ibz_t *pivot = &howell[i][j];

        // Ann(pivot)
        ibz_gcd(&tmp, pivot, mod);
        if (!ibz_is_one(&tmp))
            ibz_div(&preker[j][j], &tmp, mod, &tmp);

        for (int j2 = j + 1; j2 <= rows; j2++) {
            // howell[i][j+1..rows] * preker[j+1..rows][j2]
            for (int k = j + 1; k <= rows; k++) {
                ibz_mul(&tmp, &howell[i][k], &preker[k][j2]);
                ibz_add(&preker[j][j2], &preker[j][j2], &tmp);
            }
            ibz_mod(&preker[j][j2], &preker[j][j2], mod);
            //
            ibz_div(&preker[j][j2], &tmp, &preker[j][j2], pivot);
            assert(ibz_is_zero(&tmp));
            if (!ibz_is_zero(&preker[j][j2]))
                ibz_sub(&preker[j][j2], mod, &preker[j][j2]);
        }
    }

#ifndef NDEBUG
    // Check that preker is indeed a kernel of howell
    ibz_t acc;
    ibz_init(&acc);
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < rows + 1; j++) {
            ibz_set(&acc, 0);
            for (int k = 0; k < rows + 1; k++) {
                ibz_mul(&tmp, &howell[i][k], &preker[k][j]);
                ibz_add(&acc, &acc, &tmp);
            }
            ibz_mod(&acc, &acc, mod);
            assert(ibz_is_zero(&acc));
        }
    }
    ibz_finalize(&acc);
#endif

    // Apply (bottom part of) transition matrix to computed kernel
    for (int i = 0; i < cols; i++) {
        for (int j = 0; j < rows + 1; j++) {
            for (int k = 0; k < rows + 1; k++) {
                ibz_mul(&tmp, &trans[i + extra][k], &preker[k][j]);
                ibz_add(&near_ker[i][j], &near_ker[i][j], &tmp);
            }
            ibz_mod(&near_ker[i][j], &near_ker[i][j], mod);
        }
    }

    // Move zero columns to the start
    int read, write;
    for (read = rows, write = rows; read >= 0; read--) {
        if (!is_col_zero(cols, rows + 1, near_ker, read)) {
            if (read < write) {
                swap_col(cols, rows + 1, near_ker, read, write);
            }
            write--;
        }
    }

    // Put in upper triangular form
    const int diag_shift = rows - cols + 1; // i-th diagonal is at (i+diag_shift) column
    for (int i = cols - 1; i >= 0; i--) {
        for (int j = write + 1; j < i + diag_shift; j++) {
            if (ibz_is_zero(&near_ker[i][j]))
                continue;
            ibz_xgcd_ann(&tmp,
                         &U[0][0],
                         &U[1][0],
                         &U[0][1],
                         &U[1][1],
                         &near_ker[i][j],
                         &near_ker[i][i + diag_shift]);
            gen_elem(cols, rows + 1, near_ker, j, i + diag_shift, 0, i + 1, &U, mod);
            ibz_set(&howell[i][j], 0);
            ibz_copy(&howell[i][i + diag_shift], &tmp);
        }
    }

#ifndef NDEBUG
    // Check that ker is indeed a kernel of mat
    ibz_t check[rows][rows + 1];
    ibz_mat_init(rows, rows + 1, check);
    ibz_mat_mulmod(rows, cols, rows + 1, check, mat, near_ker, mod);
    for (int i = 0; i < rows; i++)
        for (int j = 0; j < rows + 1; j++)
            assert(ibz_is_zero(&check[i][j]));
    ibz_mat_finalize(rows, rows + 1, check);
#endif

    // Copy result
    for (int i = 0; i < cols; i++)
        for (int j = 0; j < cols; j++)
            ibz_copy(&ker[i][j], &near_ker[i][j + rows - cols + 1]);
    // Finalize
    ibz_finalize(&tmp);
    ibz_mat_2x2_finalize(&U);
    ibz_mat_finalize(rows, rows + 1, howell);
    ibz_mat_finalize(rows + 1, rows + 1, trans);
    ibz_mat_finalize(rows + 1, rows + 1, preker);
    ibz_mat_finalize(cols, rows + 1, near_ker);
}
