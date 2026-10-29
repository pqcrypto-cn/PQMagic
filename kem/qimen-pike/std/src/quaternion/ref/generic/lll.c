#include <quaternion.h>
#include <rng.h>
#include "internal.h"

// RED(k,l) sub-algorithm
static void
RED(ibz_mat_4x4_t basis, mpf_t u[4][4], mpz_t H[4][4], int k, int l)
{
    mpf_t tmp, tmp2;
    mpz_t q, tmpz;
    mpf_init_set_d(tmp, 0.5);
    mpf_init(tmp2);
    mpz_init(q);
    mpz_init(tmpz);

    // if |u_{k,l}| <= 0.5, terminate
    mpf_abs(tmp2, u[k][l]);
    if (mpf_cmp(tmp2, tmp) <= 0)
        goto end;

    // q <- floor(0.5 + u_{k,l})
    mpf_add(tmp, tmp, u[k][l]);
    mpf_floor(tmp, tmp);
    mpz_set_f(q, tmp);

    // b_k = b_k - q*b_l
    for (int i = 0; i < 4; ++i) {
        mpz_mul(tmpz, q, basis[l][i]);
        mpz_sub(basis[k][i], basis[k][i], tmpz);
    }

    // H_k = H_k - q*H_l
    for (int i = 0; i < 4; ++i) {
        mpz_mul(tmpz, q, H[l][i]);
        mpz_sub(H[k][i], H[k][i], tmpz);
    }

    // u_{k,j} = u_{k,l}-q
    mpf_set_z(tmp2, q);
    mpf_sub(u[k][l], u[k][l], tmp2);

    // forall_i \in 1..l-1: u_{k,i} = u_{k,i} - q*u_{l,i}
    for (int i = 0; i <= l - 1; ++i) {
        mpf_mul(tmp, tmp2, u[l][i]);
        mpf_sub(u[k][i], u[k][i], tmp);
    }

end:
    mpf_clear(tmp);
    mpf_clear(tmp2);
    mpz_clear(q);
    mpz_clear(tmpz);
}

// SWAP(k) sub-algorithm
static void
SWAP(ibz_mat_4x4_t basis,
     mpf_t u[4][4],
     mpz_t H[4][4],
     mpf_t B[4],
     mpf_t bStar[4][4],
     int k,
     int kmax)
{
    mpf_t tmp, tmp2, tmp3, u_tmp, B_tmp, b[4];
    mpf_init(tmp);
    mpf_init(tmp2);
    mpf_init(tmp3);
    mpf_init(u_tmp);
    mpf_init(B_tmp);

    for (int i = 0; i < 4; ++i) {
        mpf_init(b[i]);
    }

    // swap b_k and b_{k-1}
    for (int i = 0; i < 4; ++i) {
        mpz_swap(basis[k][i], basis[k - 1][i]);
    }

    // swap H_k and H_{k-1}
    for (int i = 0; i < 4; ++i) {
        mpz_swap(H[k][i], H[k - 1][i]);
    }

    if (k > 1) {
        // swap u_{k,j} and u_{k-1,j}
        for (int j = 0; j <= k - 2; ++j) {
            mpf_swap(u[k][j], u[k - 1][j]);
        }
    }

    // u = u_{k,k-1}
    mpf_set(u_tmp, u[k][k - 1]);

    // B = B_k + u^2*B_{k-1}
    mpf_mul(B_tmp, u_tmp, u_tmp);
    mpf_mul(B_tmp, B_tmp, B[k - 1]);
    mpf_add(B_tmp, B[k], B_tmp);

    // u_{k,k-1} = u*B_{k-1} / B
    mpf_mul(tmp, u_tmp, B[k - 1]);
    mpf_div(u[k][k - 1], tmp, B_tmp);

    // b = bSTAR_{k-1}
    for (int i = 0; i < 4; ++i) {
        mpf_set(b[i], bStar[k - 1][i]);
    }
    // bSTAR_{k-1}=bSTAR_k+u*b
    for (int i = 0; i < 4; ++i) {
        mpf_mul(tmp, u_tmp, b[i]);
        mpf_add(bStar[k - 1][i], bStar[k][i], tmp);
    }
    // bSTAR_k = -u_{k,k-1}*bSTAR_k+(B_k/B)*b
    mpf_div(tmp2, B[k], B_tmp); // B_k/B
    mpf_neg(tmp, u[k][k - 1]);
    for (int i = 0; i < 4; ++i) {
        mpf_mul(bStar[k][i], tmp, bStar[k][i]);
        mpf_mul(tmp3, tmp2, b[i]);
        mpf_add(bStar[k][i], bStar[k][i], tmp3);
    }

    // B_k = B_{k-1}*B_k/B
    mpf_mul(B[k], B[k - 1], B[k]);
    mpf_div(B[k], B[k], B_tmp);

    // B_{k-1} = B
    mpf_set(B[k - 1], B_tmp);

    for (int i = k + 1; i <= kmax; ++i) {
        // t = u_{i,k}
        mpf_set(tmp, u[i][k]);

        // u_{i,k} = u_{i,k-1} - u*t
        mpf_mul(u[i][k], u_tmp, tmp);
        mpf_sub(u[i][k], u[i][k - 1], u[i][k]);

        // u_{i,k-1} = t + u_{k,k-1}*u_{i,k}
        mpf_mul(tmp2, u[k][k - 1], u[i][k]);
        mpf_add(u[i][k - 1], tmp, tmp2);
    }

    mpf_clear(tmp);
    mpf_clear(tmp2);
    mpf_clear(tmp3);
    mpf_clear(u_tmp);
    mpf_clear(B_tmp);
    for (int i = 0; i < 4; ++i) {
        mpf_clear(b[i]);
    }
}

// m1[0]*m2[0] + m1[1]*m2[1] + q*(m1[2]*m2[2] + m1[3]*m2[3])
static void
dotproduct_row(mpz_t *mul,
               const ibz_mat_4x4_t m1,
               const ibz_mat_4x4_t m2,
               const ibz_t *q,
               int m1j,
               int m2j)
{
    mpz_set_ui(*mul, 0);
    mpz_t tmp1, tmp2;
    mpz_init(tmp1);
    mpz_init(tmp2);
    for (int i = 0; i < 2; ++i) {
        mpz_mul(tmp1, m1[m1j][i], m2[m2j][i]);
        mpz_add(*mul, *mul, tmp1);
    }
    for (int i = 2; i < 4; ++i) {
        mpz_mul(tmp1, m1[m1j][i], m2[m2j][i]);
        mpz_add(tmp2, tmp2, tmp1);
    }
    mpz_mul(tmp2, tmp2, *q);
    mpz_add(*mul, *mul, tmp2);

    mpz_clear(tmp1);
    mpz_clear(tmp2);
}

static void
dotproduct_zr_row(mpf_t *mul,
                  const ibz_mat_4x4_t m1,
                  const mpf_t m2[4][4],
                  const ibz_t *q,
                  int m1j,
                  int m2j)
{
    mpf_set_d(*mul, 0);
    mpf_t tmp1, tmp2;
    mpf_init(tmp1);
    mpf_init(tmp2);
    for (int i = 0; i < 2; ++i) {
        mpf_set_z(tmp1, m1[m1j][i]);
        mpf_mul(tmp1, tmp1, m2[m2j][i]);
        mpf_add(*mul, *mul, tmp1);
    }
    for (int i = 2; i < 4; ++i) {
        mpf_set_z(tmp1, m1[m1j][i]);
        mpf_mul(tmp1, tmp1, m2[m2j][i]);
        mpf_add(tmp2, tmp2, tmp1);
    }
    mpf_set_z(tmp1, *q);
    mpf_mul(tmp2, tmp2, tmp1);
    mpf_add(*mul, *mul, tmp2);

    mpf_clear(tmp1);
    mpf_clear(tmp2);
}

static void
dotproduct_rr_row(mpf_t *mul,
                  const mpf_t m1[4][4],
                  const mpf_t m2[4][4],
                  const ibz_t *q,
                  int m1j,
                  int m2j)
{
    mpf_set_ui(*mul, 0);
    mpf_t tmp1, tmp2;
    mpf_init(tmp1);
    mpf_init(tmp2);
    for (int i = 0; i < 2; ++i) {
        mpf_mul(tmp1, m1[m1j][i], m2[m2j][i]);
        mpf_add(*mul, *mul, tmp1);
    }
    for (int i = 2; i < 4; ++i) {
        mpf_mul(tmp1, m1[m1j][i], m2[m2j][i]);
        mpf_add(tmp2, tmp2, tmp1);
    }
    mpf_set_z(tmp1, *q);
    mpf_mul(tmp2, tmp2, tmp1);
    mpf_add(*mul, *mul, tmp2);

    mpf_clear(tmp1);
    mpf_clear(tmp2);
}

static void
mul_row(mpf_t mul[4][4], const mpf_t *a, const mpf_t m[4][4], int j)
{
    for (int i = 0; i < 4; ++i) {
        mpf_mul(mul[j][i], *a, m[j][i]);
    }
}

static void
add_row(ibz_mat_4x4_t add, const ibz_mat_4x4_t a, const ibz_mat_4x4_t b, int j, int aj, int bj)
{
    for (int i = 0; i < 4; ++i) {
        mpz_add(add[j][i], a[aj][i], b[bj][i]);
    }
}

static void
sub_row(mpf_t add[4][4], const mpf_t a[4][4], const mpf_t b[4][4], int j, int aj, int bj)
{
    for (int i = 0; i < 4; ++i) {
        mpf_sub(add[j][i], a[aj][i], b[bj][i]);
    }
}

/// @brief LLL reduction on 4-dimensional lattice
/// Implements Algorithm 2.6.3 from Henri Cohen's "A Course in Computational Algebraic Number
/// Theory"
/// @param red
/// @param lattice
/// @return
int
quat_lattice_lll(ibz_mat_4x4_t *red, const quat_lattice_t *lattice, const ibz_t *q)
{
    int ret = 0;
    ibz_mat_4x4_t basis;
    mpf_t bStar[4][4];
    mpf_t bStar_tmp[4][4];
    mpf_t tmp;
    mpz_t tmp_z;
    mpf_t cnst;
    mpf_t u[4][4];
    mpz_t H[4][4]; // -> I_4
    mpf_t B[4];

    // Upper bound on log(determinant)
    int logdet = 0;
    for (int i = 0; i < 4; i++) {
      int max = 0;
      for (int j = 0; j < 4; j++) {
	int s = ibz_bitsize(&lattice->basis[i][j]);
	max = s > max ? s : max;
      }
      logdet += max;
    }
    // Set fp precision
    mpf_set_default_prec(2*logdet);
    
    mpf_init(tmp);
    mpz_init(tmp_z);
    mpf_init(cnst);
    for (int i = 0; i < 4; ++i)
        mpf_init(B[i]);

    ibz_mat_4x4_init(&basis);
    ibz_mat_4x4_transpose(&basis, &lattice->basis);

    // Step 1: Initialize: ...
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            mpf_init(u[i][j]);
            mpf_init(bStar[i][j]);
            mpf_init(bStar_tmp[i][j]);
            // bSTAR_1 = b_1 (we copy all)
            if (i == j)
                mpz_init_set_ui(H[i][j], 1);
            else
                mpz_init(H[i][j]);
        }
    }
    int k = 1, kmax = 0;
    // bStar_1 = b_1
    for (int i = 0; i < 4; ++i)
        mpf_set_z(bStar[0][i], basis[0][i]);
    // B_1 = b_1 * b_1
    dotproduct_row(&tmp_z, basis, basis, q, 0, 0);
    mpf_set_z(B[0], tmp_z);

    while (k < 4) {
        // Step 2: Incremental Gram-Schmidt
        // if (k <= kmax) -> we can omit..
        if (k > kmax) {
            kmax = k;
            for (int i = 0; i < 4; ++i) {
                mpf_set_z(bStar[k][i], basis[k][i]);
            }
            for (int j = 0; j <= k - 1; ++j) {
                // bStar_k = b_k -> already done initially -> todo: check if that's ok
                // nop
                // u_{k,j} = b_k*bSTAR_j/B_j
                dotproduct_zr_row(&tmp, basis, bStar, q, k, j);
                mpf_div(u[k][j], tmp, B[j]);
                // bStar_k = bStar_k - u_{k,j}*bStar_j
                mul_row(bStar_tmp, &u[k][j], bStar, j);
                sub_row(bStar, bStar, bStar_tmp, k, k, j);
            }
            // B_k = bStar_k*bStar_k
            dotproduct_rr_row(&B[k], bStar, bStar, q, k, k);
            if (mpf_get_d(B[k]) == 0.0) {
                // b_i did not form a basis, terminate with error
                ret = -1;
                goto err;
            }
        }

        while (1) {
            // Step 3: Test LLL condition
            RED(basis, u, H, k, k - 1);
            // If B_k < (0.75 - u_{k,k-1}^2)*B_{k-1}
            mpf_mul(tmp, u[k][k - 1], u[k][k - 1]);
            mpf_set_d(cnst, 0.99);
            mpf_sub(tmp, cnst, tmp);
            mpf_mul(tmp, tmp, B[k - 1]);
            if (mpf_cmp(B[k], tmp) < 0) {
                SWAP(basis, u, H, B, bStar, k, kmax);
                k = (k - 1 > 1 ? k - 1 : 1);
            } else {
                for (int l = k - 2; l >= 0; --l) {
                    RED(basis, u, H, k, l);
                }
                k++;
                break;
            }
        }
    }
    ibz_mat_4x4_transpose(red, &basis);

err:
    mpf_clear(tmp);
    mpz_clear(tmp_z);
    mpf_clear(cnst);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            mpf_clear(u[i][j]);
            mpz_clear(H[i][j]);
            mpf_clear(bStar[i][j]);
            mpf_clear(bStar_tmp[i][j]);
        }
    }
    for (int i = 0; i < 4; ++i)
        mpf_clear(B[i]);
    ibz_mat_4x4_finalize(&basis);
    return ret;
}
