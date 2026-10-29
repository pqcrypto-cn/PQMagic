#include "curve_extras.h"
#include <ec_params.h>
#include <assert.h>

/*
 * We implement the biextension arithmetic by using the cubical torsor representation. For now only
 * implement the 2^e-ladder.
 *
 * Warning: both cubicalDBL and cubicalADD are off by a factor x4 with respect
 * to the cubical arithmetic.
 * Since this factor is the same, this means that the biextension
 * arithmetic is correct, so the pairings are ok (they only rely on the
 * biextension arithmetic).
 * In the special case where Q=P (self pairings), we use the cubical ladder
 * rather than the biextension ladder because this is faster. In that case,
 * when we do a ladder we are off by a factor 4^m, m the number of bits.
 * This factor thus disappear in the Weil pairing since we take a quotient,
 * and also in the Tate pairing due to the final exponentiation; so
 * everything is ok too.
 * (Note that when the curves are supersingular as in our case, the Tate
 * self pairing is always trivial anyway because the Galois structure of the
 * isogeneous curves are all the same, so the étale torsor representing the
 * Tate pairing has to be trivial).
 */

/* return the *normalised* point (A+2C)/4C */
void A24_from_AC(ec_point_t *A24, ec_point_t const *AC)
{
    fp2_add(&A24->z, &AC->z, &AC->z);
    fp2_add(&A24->x, &AC->x, &A24->z);
    fp2_add(&A24->z, &A24->z, &A24->z); //(A+2C: 4C)
    ec_normalize_point(A24);
}

// this is exactly like xDBLv2, except we use the fact that P is normalised
// to gain a multiplication
// Warning: for now we need to assume that A24 is normalised, ie C24=1.
// (maybe add an assert?)
void cubicalDBL(ec_point_t *Q, ec_point_t const *P, ec_point_t const *A24)
{
    // A24 = (A+2C:4C)
    fp2_t t0, t1, t2;

    assert(fp2_is_one(&A24->z));
    fp2_add(&t0, &P->x, &P->z);
    fp2_sqr(&t0, &t0);
    fp2_sub(&t1, &P->x, &P->z);
    fp2_sqr(&t1, &t1);
    fp2_sub(&t2, &t0, &t1);
    // fp2_mul(&t1, &t1, &A24->z);
    fp2_mul(&Q->x, &t0, &t1);
    fp2_mul(&t0, &t2, &A24->x);
    fp2_add(&t0, &t0, &t1);
    fp2_mul(&Q->z, &t0, &t2);
}

// this would be exactly like xADD if PQ was 'antinormalised' as (1,z)
void cubicalADD(ec_point_t *R, ec_point_t const *P, ec_point_t const *Q, fp2_t const *ixPQ)
{
    fp2_t t0, t1, t2, t3;

    fp2_add(&t0, &P->x, &P->z);
    fp2_sub(&t1, &P->x, &P->z);
    fp2_add(&t2, &Q->x, &Q->z);
    fp2_sub(&t3, &Q->x, &Q->z);
    fp2_mul(&t0, &t0, &t3);
    fp2_mul(&t1, &t1, &t2);
    fp2_add(&t2, &t0, &t1);
    fp2_sub(&t3, &t0, &t1);
    fp2_sqr(&R->z, &t3);
    fp2_sqr(&t2, &t2);
    fp2_mul(&R->x, ixPQ, &t2);
}

// given cubical reps of P+Q, Q, P, return P+2Q, 2Q
void biextDBL(ec_point_t *PQQ,
              ec_point_t *QQ,
              ec_point_t const *PQ,
              ec_point_t const *Q,
              fp2_t const *ixP,
              ec_point_t const *A24)
{
    cubicalADD(PQQ, PQ, Q, ixP);
    cubicalDBL(QQ, Q, A24);
}

// iterative biextension doubling
void biext_ladder_2e(uint64_t e,
                     ec_point_t *PnQ,
                     ec_point_t *nQ,
                     ec_point_t const *PQ,
                     ec_point_t const *Q,
                     fp2_t const *ixP,
                     ec_point_t const *A24)
{
    copy_point(PnQ, PQ);
    copy_point(nQ, Q);
    for (uint64_t i = 0; i < e; i++)
    {
        biextDBL(PnQ, nQ, PnQ, nQ, ixP, A24);
    }
}

// iterative biextension
void biext_ladder(const uint64_t *n,
                  ec_point_t *QnP,
                  ec_point_t *nP,
                  ec_point_t const *P,
                  ec_point_t const *Q,
                  ec_point_t const *PQ,
                  fp2_t const *ixP,
                  fp2_t const *ixQ,
                  fp2_t const *ixPQ,
                  ec_point_t const *A24)
{
    ec_point_t S1, R;
    copy_point(QnP, Q);
    ec_point_init(nP);
    ec_point_init(&R);
    copy_point(&S1, P);
    int i = NWORDS_ORDER - 1;
    int j = RADIX - 1;
    while (i >= 0)
    {
        if (n[i] != 0)
        {
            break;
        }
        i--;
    }
    while (j > 0)
    {
        digit_t t = 1;
        if (n[i] & (t << j))
        {
            break;
        }
        j--;
    }
    int bits = i * RADIX + j + 1;
    for (int i = NWORDS_ORDER - 1; i > -1; i--)
    {
        digit_t t = 1ULL << 63;
        for (int j = RADIX - 1; j > -1; j--)
        {
            if (bits >= i * RADIX + j + 1)
            {
                cubicalADD(&R, nP, &S1, ixP);
                if ((t & n[i]) == 0)
                {
                    cubicalADD(QnP, QnP, nP, ixQ);
                    cubicalDBL(nP, nP, A24);
                    copy_point(&S1, &R);
                }
                else
                {
                    cubicalADD(QnP, QnP, &S1, ixPQ);
                    cubicalDBL(&S1, &S1, A24);
                    copy_point(nP, &R);
                }
            }
            t >>= 1;
        };
    };
}

// compute the monodromy ratio of cubical points [(P+nQ)/P] / [(nQ)/0]
// (not used)
void ratio(fp2_t *r, ec_point_t const *PnQ, ec_point_t const *nQ, ec_point_t const *P)
{
    // Sanity tests
    assert(ec_is_zero(nQ));
    assert(is_point_equal(PnQ, P));

    fp2_mul(r, &nQ->x, &P->z);
    fp2_inv(r);
    fp2_mul(r, r, &PnQ->z);
}

// Compute the ratio X/Z above as a (X:Z) point to avoid a division
void point_ratio(ec_point_t *R, ec_point_t const *PnQ, ec_point_t const *nQ, ec_point_t const *P)
{
    // Sanity tests
    assert(ec_is_zero(nQ));
    assert(is_point_equal(PnQ, P));

    fp2_mul(&R->x, &nQ->x, &P->x);
    fp2_copy(&R->z, &PnQ->x);
}

// (X(P):Z(P))->x(P)
void x_coord(fp2_t *r, ec_point_t const *P)
{
    fp2_copy(r, &P->z);
    fp2_inv(r);
    fp2_mul(r, r, &P->x);
}

// compute the cubical translation of P by a point of 2-torsion T
void translate(ec_point_t *P, ec_point_t const *T)
{
    fp2_t t0, t1, t2;
    if (fp2_is_zero(&T->z))
    {
        // do nothing
    }
    else if (fp2_is_zero(&T->x))
    {
        fp2_copy(&t0, &P->x);
        fp2_copy(&P->x, &P->z);
        fp2_copy(&P->z, &t0);
    }
    else
    {
        fp2_mul(&t0, &T->x, &P->x);
        fp2_mul(&t1, &T->z, &P->z);
        fp2_sub(&t2, &t0, &t1);
        fp2_mul(&t0, &T->z, &P->x);
        fp2_mul(&t1, &T->x, &P->z);
        fp2_sub(&P->z, &t0, &t1);
        fp2_copy(&P->x, &t2);
    }
}

// Compute the monodromy P+2^e Q (in level 1)
// The suffix _i means that we are given 1/x(P) as parameter.
// Warning: to get meaningful result when using the monodromy to compute
// pairings, we need P, Q, PQ, A24 to be normalised
// (this is not strictly necessary, but care need to be taken when they are not normalised. Only
// handle the normalised case for now)
void monodromy_i(ec_point_t *r,
                 uint64_t e,
                 ec_point_t const *PQ,
                 ec_point_t const *Q,
                 ec_point_t const *P,
                 fp2_t const *ixP,
                 ec_point_t const *A24)
{
    ec_point_t PnQ, nQ;
    biext_ladder_2e(e - 1, &PnQ, &nQ, PQ, Q, ixP, A24);
    translate(&PnQ, &nQ);
    translate(&nQ, &nQ);
    point_ratio(r, &PnQ, &nQ, P);
}

void monodromy3(fp2_t *r,
                uint64_t *n,
                ec_point_t const *PQ,
                ec_point_t const *Q,
                ec_point_t const *P,
                fp2_t const *ixP,
                fp2_t const *ixQ,
                fp2_t const *ixPQ,
                ec_point_t const *A24)
{
    ec_point_t PnQ, nQ;
    biext_ladder(n, &PnQ, &nQ, Q, P, PQ, ixQ, ixP, ixPQ, A24);
    ratio(r, &PnQ, &nQ, P);
}

// Normalize the points and also store 1/x(P), 1/x(Q)
void to_cubical_i(ec_point_t *P, ec_point_t *Q, fp2_t *ixP, fp2_t *ixQ)
{
    fp2_t t[4];
    fp2_copy(&t[0], &P->x);
    fp2_copy(&t[1], &P->z);
    fp2_copy(&t[2], &Q->x);
    fp2_copy(&t[3], &Q->z);
    fp2_batched_inv(t, 4);
    fp2_mul(ixP, &P->z, &t[0]);
    fp2_mul(ixQ, &Q->z, &t[2]);
    fp2_mul(&P->x, &P->x, &t[1]);
    fp2_mul(&Q->x, &Q->x, &t[3]);
    fp2_set_one(&P->z);
    fp2_set_one(&Q->z);
}

void to_cubical_odd_i(ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, fp2_t *ixP, fp2_t *ixQ, fp2_t *ixPQ)
{
    fp2_t t[6];
    fp2_copy(&t[0], &P->x);
    fp2_copy(&t[1], &P->z);
    fp2_copy(&t[2], &Q->x);
    fp2_copy(&t[3], &Q->z);
    fp2_copy(&t[4], &PQ->x);
    fp2_copy(&t[5], &PQ->z);
    fp2_batched_inv(t, 6);
    fp2_mul(ixP, &P->z, &t[0]);
    fp2_mul(ixQ, &Q->z, &t[2]);
    fp2_mul(ixPQ, &PQ->z, &t[4]);
    fp2_mul(&P->x, &P->x, &t[1]);
    fp2_mul(&Q->x, &Q->x, &t[3]);
    fp2_mul(&PQ->x, &PQ->x, &t[5]);
    fp2_set_one(&P->z);
    fp2_set_one(&Q->z);
    fp2_set_one(&PQ->z);
}

// non reduced Tate pairing, PQ should be P+Q in (X:Z) coordinates
// Assume the cubical points are normalised, and that we have 1/x(P)
// The _n suffix means we assume the points are normalised
void non_reduced_tate_n(fp2_t *r,
                        uint64_t e,
                        ec_point_t *P,
                        ec_point_t *Q,
                        ec_point_t *PQ,
                        fp2_t const *ixP,
                        ec_point_t *A24)
{
    ec_point_t R;
    monodromy_i(&R, e, PQ, Q, P, ixP, A24);
    x_coord(r, &R);
}

// Same as above, but first normalise the points
void non_reduced_tate(fp2_t *r,
                      uint64_t e,
                      ec_point_t *P,
                      ec_point_t *Q,
                      ec_point_t *PQ,
                      ec_point_t *A24)
{
    fp2_t ixP, ixQ;
    to_cubical_i(P, Q, &ixP, &ixQ); // TODO: ixQ not used
    non_reduced_tate_n(r, e, P, Q, PQ, &ixP, A24);
}

// Only used for order TORSION_D
void tate_odd_TORSION_D(fp2_t *r, uint64_t *n, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24)
{
    fp2_t ixP, ixQ, ixPQ;
    to_cubical_odd_i(P, Q, PQ, &ixP, &ixQ, &ixPQ);
    monodromy3(r, n, PQ, Q, P, &ixP, &ixQ, &ixPQ, A24);
    fp2_t tmp;
    fp2_copy(&tmp, r);
    fp_neg(&tmp.im, &tmp.im);
    fp2_inv(r);
    fp2_mul(r, r, &tmp);
    digit_t exp[NWORDS_FIELD] = {0};
    ibz_to_digits(exp, &Pairing_exp);
    fp2_exp(r, r, exp, Pairing_exp->_mp_size);
}

// Used for order TORSION_ODD_PLUS
void tate_odd_Tpls(fp2_t *r, uint64_t *n, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24)
{
    fp2_t ixP, ixQ, ixPQ;
    to_cubical_odd_i(P, Q, PQ, &ixP, &ixQ, &ixPQ);
    monodromy3(r, n, PQ, Q, P, &ixP, &ixQ, &ixPQ, A24);
    fp2_t tmp;
    fp2_copy(&tmp, r);
    fp_neg(&tmp.im, &tmp.im);
    fp2_inv(r);
    fp2_mul(r, r, &tmp);
    digit_t exp[NWORDS_FIELD] = {0};
    ibz_to_digits(exp, &TORSION_ODD_PLUS);
    fp2_exp(r, r, p_cofactor_for_Tpls, (P_COFACTOR_FOR_TPLS_BITLENGTH + 63) / 64);
}

// Used for order TORSION_ODD_MINUS
void tate_odd_Tmin(fp2_t *r, uint64_t *n, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24)
{
    fp2_t ixP, ixQ, ixPQ, tmp;
    to_cubical_odd_i(P, Q, PQ, &ixP, &ixQ, &ixPQ);
    monodromy3(r, n, PQ, Q, P, &ixP, &ixQ, &ixPQ, A24);
    fp2_set_one(&tmp);
    fp_add(&tmp.re, &tmp.re, &tmp.re);
    fp_add(&tmp.re, &tmp.re, &tmp.re);
    fp_inv(&tmp.re);
    int i = NWORDS_ORDER - 1;
    int j = RADIX - 1;
    while (i >= 0)
    {
        if (n[i] != 0)
        {
            break;
        }
        i--;
    }
    while (j > 0)
    {
        digit_t t = 1;
        if (n[i] & (t << j))
        {
            break;
        }
        j--;
    }
    int bits = i * RADIX + j + 1;
    ibz_t a, b;
    ibz_init(&a);
    ibz_init(&b);
    ibz_copy(&a, &ibz_const_two);
    for (int k = 0; k < bits - 1; k++)
    {
        ibz_mul(&a, &a, &ibz_const_two);
    }
    ibz_copy_digits(&b, n, NWORDS_ORDER);
    ibz_sub(&a, &a, &b);
    ibz_sub(&a, &a, &ibz_const_one);
    digit_t POWER[NWORDS_ORDER] = {0};
    ibz_to_digits(POWER, &a);
    fp2_exp(&tmp, &tmp, POWER, mpz_size(a));
    fp2_mul(r, &tmp, r);
    fp2_copy(&tmp, r);
    fp_neg(&tmp.im, &tmp.im);
    fp2_mul(r, r, &tmp);
    fp2_exp(r, r, p_cofactor_for_Tmin, (P_COFACTOR_FOR_TMIN_BITLENGTH + 63) / 64);
    ibz_finalize(&a);
    ibz_finalize(&b);
}

// Weil pairing, PQ should be P+Q in (X:Z) coordinates
// We assume the points are normalised correctly
// Do we need a weil_c version?
void weil_n(fp2_t *r,
            uint64_t e,
            ec_point_t const *P,
            ec_point_t const *Q,
            ec_point_t const *PQ,
            fp2_t const *ixP,
            fp2_t const *ixQ,
            ec_point_t const *A24)
{
    ec_point_t R0, R1;
    monodromy_i(&R0, e, PQ, Q, P, ixP, A24);
    monodromy_i(&R1, e, PQ, P, Q, ixQ, A24);
    // TODO: check if that's the Weil pairing or its inverse
    fp2_mul(r, &R0.x, &R1.z);
    fp2_inv(r);
    fp2_mul(r, r, &R0.z);
    fp2_mul(r, r, &R1.x);
}

// Weil pairing, PQ should be P+Q in (X:Z) coordinates
// Normalise the points and call the code above
// The code will crash (division by 0) if either P or Q is (0:1)
void weil(fp2_t *r, uint64_t e, ec_point_t *P, ec_point_t *Q, ec_point_t *PQ, ec_point_t *A24)
{
    fp2_t ixP, ixQ;
    to_cubical_i(P, Q, &ixP, &ixQ);
    weil_n(r, e, P, Q, PQ, &ixP, &ixQ, A24);
}

// recursive dlog function
bool fp2_dlog_2e_rec(digit_t *a, long len, fp2_t *pows_f, fp2_t *pows_g, long stacklen)
{
    if (len == 0)
    {
        // *a = 0;
        memset(a, 0, NWORDS_ORDER * sizeof(digit_t));
        return true;
    }
    else if (len == 1)
    {
        if (fp2_is_one(&pows_f[stacklen - 1]))
        {
            // a = 0;
            memset(a, 0, NWORDS_ORDER * sizeof(digit_t));
            for (int i = 0; i < stacklen - 1; ++i)
            {
                fp2_sqr(&pows_g[i], &pows_g[i]); // new_g = g^2
            }
            return true;
        }
        else if (fp2_is_equal(&pows_f[stacklen - 1], &pows_g[stacklen - 1]))
        {
            // a = 1;
            memset(a, 0, NWORDS_ORDER * sizeof(digit_t));
            a[0] = 1;
            fp2_t tmp;
            for (int i = 0; i < stacklen - 1; ++i)
            {
                fp2_mul(&pows_f[i], &pows_f[i], &pows_g[i]); // new_f = f*g
                fp2_sqr(&pows_g[i], &pows_g[i]);             // new_g = g^2
            }
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        long right = (double)len * 0.5;
        long left = len - right;
        pows_f[stacklen] = pows_f[stacklen - 1];
        pows_g[stacklen] = pows_g[stacklen - 1];
        for (int i = 0; i < left; i++)
        {
            fp2_sqr(&pows_f[stacklen], &pows_f[stacklen]);
            fp2_sqr(&pows_g[stacklen], &pows_g[stacklen]);
        }
        // uint64_t dlp1 = 0, dlp2 = 0;
        digit_t dlp1[NWORDS_ORDER], dlp2[NWORDS_ORDER];
        bool ok;
        ok = fp2_dlog_2e_rec(dlp1, right, pows_f, pows_g, stacklen + 1);
        if (!ok)
            return false;
        ok = fp2_dlog_2e_rec(dlp2, left, pows_f, pows_g, stacklen);
        if (!ok)
            return false;
        // a = dlp1 + 2^right * dlp2
        multiple_mp_shiftl(dlp2, right, NWORDS_ORDER);
        mp_add(a, dlp2, dlp1, NWORDS_ORDER);

        return true;
    }
}

// compute DLP
bool fp2_dlog_2e(digit_t *scal, const fp2_t *f, const fp2_t *g, int e)
{
    long log, len = e;
    for (log = 0; len > 1; len >>= 1)
        log++;
    log += 1;

    fp2_t pows_f[log], pows_g[log];
    pows_f[0] = *f;
    pows_g[0] = *g;
    fp2_inv(&pows_g[0]);

    memset(scal, 0, NWORDS_ORDER * sizeof(digit_t));

    bool ok = fp2_dlog_2e_rec(scal, e, pows_f, pows_g, 1);
    assert(ok);

    return ok;
}

// recursive dlog function
bool fp2_dlog_Tpls_rec(digit_t *a, int order, long len, fp2_t *pows_f, fp2_t *pows_g, fp2_t *table, long stacklen)
{
    int bit;
    fp2_t acc;
    digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0};
    dprime[0] = TORSION_PLUS_ODD_PRIMES[order];
    dprimepow[0] = TORSION_PLUS_ODD_PRIMES[order];
    if (len == 0)
    {
        // *a = 0;
        memset(a, 0, NWORDS_ORDER * sizeof(digit_t));
        return true;
    }
    else if (len == 1)
    {
        if (fp2_is_one(&pows_f[stacklen - 1]))
        {
            // a = 0;
            memset(a, 0, NWORDS_ORDER * sizeof(digit_t));
            for (int i = 0; i < stacklen - 1; ++i)
            {
                fp2_copy(&acc, &pows_g[i]);
                for (int j = 0; j < p_plus_minus_bitlength[order]; j++)
                {
                    bit = ((TORSION_PLUS_ODD_PRIMES[order] - 1) >> j) & 1;
                    if (bit == 1)
                    {
                        fp2_mul(&pows_g[i], &pows_g[i], &acc);
                    }
                    fp2_sqr(&acc, &acc);
                }
            }
            return true;
        }
        else
        {
            int label = 0;
            for (int i = 0; i < TORSION_PLUS_ODD_PRIMES[order] - 1; i++)
            {
                if (fp2_is_equal(&pows_f[stacklen - 1], &table[i]))
                {
                    a[0] = i + 1;
                    label = 1;
                    for (int j = 1; j < NWORDS_ORDER; j++)
                    {
                        a[j] = 0;
                    }
                    for (int j = 0; j < stacklen - 1; ++j)
                    {
                        fp2_t pows_g_tmp[stacklen];
                        for (int k = 0; k < stacklen; k++)
                        {
                            fp2_copy(&pows_g_tmp[k], &pows_g[k]);
                        }
                        fp2_copy(&acc, &pows_g_tmp[j]);
                        for (int k = 0; k < p_plus_minus_bitlength[P_LEN]; k++)
                        {
                            bit = ((i) >> k) & 1;
                            if (bit == 1)
                            {
                                fp2_mul(&pows_g_tmp[j], &pows_g_tmp[j], &acc);
                            }
                            fp2_sqr(&acc, &acc);
                        }
                        fp2_mul(&pows_f[j], &pows_f[j], &pows_g_tmp[j]); // new_f
                        fp2_copy(&acc, &pows_g[j]);
                        for (int k = 0; k < p_plus_minus_bitlength[order]; k++)
                        {
                            bit = ((TORSION_PLUS_ODD_PRIMES[order] - 1) >> k) & 1;
                            if (bit == 1)
                            {
                                fp2_mul(&pows_g[j], &pows_g[j], &acc);
                            }
                            fp2_sqr(&acc, &acc);
                        }
                    }
                }
            }
            if (label == 0)
            {
                return false;
            }
            return true;
        }
    }
    else
    {
        long right = (double)len * 0.5;
        long left = len - right;
        pows_f[stacklen] = pows_f[stacklen - 1];
        pows_g[stacklen] = pows_g[stacklen - 1];
        for (int i = 0; i < left; i++)
        {
            fp2_copy(&acc, &pows_f[stacklen]);
            for (int j = 0; j < p_plus_minus_bitlength[order]; j++)
            {
                bit = ((TORSION_PLUS_ODD_PRIMES[order] - 1) >> j) & 1;
                if (bit == 1)
                {
                    fp2_mul(&pows_f[stacklen], &pows_f[stacklen], &acc);
                }
                fp2_sqr(&acc, &acc);
            }
            fp2_copy(&acc, &pows_g[stacklen]);
            for (int j = 0; j < p_plus_minus_bitlength[order]; j++)
            {
                bit = ((TORSION_PLUS_ODD_PRIMES[order] - 1) >> j) & 1;
                if (bit == 1)
                {
                    fp2_mul(&pows_g[stacklen], &pows_g[stacklen], &acc);
                }
                fp2_sqr(&acc, &acc);
            }
        }
        digit_t dlp1[NWORDS_ORDER] = {0}, dlp2[NWORDS_ORDER] = {0};
        bool ok;
        ok = fp2_dlog_Tpls_rec(dlp1, order, right, pows_f, pows_g, table, stacklen + 1);
        if (!ok)
            return false;
        ok = fp2_dlog_Tpls_rec(dlp2, order, left, pows_f, pows_g, table, stacklen);
        if (!ok)
            return false;
        // a = dlp1 + prime^right * dlp2
        for (int i = 0; i < right - 1; i++)
        {
            mp_mul_generic(dprimepow, dprimepow, dprime[0], TORSION_ODD_PLUS->_mp_size);
        }

        mp_mul_generic_md(a, dprimepow, dlp2, NWORDS_ORDER);
        mp_add(a, a, dlp1, NWORDS_ORDER);
        return true;
    }
}

// compute DLP
bool fp2_dlog_Tpls(digit_t *scal, const fp2_t *f, const fp2_t *g, int order)
{
    long log, len = TORSION_PLUS_ODD_POWERS[order];
    for (log = 0; len > 1; len >>= 1)
        log++;
    log += 1;

    fp2_t pows_f[log], pows_g[log];
    pows_f[0] = *f;
    pows_g[0] = *g;
    fp2_inv(&pows_g[0]);

    fp2_t table[TORSION_PLUS_ODD_PRIMES[order] - 1];
    fp2_set_zero(&table[0]);
    fp2_copy(&table[0], g);
    digit_t dscalar[NWORDS_ORDER] = {0}, dprime[NWORDS_ORDER] = {0};
    dprime[0] = TORSION_PLUS_ODD_PRIMES[order];
    dscalar[0] = 1;
    for (int i = 0; i < TORSION_PLUS_ODD_POWERS[order] - 1; i++)
    {
        mp_mul_generic(dscalar, dscalar, dprime[0], TORSION_ODD_PLUS->_mp_size);
    }
    fp2_exp(&table[0], &table[0], dscalar, TORSION_ODD_PLUS->_mp_size);
    for (int i = 1; i < TORSION_PLUS_ODD_PRIMES[order] - 1; i++)
    {
        fp2_mul(&table[i], &table[0], &table[i - 1]);
    }
    memset(scal, 0, NWORDS_ORDER * sizeof(digit_t));
    bool ok = fp2_dlog_Tpls_rec(scal, order, TORSION_PLUS_ODD_POWERS[order], pows_f, pows_g, table, 1);
    assert(ok);
    return ok;
}

// recursive dlog function
bool fp2_dlog_Tmin_rec(digit_t *a, int prime, long len, fp2_t *pows_f, fp2_t *pows_g, fp2_t *table, long stacklen)
{
    int bit;
    fp2_t acc;
    digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0};
    dprime[0] = prime;
    dprimepow[0] = prime;
    if (len == 0)
    {
        // *a = 0;
        for (int i = 0; i < NWORDS_ORDER; i++)
        {
            a[i] = 0;
        }
        return true;
    }
    else if (len == 1)
    {
        if (fp2_is_one(&pows_f[stacklen - 1]))
        {
            // a = 0;
            for (int i = 0; i < NWORDS_ORDER; i++)
            {
                a[i] = 0;
            }
            for (int i = 0; i < stacklen - 1; ++i)
            {
                fp2_copy(&acc, &pows_g[i]);
                for (int j = 0; j < p_plus_minus_bitlength[P_LEN]; j++)
                {
                    bit = ((prime - 1) >> j) & 1;
                    if (bit == 1)
                    {
                        fp2_mul(&pows_g[i], &pows_g[i], &acc);
                    }
                    fp2_sqr(&acc, &acc);
                }
            }
            return true;
        }
        else
        {
            int label = 0;
            for (int i = 0; i < prime - 1; i++)
            {
                if (fp2_is_equal(&pows_f[stacklen - 1], &table[i]))
                {
                    a[0] = i + 1;
                    label = 1;
                    for (int j = 1; j < NWORDS_ORDER; j++)
                    {
                        a[j] = 0;
                    }
                    for (int j = 0; j < stacklen - 1; ++j)
                    {
                        fp2_t pows_g_tmp[stacklen];
                        for (int k = 0; k < stacklen; k++)
                        {
                            fp2_copy(&pows_g_tmp[k], &pows_g[k]);
                        }
                        fp2_copy(&acc, &pows_g_tmp[j]);
                        for (int k = 0; k < p_plus_minus_bitlength[P_LEN]; k++)
                        {
                            bit = ((i) >> k) & 1;
                            if (bit == 1)
                            {
                                fp2_mul(&pows_g_tmp[j], &pows_g_tmp[j], &acc);
                            }
                            fp2_sqr(&acc, &acc);
                        }
                        fp2_mul(&pows_f[j], &pows_f[j], &pows_g_tmp[j]); // new_f
                        fp2_copy(&acc, &pows_g[j]);
                        for (int k = 0; k < p_plus_minus_bitlength[P_LEN]; k++)
                        {
                            bit = ((prime - 1) >> k) & 1;
                            if (bit == 1)
                            {
                                fp2_mul(&pows_g[j], &pows_g[j], &acc);
                            }
                            fp2_sqr(&acc, &acc);
                        }
                    }
                }
            }
            if (label == 0)
            {
                return false;
            }
            return true;
        }
    }
    else
    {
        long right = (double)len * 0.5;
        long left = len - right;
        pows_f[stacklen] = pows_f[stacklen - 1];
        pows_g[stacklen] = pows_g[stacklen - 1];
        for (int i = 0; i < left; i++)
        {
            fp2_copy(&acc, &pows_f[stacklen]);
            for (int j = 0; j < p_plus_minus_bitlength[P_LEN]; j++)
            {
                bit = ((prime - 1) >> j) & 1;
                if (bit == 1)
                {
                    fp2_mul(&pows_f[stacklen], &pows_f[stacklen], &acc);
                }
                fp2_sqr(&acc, &acc);
            }
            fp2_copy(&acc, &pows_g[stacklen]);
            for (int j = 0; j < p_plus_minus_bitlength[P_LEN]; j++)
            {
                bit = ((prime - 1) >> j) & 1;
                if (bit == 1)
                {
                    fp2_mul(&pows_g[stacklen], &pows_g[stacklen], &acc);
                }
                fp2_sqr(&acc, &acc);
            }
        }
        digit_t dlp1[NWORDS_ORDER] = {0}, dlp2[NWORDS_ORDER] = {0};
        bool ok;
        ok = fp2_dlog_Tmin_rec(dlp1, prime, right, pows_f, pows_g, table, stacklen + 1);
        if (!ok)
            return false;
        ok = fp2_dlog_Tmin_rec(dlp2, prime, left, pows_f, pows_g, table, stacklen);
        if (!ok)
            return false;
        // a = dlp1 + prime^right * dlp2
        for (int i = 0; i < right - 1; i++)
        {
            mp_mul_generic(dprimepow, dprimepow, dprime[0], TORSION_ODD_MINUS->_mp_size);
        }

        mp_mul_generic_md(a, dprimepow, dlp2, NWORDS_ORDER);
        mp_add(a, a, dlp1, NWORDS_ORDER);
        return true;
    }
}

// compute DLP
bool fp2_dlog_Tmin(digit_t *scal, const fp2_t *f, const fp2_t *g, int prime, int e)
{
    long log, len = e;
    for (log = 0; len > 1; len >>= 1)
        log++;
    log += 1;

    fp2_t pows_f[log], pows_g[log];
    pows_f[0] = *f;
    pows_g[0] = *g;
    fp2_inv(&pows_g[0]);

    fp2_t table[prime - 1];
    fp2_copy(&table[0], g);
    digit_t dscalar[NWORDS_ORDER] = {0};
    ibz_t scalar, remainder;
    ibz_init(&scalar);
    ibz_init(&remainder);
    ibz_div(&scalar, &remainder, &TORSION_ODD_MINUS, &TORSION_MINUS_PRIME);
    ibz_to_digits(dscalar, &scalar);
    fp2_exp(&table[0], &table[0], dscalar, TORSION_ODD_MINUS->_mp_size);
    for (int i = 1; i < prime - 1; i++)
    {
        fp2_mul(&table[i], &table[0], &table[i - 1]);
    }
    memset(scal, 0, NWORDS_ORDER * sizeof(digit_t));

    bool ok = fp2_dlog_Tmin_rec(scal, prime, e, pows_f, pows_g, table, 1);
    ibz_finalize(&scalar);
    ibz_finalize(&remainder);
    assert(ok);
    return ok;
}

// Normalize a point Q and a "basis" (P1, P2) and store their inverse
void to_cubical_basis_i_single(ec_point_t *Q,
                               ec_point_t *P1,
                               ec_point_t *P2,
                               fp2_t *ixQ,
                               fp2_t *ixP1,
                               fp2_t *ixP2)
{
    fp2_t t[6];
    fp2_copy(&t[0], &Q->x);
    fp2_copy(&t[1], &Q->z);
    fp2_copy(&t[2], &P1->x);
    fp2_copy(&t[3], &P1->z);
    fp2_copy(&t[4], &P2->x);
    fp2_copy(&t[5], &P2->z);
    fp2_batched_inv(t, 6);
    fp2_mul(ixQ, &Q->z, &t[0]);
    fp2_mul(&Q->x, &Q->x, &t[1]);
    fp2_set_one(&Q->z);
    fp2_mul(ixP1, &P1->z, &t[2]);
    fp2_mul(&P1->x, &P1->x, &t[3]);
    fp2_set_one(&P1->z);
    fp2_mul(ixP2, &P2->z, &t[4]);
    fp2_mul(&P2->x, &P2->x, &t[5]);
    fp2_set_one(&P2->z);
}

// Inline all the Weil pairing computations done for single point
void weil_dlog_single(digit_t *scalarP2,
                      digit_t *scalarQ2,
                      uint64_t e,
                      ec_point_t *P,
                      ec_point_t *Q,
                      ec_point_t *P2,
                      ec_point_t *PQ,
                      ec_point_t *PP2,
                      ec_point_t *P2Q,
                      ec_point_t *A24)
{

    fp2_t ixP, ixQ, ixP1, ixP2, w0, w;
    ec_point_t nP, nQ, nP2, nPQ, PnQ, nPP2, PnP2, nP2Q, P2nQ, R0, R1;

    to_cubical_basis_i_single(P, Q, P2, &ixP, &ixQ, &ixP2);

    copy_point(&nP, P);
    copy_point(&nQ, Q);
    copy_point(&nP2, P2);
    copy_point(&nPQ, PQ);
    copy_point(&PnQ, PQ);
    copy_point(&nPP2, PP2);
    copy_point(&PnP2, PP2);
    copy_point(&nP2Q, P2Q);
    copy_point(&P2nQ, P2Q);

    for (uint64_t i = 0; i < e - 1; i++)
    {
        cubicalADD(&nPQ, &nPQ, &nP, &ixQ);
        cubicalADD(&nPP2, &nPP2, &nP, &ixP2);

        cubicalADD(&PnQ, &PnQ, &nQ, &ixP);
        cubicalADD(&P2nQ, &P2nQ, &nQ, &ixP2);

        cubicalADD(&PnP2, &PnP2, &nP2, &ixP);
        cubicalADD(&nP2Q, &nP2Q, &nP2, &ixQ);

        cubicalDBL(&nP, &nP, A24);
        cubicalDBL(&nQ, &nQ, A24);
        cubicalDBL(&nP2, &nP2, A24);
    }

    // weil(&w0,e,&PQ->P,&PQ->Q,&PQ->PmQ,&A24);
    translate(&nPQ, &nP);
    translate(&nPP2, &nP);
    translate(&PnQ, &nQ);
    translate(&P2nQ, &nQ);
    translate(&PnP2, &nP2);
    translate(&nP2Q, &nP2);

    translate(&nP, &nP);
    translate(&nQ, &nQ);
    translate(&nP2, &nP2);

    // TODO: we could batch these 5 inversions

    // computation of the reference weil pairing
    // weil(&w0,e,&PQ->P,&PQ->Q,&PQ->PmQ,&A24);
    point_ratio(&R0, &nPQ, &nP, Q);
    point_ratio(&R1, &PnQ, &nQ, P);
    fp2_mul(&w0, &R0.x, &R1.z);
    fp2_inv(&w0);
    fp2_mul(&w0, &w0, &R0.z);
    fp2_mul(&w0, &w0, &R1.x);

    // e(P,P2) = w0^scalarQ2
    // weil(&w,e,&PQ->P,&basis->Q,&PmP2,&A24);
    point_ratio(&R0, &nPP2, &nP, P2);
    point_ratio(&R1, &PnP2, &nP2, P);
    fp2_mul(&w, &R0.x, &R1.z);
    fp2_inv(&w);
    fp2_mul(&w, &w, &R0.z);
    fp2_mul(&w, &w, &R1.x);
    fp2_dlog_2e(scalarQ2, &w, &w0, e);

    // e(P2,Q) = w0^scalarP2
    // weil(&w,e,&basis->Q,&PQ->Q,&P2mQ,&A24);
    point_ratio(&R0, &nP2Q, &nP2, Q);
    point_ratio(&R1, &P2nQ, &nQ, P2);
    fp2_mul(&w, &R0.x, &R1.z);
    fp2_inv(&w);
    fp2_mul(&w, &w, &R0.z);
    fp2_mul(&w, &w, &R1.x);
    fp2_dlog_2e(scalarP2, &w, &w0, e);
}

void tate_dlog_Tpls(digit_t *scalarP1,
                    digit_t *scalarQ1,
                    digit_t *scalarP2,
                    digit_t *scalarQ2,
                    ec_point_t *P,
                    ec_point_t *Q,
                    ec_point_t *P1,
                    ec_point_t *P2,
                    ec_point_t *PQ,
                    ec_point_t *PP1,
                    ec_point_t *PP2,
                    ec_point_t *P1Q,
                    ec_point_t *P2Q,
                    ec_point_t *A24,
                    const uint64_t *primes,
                    const size_t *powers,
                    int size)
{
    fp2_t ixP, ixQ, ixP1, ixP2, w0, w, wt1, wt2;
    ibz_t primepow[size], base_prime, expt, tmp1, tmp2, tmp3, tmp4;
    for (int i = 0; i < size; i++)
    {
        ibz_init(&primepow[i]);
    }
    ibz_init(&base_prime);
    ibz_init(&expt);
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    ibz_init(&tmp3);
    ibz_init(&tmp4);

    ec_point_t nP, nQ, nP1, nP2, nPQ, PnQ, nPP1, PnP1, nPP2, PnP2, nP1Q, P1nQ, nP2Q, P2nQ, R0, R1;
    bool ok;

    digit_t dTORSION_ODD_PLUS[NWORDS_ORDER] = {0};
    ibz_to_digits(dTORSION_ODD_PLUS, &TORSION_ODD_PLUS);
    // compute w0
    tate_odd_Tpls(&w0, dTORSION_ODD_PLUS, P, Q, PQ, A24);
    // e(P,P1) = w0^scalarQ1
    if (ec_is_zero(PP1))
    {
        memset(scalarQ1, 0, NWORDS_ORDER * sizeof(digit_t));
        scalarQ1[0] = 1;
    }
    else
    {
        tate_odd_Tpls(&w, dTORSION_ODD_PLUS, P, P1, PP1, A24);
        for (int i = 0; i < size; i++)
        {
            digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0}, dexpt[NWORDS_ORDER] = {0}, scltmp[NWORDS_ORDER] = {0};
            dprime[0] = primes[i];
            dprimepow[0] = primes[i];
            for (int j = 0; j < powers[i] - 1; j++)
            {
                mp_mul_generic(dprimepow, dprimepow, dprime[0], NWORDS_ORDER);
            }
            ibz_copy_digits(&base_prime, dprimepow, NWORDS_ORDER);
            ibz_div(&expt, &base_prime, &TORSION_ODD_PLUS, &base_prime);
            ibz_to_digits(dexpt, &expt);
            fp2_exp(&wt2, &w, dexpt, TORSION_ODD_PLUS->_mp_size);
            fp2_exp(&wt1, &w0, dexpt, TORSION_ODD_PLUS->_mp_size);
            ok = fp2_dlog_Tpls(scltmp, &wt2, &wt1, i);
            assert(ok);
            if (i == 0)
            {
                ibz_copy_digits(&tmp1, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp3, dprimepow, NWORDS_ORDER);
            }
            else
            {
                ibz_copy_digits(&tmp2, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp4, dprimepow, NWORDS_ORDER);
                ibz_crt(&tmp1, &tmp1, &tmp2, &tmp3, &tmp4);
                ibz_mul(&tmp3, &tmp3, &tmp4);
            }
        }
        ibz_to_digits(scalarQ1, &tmp1);
    }

    // e(P1,Q) = w0^scalarP1
    if (ec_is_zero(P1Q))
    {
        scalarP1[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarP1[0] = 0;
        }
    }
    else
    {
        tate_odd_Tpls(&w, dTORSION_ODD_PLUS, P1, Q, P1Q, A24);
        for (int i = 0; i < size; i++)
        {
            digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0}, dexpt[NWORDS_ORDER] = {0}, scltmp[NWORDS_ORDER] = {0};
            dprime[0] = primes[i];
            dprimepow[0] = primes[i];
            for (int j = 0; j < powers[i] - 1; j++)
            {
                mp_mul_generic(dprimepow, dprimepow, dprime[0], NWORDS_ORDER);
            }
            ibz_copy_digits(&base_prime, dprimepow, NWORDS_ORDER);
            ibz_div(&expt, &base_prime, &TORSION_ODD_PLUS, &base_prime);
            ibz_to_digits(dexpt, &expt);
            fp2_exp(&wt2, &w, dexpt, TORSION_ODD_PLUS->_mp_size);
            fp2_exp(&wt1, &w0, dexpt, TORSION_ODD_PLUS->_mp_size);
            ok = fp2_dlog_Tpls(scltmp, &wt2, &wt1, i);
            assert(ok);
            if (i == 0)
            {
                ibz_copy_digits(&tmp1, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp3, dprimepow, NWORDS_ORDER);
            }
            else
            {
                ibz_copy_digits(&tmp2, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp4, dprimepow, NWORDS_ORDER);
                ibz_crt(&tmp1, &tmp1, &tmp2, &tmp3, &tmp4);
                ibz_mul(&tmp3, &tmp3, &tmp4);
            }
        }
        ibz_to_digits(scalarP1, &tmp1);
    }

    // e(P,P2) = w0^scalarQ2
    // weil(&w,e,&PQ->P,&basis->Q,&PmP2,&A24);
    if (ec_is_zero(PP2))
    {
        scalarQ2[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarQ2[0] = 0;
        }
    }
    else
    {
        tate_odd_Tpls(&w, dTORSION_ODD_PLUS, P, P2, PP2, A24);
        for (int i = 0; i < size; i++)
        {
            digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0}, dexpt[NWORDS_ORDER] = {0}, scltmp[NWORDS_ORDER] = {0};
            dprime[0] = primes[i];
            dprimepow[0] = primes[i];
            for (int j = 0; j < powers[i] - 1; j++)
            {
                mp_mul_generic(dprimepow, dprimepow, dprime[0], NWORDS_ORDER);
            }
            ibz_copy_digits(&base_prime, dprimepow, NWORDS_ORDER);
            ibz_div(&expt, &base_prime, &TORSION_ODD_PLUS, &base_prime);
            ibz_to_digits(dexpt, &expt);
            fp2_exp(&wt2, &w, dexpt, TORSION_ODD_PLUS->_mp_size);
            fp2_exp(&wt1, &w0, dexpt, TORSION_ODD_PLUS->_mp_size);
            ok = fp2_dlog_Tpls(scltmp, &wt2, &wt1, i);
            assert(ok);
            if (i == 0)
            {
                ibz_copy_digits(&tmp1, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp3, dprimepow, NWORDS_ORDER);
            }
            else
            {
                ibz_copy_digits(&tmp2, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp4, dprimepow, NWORDS_ORDER);
                ibz_crt(&tmp1, &tmp1, &tmp2, &tmp3, &tmp4);
                ibz_mul(&tmp3, &tmp3, &tmp4);
            }
        }
        ibz_to_digits(scalarQ2, &tmp1);
    }

    // e(P2,Q) = w0^scalarP2
    // weil(&w,e,&basis->Q,&PQ->Q,&P2mQ,&A24);
    if (ec_is_zero(P2Q))
    {
        scalarP2[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarP2[0] = 0;
        }
    }
    else
    {
        tate_odd_Tpls(&w, dTORSION_ODD_PLUS, P2, Q, P2Q, A24);
        for (int i = 0; i < size; i++)
        {
            digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0}, dexpt[NWORDS_ORDER] = {0}, scltmp[NWORDS_ORDER] = {0};
            dprime[0] = primes[i];
            dprimepow[0] = primes[i];
            for (int j = 0; j < powers[i] - 1; j++)
            {
                mp_mul_generic(dprimepow, dprimepow, dprime[0], NWORDS_ORDER);
            }
            ibz_copy_digits(&base_prime, dprimepow, NWORDS_ORDER);
            ibz_div(&expt, &base_prime, &TORSION_ODD_PLUS, &base_prime);
            ibz_to_digits(dexpt, &expt);
            fp2_exp(&wt2, &w, dexpt, TORSION_ODD_PLUS->_mp_size);
            fp2_exp(&wt1, &w0, dexpt, TORSION_ODD_PLUS->_mp_size);
            ok = fp2_dlog_Tpls(scltmp, &wt2, &wt1, i);
            assert(ok);
            if (i == 0)
            {
                ibz_copy_digits(&tmp1, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp3, dprimepow, NWORDS_ORDER);
            }
            else
            {
                ibz_copy_digits(&tmp2, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp4, dprimepow, NWORDS_ORDER);
                ibz_crt(&tmp1, &tmp1, &tmp2, &tmp3, &tmp4);
                ibz_mul(&tmp3, &tmp3, &tmp4);
            }
        }
        ibz_to_digits(scalarP2, &tmp1);
    }

    for (int i = 0; i < size; i++)
    {
        ibz_finalize(&primepow[i]);
    }
    ibz_finalize(&base_prime);
    ibz_finalize(&expt);
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
    ibz_finalize(&tmp3);
    ibz_finalize(&tmp4);
}

void tate_dlog_Tpls_single(digit_t *scalarP2,
                           digit_t *scalarQ2,
                           ec_point_t *P,
                           ec_point_t *Q,
                           ec_point_t *P2,
                           ec_point_t *PQ,
                           ec_point_t *PP2,
                           ec_point_t *P2Q,
                           ec_point_t *A24,
                           const uint64_t *primes,
                           const size_t *powers,
                           int size)
{
    fp2_t ixP, ixQ, ixP1, ixP2, w0, w, wt1, wt2;
    ibz_t primepow[size], base_prime, expt, tmp1, tmp2, tmp3, tmp4;
    for (int i = 0; i < size; i++)
    {
        ibz_init(&primepow[i]);
    }
    ibz_init(&base_prime);
    ibz_init(&expt);
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    ibz_init(&tmp3);
    ibz_init(&tmp4);

    ec_point_t nP, nQ, nP2, nPQ, PnQ, nPP2, PnP2, P1nQ, nP2Q, P2nQ, R0, R1;
    bool ok;

    digit_t dTORSION_ODD_PLUS[NWORDS_ORDER] = {0};
    ibz_to_digits(dTORSION_ODD_PLUS, &TORSION_ODD_PLUS);
    // computation of the reference weil pairing
    tate_odd_Tpls(&w0, dTORSION_ODD_PLUS, P, Q, PQ, A24);

    // e(P,P2) = w0^scalarQ2
    if (ec_is_zero(PP2))
    {
        scalarQ2[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarQ2[0] = 0;
        }
    }
    else
    {
        tate_odd_Tpls(&w, dTORSION_ODD_PLUS, P, P2, PP2, A24);
        for (int i = 0; i < size; i++)
        {
            digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0}, dexpt[NWORDS_ORDER] = {0}, scltmp[NWORDS_ORDER] = {0};
            dprime[0] = primes[i];
            dprimepow[0] = primes[i];
            for (int j = 0; j < powers[i] - 1; j++)
            {
                mp_mul_generic(dprimepow, dprimepow, dprime[0], NWORDS_ORDER);
            }
            ibz_copy_digits(&base_prime, dprimepow, NWORDS_ORDER);
            ibz_div(&expt, &base_prime, &TORSION_ODD_PLUS, &base_prime);
            ibz_to_digits(dexpt, &expt);
            fp2_exp(&wt2, &w, dexpt, TORSION_ODD_PLUS->_mp_size);
            fp2_exp(&wt1, &w0, dexpt, TORSION_ODD_PLUS->_mp_size);
            ok = fp2_dlog_Tpls(scltmp, &wt2, &wt1, i);
            assert(ok);
            if (i == 0)
            {
                ibz_copy_digits(&tmp1, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp3, dprimepow, NWORDS_ORDER);
            }
            else
            {
                ibz_copy_digits(&tmp2, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp4, dprimepow, NWORDS_ORDER);
                ibz_crt(&tmp1, &tmp1, &tmp2, &tmp3, &tmp4);
                ibz_mul(&tmp3, &tmp3, &tmp4);
            }
        }
        ibz_to_digits(scalarQ2, &tmp1);
    }

    // e(P2,Q) = w0^scalarP2
    if (ec_is_zero(P2Q))
    {
        scalarP2[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarP2[0] = 0;
        }
    }
    else
    {
        tate_odd_Tpls(&w, dTORSION_ODD_PLUS, P2, Q, P2Q, A24);
        for (int i = 0; i < size; i++)
        {
            digit_t dprime[NWORDS_ORDER] = {0}, dprimepow[NWORDS_ORDER] = {0}, dexpt[NWORDS_ORDER] = {0}, scltmp[NWORDS_ORDER] = {0};
            dprime[0] = primes[i];
            dprimepow[0] = primes[i];
            for (int j = 0; j < powers[i] - 1; j++)
            {
                mp_mul_generic(dprimepow, dprimepow, dprime[0], NWORDS_ORDER);
            }
            ibz_copy_digits(&base_prime, dprimepow, NWORDS_ORDER);
            ibz_div(&expt, &base_prime, &TORSION_ODD_PLUS, &base_prime);
            ibz_to_digits(dexpt, &expt);
            fp2_exp(&wt2, &w, dexpt, TORSION_ODD_PLUS->_mp_size);
            fp2_exp(&wt1, &w0, dexpt, TORSION_ODD_PLUS->_mp_size);
            ok = fp2_dlog_Tpls(scltmp, &wt2, &wt1, i);
            assert(ok);
            if (i == 0)
            {
                ibz_copy_digits(&tmp1, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp3, dprimepow, NWORDS_ORDER);
            }
            else
            {
                ibz_copy_digits(&tmp2, scltmp, NWORDS_ORDER);
                ibz_copy_digits(&tmp4, dprimepow, NWORDS_ORDER);
                ibz_crt(&tmp1, &tmp1, &tmp2, &tmp3, &tmp4);
                ibz_mul(&tmp3, &tmp3, &tmp4);
            }
        }
        ibz_to_digits(scalarP2, &tmp1);
    }

    for (int i = 0; i < size; i++)
    {
        ibz_finalize(&primepow[i]);
    }
    ibz_finalize(&base_prime);
    ibz_finalize(&expt);
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
    ibz_finalize(&tmp3);
    ibz_finalize(&tmp4);
}

void tate_dlog_Tmin(digit_t *scalarP1,
                    digit_t *scalarQ1,
                    digit_t *scalarP2,
                    digit_t *scalarQ2,
                    ec_point_t *P,
                    ec_point_t *Q,
                    ec_point_t *P1,
                    ec_point_t *P2,
                    ec_point_t *PQ,
                    ec_point_t *PP1,
                    ec_point_t *PP2,
                    ec_point_t *P1Q,
                    ec_point_t *P2Q,
                    ec_point_t *A24)
{

    fp2_t ixP, ixQ, ixP1, ixP2, w0, w;
    ec_point_t nP, nQ, nP1, nP2, nPQ, PnQ, nPP1, PnP1, nPP2, PnP2, nP1Q, P1nQ, nP2Q, P2nQ, R0, R1;
    bool ok;

    digit_t dTORSION_ODD_MINUS[NWORDS_ORDER] = {0};
    ibz_to_digits(dTORSION_ODD_MINUS, &TORSION_ODD_MINUS);
    // compute w0
    tate_odd_Tmin(&w0, dTORSION_ODD_MINUS, P, Q, PQ, A24);
    // e(P,P1) = w0^scalarQ1
    if (ec_is_zero(PP1))
    {
        memset(scalarQ1, 0, NWORDS_ORDER * sizeof(digit_t));
        scalarQ1[0] = 1;
    }
    else
    {
        tate_odd_Tmin(&w, dTORSION_ODD_MINUS, P, P1, PP1, A24);
        ok = fp2_dlog_Tmin(scalarQ1, &w, &w0, TORSION_MINUS_ODD_PRIMES[0], TORSION_ODD_POWERS[P_LEN]);
        assert(ok);
    }

    // e(P1,Q) = w0^scalarP1
    if (ec_is_zero(P1Q))
    {
        scalarP1[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarP1[0] = 0;
        }
    }
    else
    {
        tate_odd_Tmin(&w, dTORSION_ODD_MINUS, P1, Q, P1Q, A24);
        ok = fp2_dlog_Tmin(scalarP1, &w, &w0, TORSION_MINUS_ODD_PRIMES[0], TORSION_ODD_POWERS[P_LEN]);
        assert(ok);
    }

    // e(P,P2) = w0^scalarQ2
    if (ec_is_zero(PP2))
    {
        scalarQ2[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarQ2[0] = 0;
        }
    }
    else
    {
        tate_odd_Tmin(&w, dTORSION_ODD_MINUS, P, P2, PP2, A24);
        ok = fp2_dlog_Tmin(scalarQ2, &w, &w0, TORSION_MINUS_ODD_PRIMES[0], TORSION_ODD_POWERS[P_LEN]);
        assert(ok);
    }

    // e(P2,Q) = w0^scalarP2
    if (ec_is_zero(P2Q))
    {
        scalarP2[0] = 1;
        for (int i = 1; i < NWORDS_ORDER; i++)
        {
            scalarP2[0] = 0;
        }
    }
    else
    {
        tate_odd_Tmin(&w, dTORSION_ODD_MINUS, P2, Q, P2Q, A24);
        ok = fp2_dlog_Tmin(scalarP2, &w, &w0, TORSION_MINUS_ODD_PRIMES[0], TORSION_ODD_POWERS[P_LEN]);
        assert(ok);
    }
}

// Like ec_dlog_2_weil_old but inline all weil pairing computation to factor
// the same arithmetic operations
void ec_dlog_2_weil_single(digit_t *scalarP2,
                           digit_t *scalarQ2,
                           ec_basis_t *PQ,
                           ec_point_t *point,
                           ec_curve_t *curve,
                           int e)
{

    assert(test_point_order_twof(&PQ->Q, curve, e));

    fp2_t w0, w;
    ec_point_t AC, A24;
    ec_point_t PmP2, P2mQ;
    jac_point_t xyP, xyQ, xyP2, temp;

    // we start by computing the different weil pairings

    // precomputing the correct curve data
    fp2_copy(&AC.x, &curve->A);
    fp2_copy(&AC.z, &curve->C);
    A24_from_AC(&A24, &AC);

    // lifting the two basis points
    lift_basis(&xyP, &xyQ, PQ, curve);
    // lift_basis(&xyP1, &xyP2, basis, curve);
    lift_point(&xyP2, point, curve);

    // computation of the differences

    jac_neg(&temp, &xyP2);
    ADD(&temp, &temp, &xyP, curve);
    jac_to_xz(&PmP2, &temp);
    jac_neg(&temp, &xyQ);
    ADD(&temp, &temp, &xyP2, curve);
    jac_to_xz(&P2mQ, &temp);

    weil_dlog_single(scalarP2,
                     scalarQ2,
                     e,
                     &PQ->P,
                     &PQ->Q,
                     point,
                     &PQ->PmQ,
                     &PmP2,
                     &P2mQ,
                     &A24);

#ifndef NDEBUG
    ec_point_t test_comput;
    ec_biscalar_mul(&test_comput, curve, scalarP2, scalarQ2, PQ);
    assert(ec_is_equal(&test_comput, point));
#endif
}

void ec_dlog_Tpls_tate_single(digit_t *scalarP2,
                              digit_t *scalarQ2,
                              ec_basis_t *PQ,
                              ec_point_t *point,
                              ec_curve_t *curve)
{
    fp2_t w0, w;
    ec_point_t AC, A24;
    ec_point_t PmP2, P2mQ;
    jac_point_t xyP, xyQ, xyP2, temp;
    ibz_t tmp1, tmp2;

    ibz_init(&tmp1);
    ibz_init(&tmp2);

    // precomputing the correct curve data
    fp2_inv(&curve->C);
    fp2_mul(&curve->A, &curve->A, &curve->C);
    fp2_set_one(&curve->C);
    fp2_copy(&AC.x, &curve->A);
    fp2_copy(&AC.z, &curve->C);
    A24_from_AC(&A24, &AC);

    // computation of the differences
    ec_normalize_point(&PQ->P);
    ec_normalize_point(&PQ->Q);
    ec_normalize_point(point);
    difference_point(&PmP2, &PQ->P, point, curve);
    difference_point(&P2mQ, &PQ->Q, point, curve);

    tate_dlog_Tpls_single(scalarP2,
                          scalarQ2,
                          &PQ->P,
                          &PQ->Q,
                          point,
                          &PQ->PmQ,
                          &PmP2,
                          &P2mQ,
                          &A24,
                          TORSION_PLUS_ODD_PRIMES,
                          TORSION_PLUS_ODD_POWERS,
                          P_LEN);

    ec_point_t test_comput;
    digit_t dTORSION_ODD_PLUS[NWORDS_ORDER] = {0};
    ibz_to_digits(dTORSION_ODD_PLUS, &TORSION_ODD_PLUS);
    ec_biscalar_mul_bounded(&test_comput, curve, scalarP2, scalarQ2, PQ, TORSION_ODD_PLUS->_mp_size);
    if (!ec_is_equal(&test_comput, point))
    {
        ibz_copy_digits(&tmp1, dTORSION_ODD_PLUS, NWORDS_ORDER);
        ibz_copy_digits(&tmp1, scalarP2, NWORDS_ORDER);
        mp_sub(scalarP2, dTORSION_ODD_PLUS, scalarP2, NWORDS_ORDER);
    }
    ibz_copy_digits(&tmp1, scalarP2, NWORDS_ORDER);
    ibz_copy_digits(&tmp2, scalarQ2, NWORDS_ORDER);
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
#ifndef NDEBUG
    ec_biscalar_mul(&test_comput, curve, scalarP2, scalarQ2, PQ);
    assert(ec_is_equal(&test_comput, point));
#endif
}

void ec_dlog_Tmin_tate(digit_t *scalarP1,
                       digit_t *scalarQ1,
                       digit_t *scalarP2,
                       digit_t *scalarQ2,
                       ec_basis_t *PQ,
                       ec_basis_t *basis,
                       ec_curve_t *curve)
{
    fp2_t w0, w;
    ec_point_t AC, A24;
    ec_point_t PmP1, P1mQ, PmP2, P2mQ;
    jac_point_t xyP, xyQ, xyP1, xyP2, temp;

    // we start by computing the different weil pairings

    // precomputing the correct curve data
    fp2_inv(&curve->C);
    fp2_mul(&curve->A, &curve->A, &curve->C);
    fp2_set_one(&curve->C);
    fp2_copy(&AC.x, &curve->A);
    fp2_copy(&AC.z, &curve->C);
    A24_from_AC(&A24, &AC);

    // computation of the differences
    ec_normalize_point(&PQ->P);
    ec_normalize_point(&PQ->Q);
    ec_normalize_point(&basis->P);
    ec_normalize_point(&basis->Q);
    difference_point(&PmP1, &PQ->P, &basis->P, curve);
    difference_point(&P1mQ, &PQ->Q, &basis->P, curve);
    difference_point(&PmP2, &PQ->P, &basis->Q, curve);
    difference_point(&P2mQ, &PQ->Q, &basis->Q, curve);

    tate_dlog_Tmin(scalarP1,
                   scalarQ1,
                   scalarP2,
                   scalarQ2,
                   &PQ->P,
                   &PQ->Q,
                   &basis->P,
                   &basis->Q,
                   &PQ->PmQ,
                   &PmP1,
                   &PmP2,
                   &P1mQ,
                   &P2mQ,
                   &A24);

    ec_point_t test_comput;
    digit_t dTORSION_ODD_MINUS[NWORDS_ORDER] = {0};
    ibz_to_digits(dTORSION_ODD_MINUS, &TORSION_ODD_MINUS);
    ec_biscalar_mul_bounded(&test_comput, curve, scalarP1, scalarQ1, PQ, TORSION_ODD_MINUS->_mp_size);
    if (!ec_is_equal(&test_comput, &basis->P))
    {
        mp_sub(scalarP1, dTORSION_ODD_MINUS, scalarP1, NWORDS_ORDER);
    }
    ec_biscalar_mul_bounded(&test_comput, curve, scalarP2, scalarQ2, PQ, TORSION_ODD_MINUS->_mp_size);
    if (!ec_is_equal(&test_comput, &basis->Q))
    {
        mp_sub(scalarP2, dTORSION_ODD_MINUS, scalarP2, NWORDS_ORDER);
    }

#ifndef NDEBUG
    ec_biscalar_mul(&test_comput, curve, scalarP1, scalarQ1, PQ);
    assert(ec_is_equal(&test_comput, &basis->P));
    ec_biscalar_mul(&test_comput, curve, scalarP2, scalarQ2, PQ);
    assert(ec_is_equal(&test_comput, &basis->Q));
#endif
}
