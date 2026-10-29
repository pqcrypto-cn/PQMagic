#include "curve_extras.h"
#include <ec_params.h>
#include <assert.h>
#include <stdio.h>

void ec_normalize_point(ec_point_t *P)
{
    fp2_inv(&P->z);
    fp2_mul(&P->x, &P->x, &P->z);
    fp2_set_one(&(P->z));
}

void ec_normalize_curve(ec_curve_t *E)
{
    fp2_inv(&E->C);
    fp2_mul(&E->A, &E->A, &E->C);
    fp2_set_one(&E->C);
}

void ec_curve_normalize_A24(ec_curve_t *E)
{
    if (E->is_A24_computed_and_normalized == 0)
    {
        AC_to_A24(&E->A24, E);
        ec_normalize_point(&E->A24);
        E->is_A24_computed_and_normalized = 1;
    }
}

bool ec_is_zero(ec_point_t const *P)
{
    return fp2_is_zero(&P->z);
}

void ec_point_init(ec_point_t *P)
{ // Initialize point as identity element (1:0)
    fp2_set_one(&(P->x));
    fp2_set_zero(&(P->z));
}

// Initialise the curve struct
void ec_curve_init(ec_curve_t *E)
{
    // Initialise the constants
    fp2_set_zero(&(E->A));
    fp2_set_one(&(E->C));

    // Initalise the point (A+2 : 4C)
    ec_point_init(&(E->A24));

    // Set the bool to be false by default
    E->is_A24_computed_and_normalized = 0;
}

// TODO: this is simply ec_point_init, we don't need both?
void ec_set_zero(ec_point_t *P)
{
    fp2_set_one(&(P->x));
    fp2_set_zero(&(P->z));
    return;
}

void copy_curve(ec_curve_t *E1, ec_curve_t const *E2)
{
    fp2_copy(&(E1->A), &(E2->A));
    fp2_copy(&(E1->C), &(E2->C));
    E1->is_A24_computed_and_normalized = E2->is_A24_computed_and_normalized;
    copy_point(&E1->A24, &E2->A24);
}

void xDBL(ec_point_t *Q, ec_point_t const *P, ec_point_t const *AC)
{
    // This version computes the coefficient values A+2C and 4C on-the-fly
    // The curve coefficients are passed via AC = (A:C)
    fp2_t t0, t1, t2, t3;

    fp2_add(&t0, &P->x, &P->z);
    fp2_sqr(&t0, &t0);
    fp2_sub(&t1, &P->x, &P->z);
    fp2_sqr(&t1, &t1);
    fp2_sub(&t2, &t0, &t1);
    fp2_add(&t3, &AC->z, &AC->z);
    fp2_mul(&t1, &t1, &t3);
    fp2_add(&t1, &t1, &t1);
    fp2_mul(&Q->x, &t0, &t1);
    fp2_add(&t0, &t3, &AC->x);
    fp2_mul(&t0, &t0, &t2);
    fp2_add(&t0, &t0, &t1);
    fp2_mul(&Q->z, &t0, &t2);
}

void xDBL_A24(ec_point_t *Q, ec_point_t const *P, ec_point_t const *A24)
{
    // This version receives the coefficient value A24 = (A+2C:4C)
    fp2_t t0, t1, t2;

    fp2_add(&t0, &P->x, &P->z);
    fp2_sqr(&t0, &t0);
    fp2_sub(&t1, &P->x, &P->z);
    fp2_sqr(&t1, &t1);
    fp2_sub(&t2, &t0, &t1);
    fp2_mul(&t1, &t1, &A24->z);
    fp2_mul(&Q->x, &t0, &t1);
    fp2_mul(&t0, &t2, &A24->x);
    fp2_add(&t0, &t0, &t1);
    fp2_mul(&Q->z, &t0, &t2);
}

void xDBL_A24_normalized(ec_point_t *Q, ec_point_t const *P, ec_point_t const *A24)
{
    // This version receives the coefficient value A24 = (A+2C/4C:1)
    fp2_t t0, t1, t2;

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

void xADD(ec_point_t *R, ec_point_t const *P, ec_point_t const *Q, ec_point_t const *PQ)
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
    fp2_sqr(&t2, &t2);
    fp2_sqr(&t3, &t3);
    fp2_mul(&t2, &PQ->z, &t2);
    fp2_mul(&R->z, &PQ->x, &t3);
    fp2_copy(&R->x, &t2);
}

void xDBLADD(ec_point_t *R,
             ec_point_t *S,
             ec_point_t const *P,
             ec_point_t const *Q,
             ec_point_t const *PQ,
             ec_point_t const *A24)
{
    // Requires precomputation of A24 = (A+2C:4C)
    fp2_t t0, t1, t2;

    fp2_add(&t0, &P->x, &P->z);
    fp2_sub(&t1, &P->x, &P->z);
    fp2_sqr(&R->x, &t0);
    fp2_sub(&t2, &Q->x, &Q->z);
    fp2_add(&S->x, &Q->x, &Q->z);
    fp2_mul(&t0, &t0, &t2);
    fp2_sqr(&R->z, &t1);
    fp2_mul(&t1, &t1, &S->x);
    fp2_sub(&t2, &R->x, &R->z);
    fp2_mul(&R->z, &R->z, &A24->z);
    fp2_mul(&R->x, &R->x, &R->z);
    fp2_mul(&S->x, &A24->x, &t2);
    fp2_sub(&S->z, &t0, &t1);
    fp2_add(&R->z, &R->z, &S->x);
    fp2_add(&S->x, &t0, &t1);
    fp2_mul(&R->z, &R->z, &t2);
    fp2_sqr(&S->z, &S->z);
    fp2_sqr(&S->x, &S->x);
    fp2_mul(&S->z, &S->z, &PQ->x);
    fp2_mul(&S->x, &S->x, &PQ->z);
}

// assume that A24 has been normalized
void xDBLADD_normalized(ec_point_t *R,
                        ec_point_t *S,
                        ec_point_t const *P,
                        ec_point_t const *Q,
                        ec_point_t const *PQ,
                        ec_point_t const *A24)
{
    // Requires precomputation of A24 = (A+2C:4C)
    fp2_t t0, t1, t2;

    fp2_add(&t0, &P->x, &P->z);
    fp2_sub(&t1, &P->x, &P->z);
    fp2_sqr(&R->x, &t0);
    fp2_sub(&t2, &Q->x, &Q->z);
    fp2_add(&S->x, &Q->x, &Q->z);
    fp2_mul(&t0, &t0, &t2);
    fp2_sqr(&R->z, &t1);
    fp2_mul(&t1, &t1, &S->x);
    fp2_sub(&t2, &R->x, &R->z);
    fp2_mul(&R->x, &R->x, &R->z);
    fp2_mul(&S->x, &A24->x, &t2);
    fp2_sub(&S->z, &t0, &t1);
    fp2_add(&R->z, &R->z, &S->x);
    fp2_add(&S->x, &t0, &t1);
    fp2_mul(&R->z, &R->z, &t2);
    fp2_sqr(&S->z, &S->z);
    fp2_sqr(&S->x, &S->x);
    fp2_mul(&S->z, &S->z, &PQ->x);
    fp2_mul(&S->x, &S->x, &PQ->z);
}

bool is_point_equal(const ec_point_t *P, const ec_point_t *Q)
{ // Evaluate if two points in Montgomery coordinates (X:Z) are equal
  // Returns 1 (true) if P=Q, 0 (false) otherwise
    fp2_t t0, t1;

    if ((fp2_is_zero(&P->x) && fp2_is_zero(&P->z)) || (fp2_is_zero(&Q->x) && fp2_is_zero(&Q->z)))
    {
        return fp2_is_zero(&P->x) && fp2_is_zero(&P->z) && fp2_is_zero(&Q->x) && fp2_is_zero(&Q->z);
    }

    fp2_mul(&t0, &P->x, &Q->z);
    fp2_mul(&t1, &Q->x, &P->z);
    fp2_sub(&t0, &t0, &t1);

    return fp2_is_zero(&t0);
}

void select_point(ec_point_t *Q, ec_point_t const *P1, ec_point_t const *P2, const digit_t option)
{ // Select points
  // If option = 0 then Q <- P1, else if option = 0xFF...FF then Q <- P2
    fp2_select(&(Q->x), &(P1->x), &(P2->x), option);
    fp2_select(&(Q->z), &(P1->z), &(P2->z), option);
}

void swap_points(ec_point_t *P, ec_point_t *Q, const digit_t option)
{ // Swap points
  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then P <- Q and Q <- P
    fp2_cswap(&(P->x), &(Q->x), option);
    fp2_cswap(&(P->z), &(Q->z), option);
}

void copy_point(ec_point_t *P, ec_point_t const *Q)
{
    fp2_copy(&(P->x), &(Q->x));
    fp2_copy(&(P->z), &(Q->z));
}

void ec_neg(ec_point_t *res, const ec_point_t *P)
{
    // DOES NOTHING
    copy_point(res, P);
}

void xMUL(ec_point_t *Q, ec_point_t const *P, digit_t const *k, const int size, ec_curve_t const *curve)
{
    ec_point_t R0, R1, A24;
    digit_t mask;
    unsigned int bit = 0, prevbit = 0, swap;

    fp2_add(&A24.x, &curve->C, &curve->C); // Precomputation of A24=(A+2C:4C)
    fp2_add(&A24.z, &A24.x, &A24.x);
    fp2_add(&A24.x, &A24.x, &curve->A);

    // R0 <- (1:0), R1 <- P
    ec_point_init(&R0);
    fp2_copy(&R1.x, &P->x);
    fp2_copy(&R1.z, &P->z);
    // Main loop
    for (int i = RADIX * size - 1; i >= 0; i--)
    {
        bit = (k[i >> LOG2RADIX] >> (i & (RADIX - 1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        swap_points(&R0, &R1, mask);
        xDBLADD(&R0, &R1, &R0, &R1, P, &A24);
    }
    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    swap_points(&R0, &R1, mask);

    fp2_copy(&Q->x, &R0.x);
    fp2_copy(&Q->z, &R0.z);
}

void xMULv2(ec_point_t *Q, ec_point_t const *P, digit_t const *k, const int kbits, ec_point_t const *A24)
{
    // This version receives the coefficient value A24 = (A+2C:4C)
    ec_point_t R0, R1;
    digit_t mask;
    unsigned int bit = 0, prevbit = 0, swap;

    // R0 <- (1:0), R1 <- P
    ec_point_init(&R0);
    fp2_copy(&R1.x, &P->x);
    fp2_copy(&R1.z, &P->z);

    // Main loop
    for (int i = kbits - 1; i >= 0; i--)
    {
        bit = (k[i >> LOG2RADIX] >> (i & (RADIX - 1))) & 1;
        swap = bit ^ prevbit;
        prevbit = bit;
        mask = 0 - (digit_t)swap;

        swap_points(&R0, &R1, mask);
        xDBLADD(&R0, &R1, &R0, &R1, P, A24);
    }
    swap = 0 ^ prevbit;
    mask = 0 - (digit_t)swap;
    swap_points(&R0, &R1, mask);

    fp2_copy(&Q->x, &R0.x);
    fp2_copy(&Q->z, &R0.z);
}

// Compute S = k*P + l*Q, with PQ = P+Q
void xDBLMUL(ec_point_t *S,
             ec_point_t const *P,
             digit_t const *k,
             ec_point_t const *Q,
             digit_t const *l,
             ec_point_t const *PQ,
             const ec_curve_t *curve)
{

    int i;
    digit_t evens, mevens, bitk0, bitl0, maskk, maskl, temp, bs1_ip1, bs2_ip1, bs1_i, bs2_i, h;
    digit_t sigma[2] = {0}, pre_sigma = 0;
    digit_t k_t[NWORDS_ORDER], l_t[NWORDS_ORDER], one[NWORDS_ORDER] = {0}, r[2 * BITS] = {0};
    ec_point_t A24, DIFF1a, DIFF1b, DIFF2a, DIFF2b, R[3] = {0}, T[3];

    // Derive sigma according to parity
    bitk0 = (k[0] & 1);
    bitl0 = (l[0] & 1);
    maskk = 0 - bitk0; // Parity masks: 0 if even, otherwise 1...1
    maskl = 0 - bitl0;
    sigma[0] = (bitk0 ^ 1);
    sigma[1] = (bitl0 ^ 1);
    evens = sigma[0] + sigma[1]; // Count number of even scalars
    mevens =
        0 - (evens & 1); // Mask mevens <- 0 if # even scalars = 0 or 2, otherwise mevens = 1...1

    // If k and l are both even or both odd, pick sigma = (0,1)
    sigma[0] = (sigma[0] & mevens);
    sigma[1] = (sigma[1] & mevens) | (1 & ~mevens);

    // Convert even scalars to odd
    one[0] = 1;
    mp_sub(k_t, k, one, NWORDS_ORDER);
    mp_sub(l_t, l, one, NWORDS_ORDER);
    select_ct(k_t, k_t, k, maskk, NWORDS_ORDER);
    select_ct(l_t, l_t, l, maskl, NWORDS_ORDER);

    // Scalar recoding
    for (i = 0; i < BITS; i++)
    {
        // If sigma[0] = 1 swap k_t and l_t
        maskk = 0 - (sigma[0] ^ pre_sigma);
        swap_ct(k_t, l_t, maskk, NWORDS_ORDER);

        if (i == BITS - 1)
        {
            bs1_ip1 = 0;
            bs2_ip1 = 0;
        }
        else
        {
            bs1_ip1 = mp_shiftr(k_t, 1, NWORDS_ORDER);
            bs2_ip1 = mp_shiftr(l_t, 1, NWORDS_ORDER);
        }
        bs1_i = k_t[0] & 1;
        bs2_i = l_t[0] & 1;

        r[2 * i] = bs1_i ^ bs1_ip1;
        r[2 * i + 1] = bs2_i ^ bs2_ip1;

        // Revert sigma if second bit, r_(2i+1), is 1
        pre_sigma = sigma[0];
        maskk = 0 - r[2 * i + 1];
        select_ct(&temp, &sigma[0], &sigma[1], maskk, 1);
        select_ct(&sigma[1], &sigma[1], &sigma[0], maskk, 1);
        sigma[0] = temp;
    }

    // Point initialization
    ec_point_init(&R[0]);
    maskk = 0 - sigma[0];
    select_point(&R[1], P, Q, maskk);
    select_point(&R[2], Q, P, maskk);

    fp2_copy(&DIFF1a.x, &R[1].x);
    fp2_copy(&DIFF1a.z, &R[1].z);
    fp2_copy(&DIFF1b.x, &R[2].x);
    fp2_copy(&DIFF1b.z, &R[2].z);

    // Initialize DIFF2a <- P+Q, DIFF2b <- P-Q
    xADD(&R[2], &R[1], &R[2], PQ);
    fp2_copy(&DIFF2a.x, &R[2].x);
    fp2_copy(&DIFF2a.z, &R[2].z);
    fp2_copy(&DIFF2b.x, &PQ->x);
    fp2_copy(&DIFF2b.z, &PQ->z);
    // normalizing
    ec_curve_t E;
    copy_curve(&E, curve);
    ec_curve_normalize_A24(&E);
    copy_point(&A24, &E.A24);

    // Main loop
    for (i = BITS - 1; i >= 0; i--)
    {
        h = r[2 * i] + r[2 * i + 1]; // in {0, 1, 2}
        maskk = 0 - (h & 1);
        select_point(&T[0], &R[0], &R[1], maskk);
        maskk = 0 - (h >> 1);
        select_point(&T[0], &T[0], &R[2], maskk);
        xDBL_A24_normalized(&T[0], &T[0], &A24);

        maskk = 0 - r[2 * i + 1]; // in {0, 1}
        select_point(&T[1], &R[0], &R[1], maskk);
        select_point(&T[2], &R[1], &R[2], maskk);

        swap_points(&DIFF1a, &DIFF1b, maskk);
        xADD(&T[1], &T[1], &T[2], &DIFF1a);
        xADD(&T[2], &R[0], &R[2], &DIFF2a);

        // If hw (mod 2) = 1 then swap DIFF2a and DIFF2b
        maskk = 0 - (h & 1);
        swap_points(&DIFF2a, &DIFF2b, maskk);

        // R <- T
        copy_point(&R[0], &T[0]);
        copy_point(&R[1], &T[1]);
        copy_point(&R[2], &T[2]);
    }

    // Output R[evens]
    select_point(S, &R[0], &R[1], mevens);

    maskk = 0 - (bitk0 & bitl0);
    select_point(S, S, &R[2], maskk);
}

void xDBLMUL_bounded(ec_point_t *S,
                     ec_point_t const *P,
                     digit_t const *k,
                     ec_point_t const *Q,
                     digit_t const *l,
                     ec_point_t const *PQ,
                     const ec_curve_t *curve,
                     int size)
{

    int i;
    digit_t evens, mevens, bitk0, bitl0, maskk, maskl, temp, bs1_ip1, bs2_ip1, bs1_i, bs2_i, h;
    digit_t sigma[2] = {0}, pre_sigma = 0;
    digit_t k_t[NWORDS_ORDER], l_t[NWORDS_ORDER], one[NWORDS_ORDER] = {0}, r[2 * BITS] = {0};
    ec_point_t A24, DIFF1a, DIFF1b, DIFF2a, DIFF2b, R[3] = {0}, T[3];

    // Derive sigma according to parity
    bitk0 = (k[0] & 1);
    bitl0 = (l[0] & 1);
    maskk = 0 - bitk0; // Parity masks: 0 if even, otherwise 1...1
    maskl = 0 - bitl0;
    sigma[0] = (bitk0 ^ 1);
    sigma[1] = (bitl0 ^ 1);
    evens = sigma[0] + sigma[1]; // Count number of even scalars
    mevens =
        0 - (evens & 1); // Mask mevens <- 0 if # even scalars = 0 or 2, otherwise mevens = 1...1

    // If k and l are both even or both odd, pick sigma = (0,1)
    sigma[0] = (sigma[0] & mevens);
    sigma[1] = (sigma[1] & mevens) | (1 & ~mevens);

    // Convert even scalars to odd
    one[0] = 1;
    mp_sub(k_t, k, one, NWORDS_ORDER);
    mp_sub(l_t, l, one, NWORDS_ORDER);
    select_ct(k_t, k_t, k, maskk, NWORDS_ORDER);
    select_ct(l_t, l_t, l, maskl, NWORDS_ORDER);

    // Scalar recoding
    for (i = 0; i < BITS; i++)
    {
        // If sigma[0] = 1 swap k_t and l_t
        maskk = 0 - (sigma[0] ^ pre_sigma);
        swap_ct(k_t, l_t, maskk, NWORDS_ORDER);

        if (i == BITS - 1)
        {
            bs1_ip1 = 0;
            bs2_ip1 = 0;
        }
        else
        {
            bs1_ip1 = mp_shiftr(k_t, 1, NWORDS_ORDER);
            bs2_ip1 = mp_shiftr(l_t, 1, NWORDS_ORDER);
        }
        bs1_i = k_t[0] & 1;
        bs2_i = l_t[0] & 1;

        r[2 * i] = bs1_i ^ bs1_ip1;
        r[2 * i + 1] = bs2_i ^ bs2_ip1;

        // Revert sigma if second bit, r_(2i+1), is 1
        pre_sigma = sigma[0];
        maskk = 0 - r[2 * i + 1];
        select_ct(&temp, &sigma[0], &sigma[1], maskk, 1);
        select_ct(&sigma[1], &sigma[1], &sigma[0], maskk, 1);
        sigma[0] = temp;
    }

    // Point initialization
    ec_point_init(&R[0]);
    maskk = 0 - sigma[0];
    select_point(&R[1], P, Q, maskk);
    select_point(&R[2], Q, P, maskk);

    fp2_copy(&DIFF1a.x, &R[1].x);
    fp2_copy(&DIFF1a.z, &R[1].z);
    fp2_copy(&DIFF1b.x, &R[2].x);
    fp2_copy(&DIFF1b.z, &R[2].z);

    // Initialize DIFF2a <- P+Q, DIFF2b <- P-Q
    xADD(&R[2], &R[1], &R[2], PQ);
    fp2_copy(&DIFF2a.x, &R[2].x);
    fp2_copy(&DIFF2a.z, &R[2].z);
    fp2_copy(&DIFF2b.x, &PQ->x);
    fp2_copy(&DIFF2b.z, &PQ->z);

    // normalizing
    ec_curve_t E;
    copy_curve(&E, curve);
    ec_curve_normalize_A24(&E);
    copy_point(&A24, &E.A24);

    // T <- R
    copy_point(&T[0], &R[0]);
    copy_point(&T[1], &R[1]);
    copy_point(&T[2], &R[2]);

    // Main loop
    for (i = BITS - 1; i >= 0; i--)
    {

        // TODO : clean this
        // this is an ugly fix to avoid unnecessary operations
        bool apply = (i <= size * RADIX + 2);

        h = r[2 * i] + r[2 * i + 1]; // in {0, 1, 2}
        maskk = 0 - (h & 1);
        if (apply)
        {
            select_point(&T[0], &R[0], &R[1], maskk);
        }

        maskk = 0 - (h >> 1);

        if (apply)
        {
            select_point(&T[0], &T[0], &R[2], maskk);
            xDBL_A24_normalized(&T[0], &T[0], &A24);
        }

        maskk = 0 - r[2 * i + 1]; // in {0, 1}
        if (apply)
        {
            select_point(&T[1], &R[0], &R[1], maskk);
            select_point(&T[2], &R[1], &R[2], maskk);
        }

        swap_points(&DIFF1a, &DIFF1b, maskk);
        if (apply)
        {
            xADD(&T[1], &T[1], &T[2], &DIFF1a);
            xADD(&T[2], &R[0], &R[2], &DIFF2a);
        }

        // If hw (mod 2) = 1 then swap DIFF2a and DIFF2b
        maskk = 0 - (h & 1);
        swap_points(&DIFF2a, &DIFF2b, maskk);

        // R <- T
        copy_point(&R[0], &T[0]);
        copy_point(&R[1], &T[1]);
        copy_point(&R[2], &T[2]);
    }

    // Output R[evens]
    select_point(S, &R[0], &R[1], mevens);

    maskk = 0 - (bitk0 & bitl0);
    select_point(S, S, &R[2], maskk);
}

void ec_ladder3pt_bounded(ec_point_t *R,
                          digit_t *const m,
                          ec_point_t const *P,
                          ec_point_t const *Q,
                          ec_point_t const *PQ,
                          ec_curve_t const *A,
                          int size)
{
    ec_point_t X0, X1, X2;
    copy_point(&X0, Q);
    copy_point(&X1, P);
    copy_point(&X2, PQ);

    int i, j;
    uint64_t t;
    for (i = 0; i < size; i++)
    {
        t = 1;
        for (j = 0; j < 64; j++)
        {
            swap_points(&X1, &X2, -((t & m[i]) == 0));
            xDBLADD_normalized(&X0, &X1, &X0, &X1, &X2, &A->A24);
            swap_points(&X1, &X2, -((t & m[i]) == 0));
            t <<= 1;
        };
    };
    copy_point(R, &X1);
}

static void
jac_init(jac_point_t *P)
{ // Initialize Montgomery in Jacobian coordinates as identity element (0:1:0)
    fp2_set_zero(&(P->x));
    fp2_set_one(&(P->y));
    fp2_set_zero(&(P->z));
}

bool is_jac_equal(const jac_point_t *P, const jac_point_t *Q)
{ // Evaluate if two points in Jacobian coordinates (X:Y:Z) are equal
  // Returns 1 (true) if P=Q, 0 (false) otherwise
    fp2_t t0, t1, t2, t3;

    fp2_sqr(&t0, &Q->z);
    fp2_mul(&t2, &P->x, &t0); // x1*z2^2
    fp2_sqr(&t1, &P->z);
    fp2_mul(&t3, &Q->x, &t1); // x2*z1^2
    fp2_sub(&t2, &t2, &t3);

    fp2_mul(&t0, &t0, &Q->z);
    fp2_mul(&t0, &P->y, &t0); // y1*z2^3
    fp2_mul(&t1, &t1, &P->z);
    fp2_mul(&t1, &Q->y, &t1); // y2*z1^3
    fp2_sub(&t0, &t0, &t1);

    return fp2_is_zero(&t0) && fp2_is_zero(&t2);
}

void jac_to_xz(ec_point_t *P, const jac_point_t *xyP)
{
    fp2_copy(&P->x, &xyP->x);
    fp2_copy(&P->z, &xyP->z);
    fp2_sqr(&P->z, &P->z);
}

bool is_jac_xz_equal(const jac_point_t *P, const ec_point_t *Q)
{ // Evaluate if point P in Jacobian coordinates is equal to Q in homogeneous projective coordinates
  // (X:Z) Comparison is up to sign (only compares X and Z coordinates) Returns 1 (true) if P=Q, 0
  // (false) otherwise
    fp2_t t0, t1;

    fp2_mul(&t0, &P->x, &Q->z); // x1*z2
    fp2_sqr(&t1, &P->z);
    fp2_mul(&t1, &Q->x, &t1); // x2*z1^2
    fp2_sub(&t0, &t0, &t1);

    return fp2_is_zero(&t0);
}

void copy_jac_point(jac_point_t *P, jac_point_t const *Q)
{
    fp2_copy(&(P->x), &(Q->x));
    fp2_copy(&(P->y), &(Q->y));
    fp2_copy(&(P->z), &(Q->z));
}

void jac_neg(jac_point_t *Q, jac_point_t const *P)
{
    fp2_copy(&Q->x, &P->x);
    fp2_neg(&Q->y, &P->y);
    fp2_copy(&Q->z, &P->z);
}

void DBL(jac_point_t *Q, jac_point_t const *P, ec_curve_t const *AC)
{ // Doubling on a Montgomery curve, representation in Jacobian coordinates (X:Y:Z) corresponding to
  // (X/Z^2,Y/Z^3) This version receives the coefficient value A
    fp2_t t0, t1, t2, t3;

    if (fp2_is_zero(&P->x) && fp2_is_zero(&P->z))
    {
        jac_init(Q);
        return;
    }

    fp2_sqr(&t0, &P->x); // t0 = x1^2
    fp2_add(&t1, &t0, &t0);
    fp2_add(&t0, &t0, &t1); // t0 = 3x1^2
    fp2_sqr(&t1, &P->z);    // t1 = z1^2
    fp2_mul(&t2, &P->x, &AC->A);
    fp2_add(&t2, &t2, &t2); // t2 = 2Ax1
    fp2_add(&t2, &t1, &t2); // t2 = 2Ax1+z1^2
    fp2_mul(&t2, &t1, &t2); // t2 = z1^2(2Ax1+z1^2)
    fp2_add(&t2, &t0, &t2); // t2 = alpha = 3x1^2 + z1^2(2Ax1+z1^2)
    fp2_mul(&Q->z, &P->y, &P->z);
    fp2_add(&Q->z, &Q->z, &Q->z); // z2 = 2y1z1
    fp2_sqr(&t0, &Q->z);
    fp2_mul(&t0, &t0, &AC->A); // t0 = 4Ay1^2z1^2
    fp2_sqr(&t1, &P->y);
    fp2_add(&t1, &t1, &t1);     // t1 = 2y1^2
    fp2_add(&t3, &P->x, &P->x); // t3 = 2x1
    fp2_mul(&t3, &t1, &t3);     // t3 = 4x1y1^2
    fp2_sqr(&Q->x, &t2);        // x2 = alpha^2
    fp2_sub(&Q->x, &Q->x, &t0); // x2 = alpha^2 - 4Ay1^2z1^2
    fp2_sub(&Q->x, &Q->x, &t3);
    fp2_sub(&Q->x, &Q->x, &t3); // x2 = alpha^2 - 4Ay1^2z1^2 - 8x1y1^2
    fp2_sub(&Q->y, &t3, &Q->x); // y2 = 4x1y1^2 - x2
    fp2_mul(&Q->y, &Q->y, &t2); // y2 = alpha(4x1y1^2 - x2)
    fp2_sqr(&t1, &t1);          // t1 = 4y1^4
    fp2_sub(&Q->y, &Q->y, &t1);
    fp2_sub(&Q->y, &Q->y, &t1); // y2 = alpha(4x1y1^2 - x2) - 8y1^4
}

void ADD(jac_point_t *R, jac_point_t const *P, jac_point_t const *Q, ec_curve_t const *AC)
{ // Addition on a Montgomery curve, representation in Jacobian coordinates (X:Y:Z) corresponding to
  // (X/Z^2,Y/Z^3) This version receives the coefficient value A
    fp2_t t0, t1, t2, t3, t4, t5, t6;
    jac_point_t T;

    if (is_jac_equal(P, Q))
    {
        DBL(R, P, AC);
        return;
    }
    jac_neg(&T, P);
    if (is_jac_equal(&T, Q))
    {
        jac_init(R);
        return;
    }
    if (fp2_is_zero(&P->x) && fp2_is_zero(&P->z))
    {
        copy_jac_point(R, Q);
        return;
    }
    else if (fp2_is_zero(&Q->x) && fp2_is_zero(&Q->z))
    {
        copy_jac_point(R, P);
        return;
    }

    fp2_sqr(&t0, &P->z);        // t0 = z1^2
    fp2_mul(&t1, &t0, &P->z);   // t1 = z1^3
    fp2_sqr(&t2, &Q->z);        // t2 = z2^2
    fp2_mul(&t3, &t2, &Q->z);   // t3 = z2^3
    fp2_mul(&t1, &t1, &Q->y);   // t1 = y2z1^3
    fp2_mul(&t3, &t3, &P->y);   // t3 = y1z2^3
    fp2_sub(&t1, &t1, &t3);     // t1 = lambda1 = y2z1^3 - y1z2^3
    fp2_mul(&t0, &t0, &Q->x);   // t0 = x2z1^2
    fp2_mul(&t2, &t2, &P->x);   // t2 = x1z2^2
    fp2_sub(&t4, &t0, &t2);     // t4 = lambda3 = x2z1^2 - x1z2^2
    fp2_add(&t0, &t0, &t2);     // t0 = lambda2 = x2z1^2 + x1z2^2
    fp2_mul(&t5, &P->z, &Q->z); // t5 = z1z2
    fp2_mul(&R->z, &t4, &t5);   // z3 = z1z2*lambda3
    fp2_sqr(&t5, &t5);          // t5 = z1^2z2^2
    fp2_mul(&t5, &AC->A, &t5);  // t5 = Az1^2z2^2
    fp2_add(&t0, &t0, &t5);     // t0 = Az1^2z2^2 + lambda2
    fp2_sqr(&t6, &t4);          // t6 = lambda3^2
    fp2_mul(&t5, &t0, &t6);     // t5 = lambda3^2(Az1^2z2^2 + lambda2)
    fp2_sqr(&R->x, &t1);        // x3 = lambda1^2
    fp2_sub(&R->x, &R->x, &t5); // x3 = lambda1^2 - lambda3^2(Az1^2z2^2 + lambda2)
    fp2_mul(&t3, &t3, &t4);     // t3 = y1z2^3*lambda3
    fp2_mul(&t3, &t3, &t6);     // t3 = y1z2^3*lambda3^3
    fp2_mul(&t2, &t2, &t6);     // t2 = x1z2^2*lambda3^2
    fp2_sub(&R->y, &t2, &R->x); // y3 = x1z2^2*lambda3^2 - x3
    fp2_mul(&R->y, &R->y, &t1); // y3 = lambda1(x1z2^2*lambda3^2 - x3)
    fp2_sub(&R->y, &R->y, &t3); // y3 = lambda1(x1z2^2*lambda3^2 - x3) - y1z2^3*lambda3^3
}

void recover_y(fp2_t *y, fp2_t const *Px, ec_curve_t const *curve)
{ // Recover y-coordinate of a point on the Montgomery curve y^2 = x^3 + Ax^2 + x
    fp2_t t0;

    fp2_sqr(&t0, Px);
    fp2_mul(y, &t0, &curve->A); // Ax^2
    fp2_add(y, y, Px);          // Ax^2 + x
    fp2_mul(&t0, &t0, Px);
    fp2_add(y, y, &t0); // x^3 + Ax^2 + x
    fp2_sqrt(y);
}

void recover_domain(ec_curve_t *E, const ec_point_t *P, const ec_point_t *Q, const ec_point_t *PmQ)
{
    fp2_t x12, x123, z12, z123, xz12, xz23, xz31, xz123, xz213, xz312, tmp1, tmp2;
    fp2_mul(&x12, &P->x, &Q->x);
    fp2_mul(&x123, &PmQ->x, &x12);
    fp2_mul(&xz12, &P->x, &Q->z);
    fp2_mul(&xz23, &Q->x, &PmQ->z);
    fp2_mul(&xz31, &PmQ->x, &P->z);
    fp2_mul(&xz123, &xz12, &PmQ->z);
    fp2_mul(&xz213, &xz23, &P->z);
    fp2_mul(&xz312, &xz31, &Q->z);
    fp2_sub(&tmp1, &P->x, &P->z);     // t1 = x1-z1
    fp2_sub(&tmp2, &Q->x, &Q->z);     // t2 = x2-z2
    fp2_mul(&tmp1, &tmp2, &tmp1);     // t1=(x1-z1)(x2-z2)
    fp2_sub(&tmp2, &PmQ->x, &PmQ->z); // t1 = x3-z3
    fp2_mul(&E->A, &tmp1, &tmp2);     // A=(x1-z1)(x2-z2)(x3-z3)
    fp2_add(&tmp1, &xz123, &xz213);   // t1=x1z2z3+x2z1z3
    fp2_add(&tmp1, &tmp1, &xz312);    // t1=x1z2z3+x2z1z3+x3z1z2
    fp2_sub(&E->A, &E->A, &x123);     // A=(x1-z1)(x2-z2)(x3-z3)-x1x2x3
    fp2_sub(&E->A, &E->A, &tmp1);     // A=(x1-z1)(x2-z2)(x3-z3)-x1x2x3-(x1z2z3+x2z1z3+x3z1z2)
    fp2_mul(&z12, &P->z, &Q->z);      // z12=z1z2
    fp2_mul(&z123, &PmQ->z, &z12);    // z123=z1z2z3
    fp2_add(&x123, &x123, &x123);     // x123=2x1x2x3
    fp2_add(&x123, &x123, &x123);     // x123=4x1x2x3
    fp2_mul(&E->C, &x123, &z123);     // C=4x1x2x3z1z2z3
    fp2_mul(&tmp1, &tmp1, &x123);     // t1=4x1x2x3*(x1z2z3+x2z1z3+x3z1z2)
    fp2_add(&z123, &z123, &z123);     // z123=2z1z2z3
    fp2_add(&E->A, &E->A, &z123);     // A=(x1-z1)(x2-z2)(x3-z3)-x1x2x3-(x1z2z3+x2z1z3+x3z1z2)+2z1z2z3
    fp2_sqr(&E->A, &E->A);            // A=A^2
    fp2_sub(&E->A, &E->A, &tmp1);     // A=A^2-4x1x2x3*(x1z2z3+x2z1z3+x3z1z2)
    E->is_A24_computed_and_normalized = 0;
};

void DBLMUL(jac_point_t *R,
            const jac_point_t *P,
            const digit_t k,
            const jac_point_t *Q,
            const digit_t l,
            const ec_curve_t *curve)
{ // Double-scalar multiplication R <- k*P + l*Q, fixed for 64-bit scalars
    digit_t k_t, l_t;
    jac_point_t PQ;

    ADD(&PQ, P, Q, curve);
    jac_init(R);

    for (int i = 0; i < 64; i++)
    {
        k_t = k >> (63 - i);
        k_t &= 0x01;
        l_t = l >> (63 - i);
        l_t &= 0x01;
        DBL(R, R, curve);
        if (k_t == 1 && l_t == 1)
        {
            ADD(R, R, &PQ, curve);
        }
        else if (k_t == 1)
        {
            ADD(R, R, P, curve);
        }
        else if (l_t == 1)
        {
            ADD(R, R, Q, curve);
        }
    }
}

#define SCALAR_BITS 128 //// TODO: this could be defined by level

static void
ec_dlog_2_step(digit_t *x,
               digit_t *y,
               const jac_point_t *R,
               const int f,
               const int B,
               const jac_point_t *Pe2,
               const jac_point_t *Qe2,
               const jac_point_t *PQe2,
               const ec_curve_t *curve)
{ // Based on Montgomery formulas using Jacobian coordinates
    int i, j;
    digit_t value = 1;
    jac_point_t P, Q, TT, SS, PQp, T[(POWER_OF_2 - 1) / 2],
        Re[(POWER_OF_2 - 1) / 2]; // Storage could be reduced to e1 points

    *x = 0;
    *y = 0;

    // printf(" ec_dlog_2_step on size %d \n", f);

    copy_jac_point(&P, &Pe2[f - 1]);
    copy_jac_point(&Q, &Qe2[f - 1]);
    copy_jac_point(&Re[f - 1], R);

    for (i = 0; i < (f - 1); i++)
    {
        DBL(&Re[f - i - 2], &Re[f - i - 1], curve);
    }
    ADD(&PQp, &P, &Q, curve);

    // Unrolling the first two iterations
    if (is_jac_equal(&Pe2[0], &Re[0]))
    {
        *x += 1;
        copy_jac_point(&T[0], &P);
        for (j = 3; j <= B; j++)
        {
            copy_jac_point(&T[j - 1], &Pe2[j - 1]);
        }
        jac_neg(&TT, &Pe2[1]);
        ADD(&Re[0], &Re[1], &TT, curve);
    }
    else if (is_jac_equal(&Qe2[0], &Re[0]))
    {
        *y += 1;
        copy_jac_point(&T[0], &Q);
        for (j = 3; j <= B; j++)
        {
            copy_jac_point(&T[j - 1], &Qe2[j - 1]);
        }
        jac_neg(&TT, &Qe2[1]);
        ADD(&Re[0], &Re[1], &TT, curve);
    }
    else if (is_jac_equal(&PQe2[0], &Re[0]))
    {
        *x += 1;
        *y += 1;
        copy_jac_point(&T[0], &PQp);
        for (j = 3; j <= B; j++)
        {
            copy_jac_point(&T[j - 1], &PQe2[j - 1]);
        }
        jac_neg(&TT, &PQe2[1]);
        ADD(&Re[0], &Re[1], &TT, curve);
    }
    else
    {
        jac_init(&T[0]);
        for (j = 3; j <= B; j++)
        {
            jac_init(&T[j - 1]);
        }
        copy_jac_point(&Re[0], &Re[1]);
    }

    // Unrolling iterations 3-B
    for (i = 3; i <= B; i++)
    {
        value <<= 1;
        jac_neg(&TT, &T[i - 1]);
        ADD(&TT, &Re[i - 1], &TT, curve); // TT <- Re[i-1]-T[i-1]
        if (is_jac_equal(&Pe2[0], &Re[0]))
        {
            *x += value;
            ADD(&T[0], &T[0], &Pe2[f - i + 1], curve);
            for (j = i + 1; j <= B; j++)
            {
                ADD(&T[j - 1], &T[j - 1], &Pe2[j - i + 1], curve);
            }
            jac_neg(&SS, &Pe2[1]);
            ADD(&Re[0], &TT, &SS, curve);
        }
        else if (is_jac_equal(&Qe2[0], &Re[0]))
        {
            *y += value;
            ADD(&T[0], &T[0], &Qe2[f - i + 1], curve);
            for (j = i + 1; j <= B; j++)
            {
                ADD(&T[j - 1], &T[j - 1], &Qe2[j - i + 1], curve);
            }
            jac_neg(&SS, &Qe2[1]);
            ADD(&Re[0], &TT, &SS, curve);
        }
        else if (is_jac_equal(&PQe2[0], &Re[0]))
        {
            *x += value;
            *y += value;
            ADD(&T[0], &T[0], &PQe2[f - i + 1], curve);
            for (j = i + 1; j <= B; j++)
            {
                ADD(&T[j - 1], &T[j - 1], &PQe2[j - i + 1], curve);
            }
            jac_neg(&SS, &PQe2[1]);
            ADD(&Re[0], &TT, &SS, curve);
        }
        else
        {
            copy_jac_point(&Re[0], &TT);
        }
    }

    // Main Loop
    for (i = B; i < f; i++)
    {
        value <<= 1;
        if (is_jac_equal(&Pe2[0], &Re[0]))
        {
            *x += value;
            ADD(&T[0], &T[0], &Pe2[f - i], curve);
        }
        else if (is_jac_equal(&Qe2[0], &Re[0]))
        {
            *y += value;
            ADD(&T[0], &T[0], &Qe2[f - i], curve);
        }
        else if (is_jac_equal(&PQe2[0], &Re[0]))
        {
            *x += value;
            *y += value;
            ADD(&T[0], &T[0], &PQe2[f - i], curve);
        }
        jac_neg(&TT, &T[0]);
        ADD(&Re[0], R, &TT, curve); // TT <- R-T[0]
        for (j = 0; j < (f - i - 1); j++)
        {
            DBL(&Re[0], &Re[0], curve);
        }
    }
    value <<= 1;
    if (is_jac_equal(&Pe2[0], &Re[0]))
    {
        *x += value;
    }
    else if (is_jac_equal(&Qe2[0], &Re[0]))
    {
        *y += value;
    }
    else if (is_jac_equal(&PQe2[0], &Re[0]))
    {
        *x += value;
        *y += value;
    }
}

void ec_dlog_2(digit_t *scalarP,
               digit_t *scalarQ,
               const ec_basis_t *PQ2,
               const ec_point_t *R,
               const ec_curve_t *curve)
{ // Optimized implementation based on Montgomery formulas using Jacobian coordinates

    // printf(" ec_dlog_2 %d %d %d\n", POWER_OF_2, NWORDS_ORDER, RADIX);

    int i;
    digit_t w0 = 0, z0 = 0, x0 = 0, y0 = 0, x1 = 0, y1 = 0, w1 = 0, z1 = 0, e, ediv2, e1, f, f1, f2,
            f2div2, f22, w, z;
    digit_t fp2[NWORDS_ORDER] = {1}, xx[NWORDS_ORDER] = {0}, yy[NWORDS_ORDER] = {0},
            ww[NWORDS_ORDER] = {0}, zz[NWORDS_ORDER] = {0};
    digit_t f22_p[NWORDS_ORDER] = {0}, w_p[NWORDS_ORDER] = {0}, z_p[NWORDS_ORDER] = {0},
            x0_p[NWORDS_ORDER] = {0}, y0_p[NWORDS_ORDER] = {0}, w0_p[NWORDS_ORDER] = {0},
            z0_p[NWORDS_ORDER] = {0};
    jac_point_t P, Q, RR, TT, R2r0, R2r, R2r1;
    jac_point_t Pe2[POWER_OF_2], Qe2[POWER_OF_2], PQe2[POWER_OF_2];
    ec_point_t Rnorm;
    ec_curve_t curvenorm;
    ec_basis_t PQ2norm;

    if (ec_is_zero(R))
    {
        memset(scalarP, 0, NWORDS_ORDER * RADIX / 8);
        memset(scalarQ, 0, NWORDS_ORDER * RADIX / 8);
        return;
    }

    ec_curve_init(&curvenorm);

    f = POWER_OF_2;
    memset(scalarP, 0, NWORDS_ORDER * RADIX / 8);
    memset(scalarQ, 0, NWORDS_ORDER * RADIX / 8);

    // printf("POWER_OF_2 : %d\n", POWER_OF_2);
    multiple_mp_shiftl(fp2, POWER_OF_2 - 1, NWORDS_ORDER);

    // Normalize R,PQ2,curve
    fp2_t D;
    fp2_mul(&D, &PQ2->P.z, &PQ2->Q.z);
    fp2_mul(&D, &D, &PQ2->PmQ.z);
    fp2_mul(&D, &D, &R->z);
    fp2_mul(&D, &D, &curve->C);
    fp2_inv(&D);
    fp2_set_one(&Rnorm.z);
    fp2_copy(&PQ2norm.P.z, &Rnorm.z);
    fp2_copy(&PQ2norm.Q.z, &Rnorm.z);
    fp2_copy(&PQ2norm.PmQ.z, &Rnorm.z);
    fp2_copy(&curvenorm.C, &Rnorm.z);
    fp2_mul(&Rnorm.x, &R->x, &D);
    fp2_mul(&Rnorm.x, &Rnorm.x, &PQ2->P.z);
    fp2_mul(&Rnorm.x, &Rnorm.x, &PQ2->Q.z);
    fp2_mul(&Rnorm.x, &Rnorm.x, &PQ2->PmQ.z);
    fp2_mul(&Rnorm.x, &Rnorm.x, &curve->C);
    fp2_mul(&PQ2norm.P.x, &PQ2->P.x, &D);
    fp2_mul(&PQ2norm.P.x, &PQ2norm.P.x, &R->z);
    fp2_mul(&PQ2norm.P.x, &PQ2norm.P.x, &PQ2->Q.z);
    fp2_mul(&PQ2norm.P.x, &PQ2norm.P.x, &PQ2->PmQ.z);
    fp2_mul(&PQ2norm.P.x, &PQ2norm.P.x, &curve->C);
    fp2_mul(&PQ2norm.Q.x, &PQ2->Q.x, &D);
    fp2_mul(&PQ2norm.Q.x, &PQ2norm.Q.x, &R->z);
    fp2_mul(&PQ2norm.Q.x, &PQ2norm.Q.x, &PQ2->P.z);
    fp2_mul(&PQ2norm.Q.x, &PQ2norm.Q.x, &PQ2->PmQ.z);
    fp2_mul(&PQ2norm.Q.x, &PQ2norm.Q.x, &curve->C);
    fp2_mul(&PQ2norm.PmQ.x, &PQ2->PmQ.x, &D);
    fp2_mul(&PQ2norm.PmQ.x, &PQ2norm.PmQ.x, &R->z);
    fp2_mul(&PQ2norm.PmQ.x, &PQ2norm.PmQ.x, &PQ2->P.z);
    fp2_mul(&PQ2norm.PmQ.x, &PQ2norm.PmQ.x, &PQ2->Q.z);
    fp2_mul(&PQ2norm.PmQ.x, &PQ2norm.PmQ.x, &curve->C);
    fp2_mul(&curvenorm.A, &curve->A, &D);
    fp2_mul(&curvenorm.A, &curvenorm.A, &R->z);
    fp2_mul(&curvenorm.A, &curvenorm.A, &PQ2->P.z);
    fp2_mul(&curvenorm.A, &curvenorm.A, &PQ2->Q.z);
    fp2_mul(&curvenorm.A, &curvenorm.A, &PQ2->PmQ.z);

    recover_y(&P.y, &PQ2norm.P.x, &curvenorm);
    fp2_copy(&P.x, &PQ2norm.P.x);
    fp2_copy(&P.z, &PQ2norm.P.z);
    recover_y(&Q.y, &PQ2norm.Q.x, &curvenorm); // TODO: THIS SECOND SQRT CAN BE ELIMINATED
    fp2_copy(&Q.x, &PQ2norm.Q.x);
    fp2_copy(&Q.z, &PQ2norm.Q.z);
    recover_y(&RR.y, &Rnorm.x, &curvenorm);
    fp2_copy(&RR.x, &Rnorm.x);
    fp2_copy(&RR.z, &Rnorm.z);

    jac_neg(&TT, &Q);
    ADD(&TT, &P, &TT, &curvenorm);
    if (!is_jac_xz_equal(&TT, &PQ2norm.PmQ))
        jac_neg(&Q, &Q);

    // Computing torsion-2^f points, multiples of P, Q and P+Q
    copy_jac_point(&Pe2[POWER_OF_2 - 1], &P);
    copy_jac_point(&Qe2[POWER_OF_2 - 1], &Q);
    ADD(&PQe2[POWER_OF_2 - 1], &P, &Q, &curvenorm); // P+Q

    for (i = 0; i < (POWER_OF_2 - 1); i++)
    {
        DBL(&Pe2[POWER_OF_2 - i - 2], &Pe2[POWER_OF_2 - i - 1], &curvenorm);
        DBL(&Qe2[POWER_OF_2 - i - 2], &Qe2[POWER_OF_2 - i - 1], &curvenorm);
        DBL(&PQe2[POWER_OF_2 - i - 2], &PQe2[POWER_OF_2 - i - 1], &curvenorm);
    }

    e = 0;
    const unsigned int TWOe = 64;
    ediv2 = 32;
    while (e * TWOe + TWOe < f)
    {
        copy_jac_point(&TT, &RR);
        for (i = 0; i < f - ((e + 1) * TWOe); i++)
        {
            DBL(&TT, &TT, &curvenorm);
        }

        // w0, z0 <- dlog2(2^(f-(e+1)<<6)*R, f1, f1 div 2)
        ec_dlog_2_step(&w0, &z0, &TT, (int)TWOe, (int)ediv2, &Pe2[0], &Qe2[0], &PQe2[0], &curvenorm);

        // RR <- RR - (w0 * Pe2[f-1] + z0 * Qe2[f-1])
        DBLMUL(&R2r0, &Pe2[f - e * TWOe - 1], w0, &Qe2[f - e * TWOe - 1], z0, &curvenorm);
        jac_neg(&R2r0, &R2r0);
        ADD(&RR, &RR, &R2r0, &curvenorm);

        memset(ww, 0, NWORDS_ORDER * RADIX / 8);
        memset(zz, 0, NWORDS_ORDER * RADIX / 8);
        ww[0] = w0;
        zz[0] = z0;
        // printf("w0, z0 : %lx %lx\n", w0, z0);
        for (int i = 0; i < e; i++)
        {
            multiple_mp_shiftl(&ww[0], TWOe, NWORDS_ORDER);
            multiple_mp_shiftl(&zz[0], TWOe, NWORDS_ORDER);
        }

        mp_add(scalarP, scalarP, &ww[0], NWORDS_ORDER);
        mp_add(scalarQ, scalarQ, &zz[0], NWORDS_ORDER);
        e++;
    }

    digit_t rest;
    copy_jac_point(&TT, &RR);
    rest = f - e * TWOe;
    // w0, z0 <- dlog2(R, f1, f1 div 2)
    ec_dlog_2_step(&w0, &z0, &TT, (int)rest, (int)(rest >> 1), &Pe2[0], &Qe2[0], &PQe2[0], &curvenorm);

    // RR <- RR - (w0 * Pe2[f-1] + z0 * Qe2[f-1])
    DBLMUL(&R2r0, &Pe2[f - e * TWOe - 1], w0, &Qe2[f - e * TWOe - 1], z0, &curvenorm);
    jac_neg(&R2r0, &R2r0);
    ADD(&RR, &RR, &R2r0, &curvenorm);

    memset(ww, 0, NWORDS_ORDER * RADIX / 8);
    memset(zz, 0, NWORDS_ORDER * RADIX / 8);
    ww[0] = w0;
    zz[0] = z0;
    // printf("w0, z0 : %lx %lx\n", w0, z0);
    for (int i = 0; i < e; i++)
    {
        multiple_mp_shiftl(&ww[0], TWOe, NWORDS_ORDER);
        multiple_mp_shiftl(&zz[0], TWOe, NWORDS_ORDER);
    }

    mp_add(scalarP, scalarP, &ww[0], NWORDS_ORDER);
    mp_add(scalarQ, scalarQ, &zz[0], NWORDS_ORDER);

    // If scalarP > 2^(f-1) or (scalarQ > 2^(f-1) and (scalarP = 0 or scalarP = 2^(f-1))) then
    // output -scalarP mod 2^f, -scalarQ mod 2^f
    if (mp_compare(scalarP, fp2, NWORDS_ORDER) == 1 ||
        (mp_compare(scalarQ, fp2, NWORDS_ORDER) == 1 &&
         (mp_is_zero(scalarP, NWORDS_ORDER) == 1 || mp_compare(scalarP, fp2, NWORDS_ORDER) == 0)))
    {
        mp_shiftl(fp2, 1, NWORDS_ORDER); // Get 2^f
        if (mp_is_zero(scalarP, NWORDS_ORDER) != 1)
            mp_sub(scalarP, fp2, scalarP, NWORDS_ORDER);
        if (mp_is_zero(scalarQ, NWORDS_ORDER) != 1)
            mp_sub(scalarQ, fp2, scalarQ, NWORDS_ORDER);
    }
}

void lift_point(jac_point_t *P, ec_point_t *Q, ec_curve_t *E)
{
    fp2_t inverses[2];
    if (fp2_is_zero(&Q->z))
    {
        fp2_set_one(&P->x);
        fp2_set_one(&P->y);
        fp2_set_zero(&P->z);
    }
    else
    {
        fp2_copy(&inverses[0], &Q->z);
        fp2_copy(&inverses[1], &E->C);
        fp2_batched_inv(inverses, 2);

        fp2_set_one(&Q->z);
        fp2_set_one(&E->C);

        fp2_mul(&Q->x, &Q->x, &inverses[0]);
        fp2_mul(&E->A, &E->A, &inverses[1]);

        fp2_copy(&P->x, &Q->x);
        fp2_set_one(&P->z);
        recover_y(&P->y, &P->x, E);
    }
}

void lift_basis(jac_point_t *P, jac_point_t *Q, ec_basis_t *B, ec_curve_t *E)
{
    fp2_t inverses[2];
    fp2_copy(&inverses[0], &B->P.z);
    // fp2_copy(&inverses[1],&B->Q.z);
    fp2_copy(&inverses[1], &E->C);

    fp2_batched_inv(inverses, 2);
    fp2_set_one(&B->P.z);
    fp2_set_one(&E->C);

    fp2_mul(&B->P.x, &B->P.x, &inverses[0]);
    fp2_mul(&E->A, &E->A, &inverses[1]);

    fp2_copy(&P->x, &B->P.x);
    fp2_copy(&Q->x, &B->Q.x);
    fp2_copy(&Q->z, &B->Q.z);
    fp2_set_one(&P->z);
    recover_y(&P->y, &P->x, E);

    // Algorithm of Okeya-Sakurai to recover y.Q in the montgomery model
    fp2_t v1, v2, v3, v4;
    fp2_mul(&v1, &P->x, &Q->z);
    fp2_add(&v2, &Q->x, &v1);
    fp2_sub(&v3, &Q->x, &v1);
    fp2_sqr(&v3, &v3);
    fp2_mul(&v3, &v3, &B->PmQ.x);
    fp2_add(&v1, &E->A, &E->A);
    fp2_mul(&v1, &v1, &Q->z);
    fp2_add(&v2, &v2, &v1);
    fp2_mul(&v4, &P->x, &Q->x);
    fp2_add(&v4, &v4, &Q->z);
    fp2_mul(&v2, &v2, &v4);
    fp2_mul(&v1, &v1, &Q->z);
    fp2_sub(&v2, &v2, &v1);
    fp2_mul(&v2, &v2, &B->PmQ.z);
    fp2_sub(&Q->y, &v3, &v2);
    fp2_add(&v1, &P->y, &P->y);
    fp2_mul(&v1, &v1, &Q->z);
    fp2_mul(&v1, &v1, &B->PmQ.z);
    fp2_mul(&Q->x, &Q->x, &v1);
    fp2_mul(&Q->z, &Q->z, &v1);

    // Transforming to a jacobian coordinate
    fp2_sqr(&v1, &Q->z);
    fp2_mul(&Q->y, &Q->y, &v1);
    fp2_mul(&Q->x, &Q->x, &Q->z);
}

// WRAPPERS

void ec_dbl(ec_point_t *res, const ec_curve_t *curve, const ec_point_t *P)
{
    xDBL(res, P, (ec_point_t const *)curve);
}

void ec_mul(ec_point_t *res, const ec_curve_t *curve, const digit_t *scalar, const int size, const ec_point_t *P)
{
    xMUL(res, P, scalar, size, curve);
}
void ec_biscalar_mul(ec_point_t *res,
                     const ec_curve_t *curve,
                     const digit_t *scalarP,
                     const digit_t *scalarQ,
                     const ec_basis_t *PQ)
{
    xDBLMUL(res, &PQ->P, scalarP, &PQ->Q, scalarQ, &PQ->PmQ, curve);
}

void ec_biscalar_mul_bounded(ec_point_t *res,
                             const ec_curve_t *curve,
                             const digit_t *scalarP,
                             const digit_t *scalarQ,
                             const ec_basis_t *PQ,
                             int size)
{
    xDBLMUL_bounded(res, &PQ->P, scalarP, &PQ->Q, scalarQ, &PQ->PmQ, curve, size);
}
