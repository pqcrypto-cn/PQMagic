#include <quaternion.h>
#include "internal.h"
#include <stdlib.h>
#include <stdio.h>
#include <tools.h>

// Small helper for integers
void
ibz_rounded_div(ibz_t *q, const ibz_t *a, const ibz_t *b)
{
    ibz_t r, sign_q, abs_b;
    ibz_init(&r);
    ibz_init(&sign_q);
    ibz_init(&abs_b);

    // assumed to round towards 0
    ibz_abs(&abs_b, b);
    // q is of same sign as a*b (and 0 if a is 0)
    ibz_mul(&sign_q, a, b);
    ibz_div(q, &r, a, b);
    ibz_abs(&r, &r);
    ibz_add(&r, &r, &r);
    if (ibz_cmp(&r, &abs_b) > 0) {
        ibz_set(&r, 0);
        if (ibz_cmp(&sign_q, &r) < 0) {
            ibz_set(&sign_q, -1);
        } else {
            ibz_set(&sign_q, 1);
        }
        ibz_add(q, q, &sign_q);
    }
    ibz_finalize(&r);
    ibz_finalize(&sign_q);
    ibz_finalize(&abs_b);
}

// this function assumes that there is a sqrt of -1 mod p and p is prime
// algorithm read at http://www.lix.polytechnique.fr/Labo/Francois.Morain/Articles/cornac.pdf, on
// 2nd of may 2023, 14h45 CEST
int
ibz_cornacchia_prime(ibz_t *x, ibz_t *y, const ibz_t *n, const ibz_t *p)
{
    int res = 1;
    ibz_t two, r0, r1, r2, a, x0, prod;
    ibz_init(&r0);
    ibz_init(&r1);
    ibz_init(&r2);
    ibz_init(&a);
    ibz_init(&prod);
    ibz_init(&two);

    // manage case p = 2 separately
    ibz_set(&two, 2);
    int test = ibz_cmp(p, &two);
    if (test == 0) {
        if (ibz_is_one(n)) {
            ibz_set(x, 1);
            ibz_set(y, 1);
            res = 1;
        } else {
            res = 0;
        }
    }

// test coprimality (should always be ok in our cases)
#ifndef NDEBUG
    ibz_gcd(&r2, p, n);
    assert(ibz_is_one(&r2));
#endif
    if ((test != 0)) {

        // get sqrt of -n mod p
        ibz_set(&r2, 0);
        ibz_sub(&r2, &r2, n);
        res = res && ibz_sqrt_mod_p(&r2, &r2, p);
        if (res) {
            // run loop
            ibz_copy(&prod, p);
            ibz_copy(&r1, p);
            while (ibz_cmp(&prod, p) >= 0) {
                ibz_div(&a, &r0, &r2, &r1);
                ibz_mul(&prod, &r0, &r0);
                ibz_copy(&r2, &r1);
                ibz_copy(&r1, &r0);
            }
            // test if result is solution
            ibz_sub(&a, p, &prod);
            ibz_div(&a, &r2, &a, n);
            res = res && (ibz_is_zero(&r2));
            res = res && ibz_sqrt(y, &a);
            if (res) {
                ibz_copy(x, &r0);
                ibz_mul(&a, y, y);
                ibz_mul(&a, &a, n);
                ibz_add(&prod, &prod, &a);
                res = res && (0 == ibz_cmp(&prod, p));
            }
        }
    }
    ibz_finalize(&r0);
    ibz_finalize(&r1);
    ibz_finalize(&r2);
    ibz_finalize(&a);
    ibz_finalize(&prod);
    ibz_finalize(&two);
    return (res);
}

int
ibz_cornacchia_special_prime(ibz_t *x,
                             ibz_t *y,
                             const ibz_t *n,
                             const ibz_t *p,
                             const int exp_adjust)
{
    int res = 1;
    ibz_t two, r0, r1, r2, a, x0, prod;
    ibz_t p4;
    ibz_t test_square;
    ibz_init(&test_square);
    ibz_init(&r0);
    ibz_init(&r1);
    ibz_init(&r2);
    ibz_init(&a);
    ibz_init(&prod);
    ibz_init(&two);
    ibz_init(&p4);
    ibz_set(&two, 2);
    ibz_pow(&p4, &two, exp_adjust);
    ibz_mul(&p4, p, &p4);

    assert(exp_adjust > 0);

#ifndef NDEBUG
    ibz_set(&r0, 3);
    ibz_set(&r1, 4);
    ibz_mod(&r2, n, &r1);
    assert((ibz_cmp(&r2, &r0) == 0));
    ibz_set(&r0, 0);
    ibz_set(&r1, 0);
    ibz_set(&r2, 0);
#endif

    // manage case p = 2 separately
    int test = ibz_cmp(p, &two);
    if (test == 0) {
        if (ibz_is_one(n)) {
            ibz_set(x, 1);
            ibz_set(y, 1);
            res = 1;
        } else {
            res = 0;
        }
    }

    // test coprimality (should always be ok in our cases)
    ibz_gcd(&r2, p, n);
    if (ibz_is_one(&r2) && (test != 0)) {

        // get sqrt of -n mod p
        ibz_set(&r2, 0);
        ibz_sub(&r2, &r2, n);
        res = res && ibz_sqrt_mod_p(&r2, &r2, p);
        res = res && (ibz_get(&r2) % 2 != 0);

        ibz_mul(&test_square, &r2, &r2);
        ibz_add(&test_square, &test_square, n);
        ibz_mod(&test_square, &test_square, &p4);
        res = res && ibz_is_zero(&test_square);
        if (res) {
            // run loop
            ibz_copy(&prod, &p4);
            ibz_copy(&r1, &p4);
            while (ibz_cmp(&prod, &p4) >= 0) {
                ibz_div(&a, &r0, &r2, &r1);
                ibz_mul(&prod, &r0, &r0);
                ibz_copy(&r2, &r1);
                ibz_copy(&r1, &r0);
            }
            // test if result is solution
            ibz_sub(&a, &p4, &prod);
            ibz_div(&a, &r2, &a, n);
            res = res && ibz_is_zero(&r2);
            res = res && ibz_sqrt(y, &a);
            if (res) {
                ibz_copy(x, &r0);
                ibz_mul(&a, y, y);
                ibz_mul(&a, &a, n);
                ibz_add(&prod, &prod, &a);
                res = res && (0 == ibz_cmp(&prod, &p4));
            }
        }
    }
    ibz_finalize(&r0);
    ibz_finalize(&r1);
    ibz_finalize(&r2);
    ibz_finalize(&a);
    ibz_finalize(&prod);
    ibz_finalize(&two);
    ibz_finalize(&p4);
    ibz_finalize(&test_square);
    return (res);
}

// returns complex product of a and b
void
ibz_complex_mul(ibz_t *re_res,
                ibz_t *im_res,
                const ibz_t *re_a,
                const ibz_t *im_a,
                const ibz_t *re_b,
                const ibz_t *im_b)
{
    ibz_t prod, re, im;
    ibz_init(&prod);
    ibz_init(&re);
    ibz_init(&im);
    ibz_mul(&re, re_a, re_b);
    ibz_mul(&prod, im_a, im_b);
    ibz_sub(&re, &re, &prod);
    ibz_mul(&im, re_a, im_b);
    ibz_mul(&prod, im_a, re_b);
    ibz_add(&im, &im, &prod);
    ibz_copy(im_res, &im);
    ibz_copy(re_res, &re);
    ibz_finalize(&prod);
    ibz_finalize(&re);
    ibz_finalize(&im);
}

// multiplies res by a^e with res and a integer complex numbers
void
ibz_complex_mul_by_complex_power(ibz_t *re_res,
                                 ibz_t *im_res,
                                 const ibz_t *re_a,
                                 const ibz_t *im_a,
                                 int64_t exp)
{
    ibz_t re_x, im_x;
    ibz_init(&re_x);
    ibz_init(&im_x);
    ibz_set(&re_x, 1);
    ibz_set(&im_x, 0);
    for (int i = 0; i < 64; i++) {
        ibz_complex_mul(&re_x, &im_x, &re_x, &im_x, &re_x, &im_x);
        if ((exp >> (63 - i)) & 1) {
            ibz_complex_mul(&re_x, &im_x, &re_x, &im_x, re_a, im_a);
        }
    }
    ibz_complex_mul(re_res, im_res, re_res, im_res, &re_x, &im_x);
    ibz_finalize(&re_x);
    ibz_finalize(&im_x);
}

// multiplies to res the result of the solutions of cornacchia for prime depending on valuation val
// (prime-adic valuation)
int
ibz_cornacchia_extended_prime_loop(ibz_t *re_res, ibz_t *im_res, int64_t prime, int64_t val)
{
    ibz_t re, im, p, n;
    ibz_init(&re);
    ibz_init(&im);
    ibz_init(&p);
    ibz_init(&n);
    ibz_set(&n, 1);
    ibz_set(&p, prime);
    int res = ibz_cornacchia_prime(&re, &im, &n, &p);
    if (res) {
        ibz_complex_mul_by_complex_power(re_res, im_res, &re, &im, val);
    }
    ibz_finalize(&re);
    ibz_finalize(&im);
    ibz_finalize(&p);
    ibz_finalize(&n);
    return (res);
}

int
ibz_cornacchia_extended(ibz_t *x,
                        ibz_t *y,
                        const ibz_t *n,
                        const short *prime_list,
                        const int prime_list_length,
                        short primality_test_iterations,
                        const ibz_t *bad_primes_prod)
{
    int res = 1;
    ibz_t four, one, nodd, q, r, p;
    ibz_init(&four);
    ibz_init(&one);
    ibz_init(&nodd);
    ibz_init(&r);
    ibz_init(&q);
    ibz_init(&p);
    int64_t *valuations = malloc(prime_list_length * sizeof(int64_t));
    ibz_set(&four, 4);
    ibz_set(&one, 1);

    // if a prime which is 3 mod 4 divides n, extended Cornacchia can't solve the equation
    if (bad_primes_prod != NULL) {
        ibz_gcd(&q, n, bad_primes_prod);
        if (!ibz_is_one(&q)) {
            res = 0;
        }
    }

    if (res) {
        // get the valuations and the unfactored part by attempting division by all given primes
        ibz_copy(&nodd, n);
        for (int i = 0; i < prime_list_length; i++) {
            valuations[i] = 0;
            if (((*(prime_list + i) % 4) == 1) || (i == 0)) {
                ibz_set(&r, 0);
                ibz_set(&p, *(prime_list + i));
                ibz_copy(&q, &nodd);
                while (ibz_is_zero(&r)) {
                    valuations[i] += 1;
                    ibz_copy(&nodd, &q);
                    ibz_div(&q, &r, &nodd, &p);
                }
                valuations[i] -= 1;
            }
        }

        // compute the remainder mod 4
        ibz_mod(&r, &nodd, &four);
        if (ibz_is_one(&r)) { // we hope the 'unfactored' part is a prime 1 mod 4
            int probab = ibz_probab_prime(&nodd, primality_test_iterations);
            if (probab || ibz_is_one(&nodd)) {
                if (ibz_is_one(&nodd)) { // the unfactored part is 1
                    ibz_set(x, 1);
                    ibz_set(y, 0);
                } else { // the 'unfactored' part is prime, can use Cornacchia
                    res = res && ibz_cornacchia_prime(x, y, &one, &nodd);
                }
                if (res == 1) { // no need to continue if failure here
                    for (int i = 0; i < prime_list_length; i++) {
                        if (valuations[i] != 0) {

                            res = res && ibz_cornacchia_extended_prime_loop(
                                             x, y, prime_list[i], valuations[i]);
                        }
                    }
                }
            } else {
                res = 0;
            }
        } else {
            res = 0;
        }
    }
    free(valuations);
    ibz_finalize(&four);
    ibz_finalize(&one);
    ibz_finalize(&nodd);
    ibz_finalize(&r);
    ibz_finalize(&q);
    ibz_finalize(&p);
    return (res);
}
