#include <intbig.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rng.h>

static int
test_ibq_consts()
{
    int ret = 0;
    ibq_t t;
    ibz_t tmp1, tmp2, tmp3;
    ibz_init(&tmp1);
    ibz_init(&tmp2);
    ibz_init(&tmp3);
    ibq_init(&t);

    ibz_set(&tmp1, 123);
    ibz_set(&tmp2, -123);
    if (!ibq_set(&t, &tmp1, &tmp2)) {
        ret = -1;
        goto err;
    }

    if (ibq_is_one(&t)) {
        ret = -1;
        goto err;
    }

    if (!ibq_is_ibz(&t)) {
        ret = -1;
        goto err;
    }

    if (!ibq_to_ibz(&tmp3, &t)) {
        ret = -1;
        goto err;
    }

    if (ibz_is_one(&tmp3)) {
        ret = -1;
        goto err;
    }

    ibz_set(&tmp2, 123);
    if (!ibq_set(&t, &tmp1, &tmp2)) {
        ret = -1;
        goto err;
    }

    if (!ibq_is_one(&t)) {
        ret = -1;
        goto err;
    }

    if (!ibq_is_ibz(&t)) {
        ret = -1;
        goto err;
    }

    if (!ibq_to_ibz(&tmp3, &t)) {
        ret = -1;
        goto err;
    }

    if (!ibz_is_one(&tmp3)) {
        ret = -1;
        goto err;
    }

    ibz_set(&tmp1, 0);
    ibq_set(&t, &tmp1, &tmp2);

    if (!ibq_is_zero(&t)) {
        ret = -1;
        goto err;
    }

    if (!ibq_is_ibz(&t)) {
        ret = -1;
        goto err;
    }

    if (!ibq_to_ibz(&tmp3, &t)) {
        ret = -1;
        goto err;
    }

    if (!ibz_is_zero(&tmp3)) {
        ret = -1;
        goto err;
    }

err:
    ibq_finalize(&t);
    ibz_finalize(&tmp1);
    ibz_finalize(&tmp2);
    ibz_finalize(&tmp3);
    return ret;
}

/**
 * Tests ibz_sqrt_mod_p and ibz_sqrt_mod_2p
 * Allows to provide the number of repetitions and the bit-size of the primes.
 */
static int
test_ibz_sqrt_mod_p_2p(int reps, int prime_n)
{
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, 1); // set static seed

    int ret = 0;

    // Initialize GMP variables
    mpz_t prime, a, prime_minus_a, asq, sqrt, tmp;
    mpz_t prime_p4m3, prime_p5m8, prime_p1m8;
    mpz_t prime_p4m3_x2, prime_p5m8_x2, prime_p1m8_x2;
    mpz_init(prime);
    mpz_init(prime_p4m3);
    mpz_init(prime_p5m8);
    mpz_init(prime_p1m8);
    mpz_init(prime_p4m3_x2);
    mpz_init(prime_p5m8_x2);
    mpz_init(prime_p1m8_x2);
    mpz_init(a);
    mpz_init(prime_minus_a);
    mpz_init(asq);
    mpz_init(sqrt);
    mpz_init(tmp);

    // Generate random prime number
    int n = prime_n; // Number of bits

    for (int r = 0; r < reps; ++r) {
        mpz_urandomb(prime, state, n);

        int p4m3 = 0, p5m8 = 0, p1m8 = 0;

        while (p4m3 == 0 || p5m8 == 0 || p1m8 == 0) {
            mpz_nextprime(prime, prime);

            if (mpz_mod_ui(tmp, prime, 4) == 3) {
                mpz_set(prime_p4m3, prime);
                p4m3 = 1;
            } else if (mpz_mod_ui(tmp, prime, 8) == 5) {
                mpz_set(prime_p5m8, prime);
                p5m8 = 1;
            } else if (mpz_mod_ui(tmp, prime, 8) == 1) {
                mpz_set(prime_p1m8, prime);
                p1m8 = 1;
            } else {
                printf("Should not happen..\n");
                ret = -1;
                goto err;
            }
        }

        mpz_t *primes[] = { &prime_p4m3, &prime_p5m8, &prime_p1m8 };
        mpz_t *primes_x2[] = { &prime_p4m3_x2, &prime_p5m8_x2, &prime_p1m8_x2 };
        for (int i = 0; i < 3; ++i) // 2p
            mpz_mul_2exp(*primes_x2[i], *primes[i], 1);

        // Test sqrt mod p
        for (int i = 0; i < 3; ++i) {
            mpz_urandomm(a, state, *primes[i]);
            mpz_sub(prime_minus_a, *primes[i], a);
            mpz_powm_ui(asq, a, 2, *primes[i]);

            int no_sqrt = !ibz_sqrt_mod_p(&sqrt, &asq, primes[i]);
            mpz_powm_ui(tmp, sqrt, 2, *primes[i]);

            if (no_sqrt || (mpz_cmp(sqrt, a) && mpz_cmp(sqrt, prime_minus_a))) {
                printf("Test sqrt_mod_p failed\n");
                gmp_printf("%Zx\n%Zx\n", sqrt, a);
                ret = -1;
                goto err;
            }
        }

        // Test sqrt mod 2p
        for (int i = 0; i < 3; ++i) {
            mpz_urandomm(a, state, *primes_x2[i]);

            mpz_sub(prime_minus_a, *primes_x2[i], a);
            mpz_powm_ui(asq, a, 2, *primes_x2[i]);

            int no_sqrt = !ibz_sqrt_mod_2p(&sqrt, &asq, primes[i]);
            mpz_powm_ui(tmp, sqrt, 2, *primes_x2[i]);

            if (no_sqrt || (mpz_cmp(sqrt, a) && mpz_cmp(sqrt, prime_minus_a))) {
                printf("Test sqrt_mod_2p failed\n");
                gmp_printf(
                    "prime = %Zx\nprime_x2 = %Zx\nsqrt = %Zx\na = %Zx\na^2=%Zx\np - a = %Zx\n",
                    *primes[i],
                    *primes_x2[i],
                    sqrt,
                    a,
                    asq,
                    prime_minus_a);
                ret = -1;
                goto err;
            }
        }
    }

err:
    gmp_randclear(state);
    mpz_clear(prime);
    mpz_clear(prime_p4m3);
    mpz_clear(prime_p5m8);
    mpz_clear(prime_p1m8);
    mpz_clear(prime_p4m3_x2);
    mpz_clear(prime_p5m8_x2);
    mpz_clear(prime_p1m8_x2);
    mpz_clear(a);
    mpz_clear(prime_minus_a);
    mpz_clear(asq);
    mpz_clear(sqrt);
    mpz_clear(tmp);
    return ret;
}

/**
 * Tests CRT
 */
static int
test_ibz_crt(int reps, int prime_n)
{
    gmp_randstate_t state;
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, 1); // set static seed

    int ret = 0;

    // Initialize GMP variables
    mpz_t prime1, prime2, prime1xprime2, crt, a, b, tst;
    mpz_init(prime1);
    mpz_init(prime2);
    mpz_init(prime1xprime2);
    mpz_init(crt);
    mpz_init(a);
    mpz_init(b);
    mpz_init(tst);

    // Generate random prime number
    int n = prime_n; // Number of bits

    for (int r = 0; r < reps; ++r) {
        mpz_urandomb(prime1, state, n);
        mpz_nextprime(prime1, prime1);
        mpz_urandomm(a, state, prime1);
        mpz_urandomb(prime2, state, n);
        mpz_nextprime(prime2, prime2);
        mpz_urandomm(b, state, prime2);
        mpz_mul(prime1xprime2, prime1, prime2);

        ibz_crt(&crt, &a, &b, &prime1, &prime2);
        mpz_mod(tst, crt, prime1);
        if (mpz_cmp(tst, a)) {
            ret = -1;
            goto err;
        }
        mpz_mod(tst, crt, prime2);
        if (mpz_cmp(tst, b)) {
            ret = -1;
            goto err;
        }
        mpz_mod(tst, crt, prime1xprime2);
        if (mpz_cmp(tst, crt)) {
            ret = -1;
            goto err;
        }
    }

err:
    gmp_randclear(state);
    mpz_clear(prime1);
    mpz_clear(prime2);
    mpz_clear(prime1xprime2);
    mpz_clear(crt);
    mpz_clear(a);
    mpz_clear(b);
    mpz_clear(tst);
    return ret;
}

static int
test_ibz_constants()
{
    int ret = 0;
    const ibz_t *zero = &ibz_const_zero;
    const ibz_t *one = &ibz_const_one;
    const ibz_t *two = &ibz_const_two;

    mpz_t tmp;
    mpz_init(tmp);
    mpz_add(tmp, *zero, *one);
    mpz_add(tmp, tmp, *two);

    ret = (!mpz_cmp_ui(tmp, 3) ? 0 : -1);

    mpz_clear(tmp);
    return ret;
}

static int
test_ibz_rand_interval(int reps)
{
    int ret = 0;
    mpz_t low, high, rand;
    mpz_init(low);
    mpz_init(high);
    mpz_init(rand);
    mpz_set_str(low, "ffa", 16);
    mpz_set_str(high, "eeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 16);

    for (int i = 0; i < reps; ++i) {
        ret = ibz_rand_interval(&rand, &low, &high);
        if (ret != 1) {
            ret = -1;
            goto err;
        } else {
            ret = 0;
        }

        if (mpz_cmp(rand, low) < 0 || mpz_cmp(rand, high) > 0) {
            ret = -1;
            gmp_printf("rand: %Zx\n", rand);
            goto err;
        }
    }
err:
    mpz_clear(low);
    mpz_clear(high);
    mpz_clear(rand);
    return ret;
}

static int
test_ibz_rand_interval_i(int reps)
{
    int ret = 0;
    int64_t low, high;
    mpz_t rand;
    mpz_init(rand);

    for (int i = 0; i < reps; ++i) {
        randombytes((unsigned char *)&low, sizeof(int64_t));
        randombytes((unsigned char *)&high, sizeof(int64_t));
        if (low < 0)
            low = -low;
        if (high < 0)
            high = -high;
        if (low > high) {
            int64_t tmp = low;
            low = high;
            high = tmp;
        }

        ret = ibz_rand_interval_i(&rand, low, high);
        if (ret != 1) {
            ret = -1;
            goto err;
        } else {
            ret = 0;
        }

        if (mpz_cmp_si(rand, low) < 0 || mpz_cmp_si(rand, high) > 0) {
            ret = -1;
            gmp_printf("rand: %Zx\n", rand);
            goto err;
        }
    }

err:
    mpz_clear(rand);
    return ret;
}

static int
test_ibz_rand_interval_minm_m(int reps)
{
    int ret = 0;
    int64_t m;
    mpz_t rand;
    mpz_init(rand);

    for (int i = 0; i < reps; ++i) {
        randombytes((unsigned char *)&m, sizeof(int64_t));
        if (m < 0)
            m = -m;
        m >>= 1; // less than 64 bit

        if (m < 0) {
            ret = -1;
            goto err;
        }

        ret = ibz_rand_interval_minm_m(&rand, m);
        if (ret != 1) {
            ret = -1;
            goto err;
        } else {
            ret = 0;
        }

        if (mpz_cmp_si(rand, -m) < 0 || mpz_cmp_si(rand, m) > 0) {
            ret = -1;
            gmp_printf("rand: %Zx\n", rand);
            goto err;
        }
    }

err:
    mpz_clear(rand);
    return ret;
}

static int
test_ibz_copy_digits()
{
    int ret = 0;
    digit_t d1[] = { 0x12345678 };
    digit_t d2[] = { 2, 1 };

    // TODO: test for other than 64 bit
    const char d1str[] = "12345678";
    const char d2str[] = "10000000000000002";

    char d1_intbig_str[80] = { 0 };
    char d2_intbig_str[80] = { 0 };

    mpz_t d1_intbig, d2_intbig;
    mpz_init(d1_intbig);
    mpz_init(d2_intbig);

    ibz_copy_digits(&d1_intbig, d1, 1);
    ibz_copy_digits(&d2_intbig, d2, 2);

    gmp_sprintf(d1_intbig_str, "%Zx", d1_intbig);
    gmp_sprintf(d2_intbig_str, "%Zx", d2_intbig);

    if (memcmp(d1str, d1_intbig_str, 8)) {
        ret = -1;
        goto err;
    }
    if (memcmp(d2str, d2_intbig_str, 17)) {
        ret = -1;
        goto err;
    }
err:
    mpz_clear(d1_intbig);
    mpz_clear(d2_intbig);
    return ret;
}

static int
test_ibz_to_digits()
{
    int ret = 0;
    mpz_t d1_intbig, d2_intbig, zero_intbig;
    mpz_t d1_intbig_rec, d2_intbig_rec, zero_intbig_rec, cof, cof2;
    const char d1str[] = "12345678";
    const char d2str[] = "10000000000000002";

    mpz_init_set_str(d1_intbig, d1str, 16);
    mpz_init_set_str(d2_intbig, d2str, 16);
    mpz_init(zero_intbig);

    mpz_init(d1_intbig_rec);
    mpz_init(d2_intbig_rec);
    mpz_init(zero_intbig_rec);
    mpz_init(cof);
    mpz_init(cof2);

    size_t d1_digits =
        (mpz_sizeinbase(d1_intbig, 2) + sizeof(digit_t) * 8 - 1) / (sizeof(digit_t) * 8);
    size_t d2_digits =
        (mpz_sizeinbase(d2_intbig, 2) + sizeof(digit_t) * 8 - 1) / (sizeof(digit_t) * 8);

    digit_t d1[d1_digits];
    digit_t d2[d2_digits];
    digit_t zero[1];

    ibz_to_digits(d1, &d1_intbig);
    ibz_to_digits(d2, &d2_intbig);
    ibz_to_digits(zero, &zero_intbig);

    // A lazy test, but we know that this conversion should be correct from the previous test

    ibz_copy_digits(&d1_intbig_rec, d1, d1_digits);
    ibz_copy_digits(&d2_intbig_rec, d2, d2_digits);
    ibz_copy_digits(&zero_intbig_rec, zero, 1);

    if (mpz_cmp(d1_intbig, d1_intbig_rec) || mpz_cmp(zero_intbig, zero_intbig_rec)) {
        ret = -1;
        goto err;
    }

    digit_t p_cofactor_for_3g[5] = {
        0x0000000000000000, 0x74f9dace0d9ec800, 0x63a25b437f655001, 0x0000000000000019, 0
    };
    digit_t p_cofactor_for_3g_rec[5] = { 0 };
    ibz_copy_digits(&cof, p_cofactor_for_3g, 5);
    ibz_printf("cof: %Zx\n", cof);
    ibz_to_digits(p_cofactor_for_3g_rec, &cof);
    ibz_copy_digits(&cof2, p_cofactor_for_3g_rec, 5);
    ibz_printf("cof2: %Zx\n", cof2);

    if (ibz_cmp(&cof, &cof2)) {
        ret = -1;
        goto err;
    }

    digit_t da[2] = { 0, 0 };

    mpz_t strval, strval_check;
    mpz_init(strval_check);
    mpz_init_set_str(strval, "1617406613339667622221321", 10);
    ibz_to_digits(da, &strval);
    ibz_copy_digits(&strval_check, da, 2);
    ibz_printf("strval:       %Zd\nstrval_check: %Zd\n", strval, strval_check);
    if (ibz_cmp(&strval, &strval_check)) {
        ret = -1;
        goto err;
    }

err:
    mpz_clear(d1_intbig);
    mpz_clear(d2_intbig);
    mpz_clear(zero_intbig);
    mpz_clear(d1_intbig_rec);
    mpz_clear(d2_intbig_rec);
    mpz_clear(zero_intbig_rec);
    mpz_clear(cof);
    mpz_clear(cof2);
    mpz_clear(strval);
    mpz_clear(strval_check);
    return ret;
}

int
main(int argc, char *argv[])
{
    int ret = 0;
    if (argc < 3) {
        printf("Please enter an integer argument for the number of repetitions, and one for the "
               "prime size in bits.\n");
        exit(1);
    }
    int reps = atoi(argv[1]);
    int prime_n = atoi(argv[2]);

    ret = test_ibq_consts();
    if (ret)
        goto err;

    ret = test_ibz_sqrt_mod_p_2p(reps, prime_n);
    if (ret)
        goto err;

    ret = test_ibz_crt(reps, prime_n);
    if (ret)
        goto err;

    ret = test_ibz_constants();
    if (ret)
        goto err;

    ret = test_ibz_rand_interval(reps);
    if (ret)
        goto err;

    ret = test_ibz_rand_interval_i(reps);
    if (ret)
        goto err;

    ret = test_ibz_rand_interval_minm_m(reps);
    if (ret)
        goto err;

    ret = test_ibz_copy_digits();
    if (ret)
        goto err;

    ret = test_ibz_to_digits();
    if (ret)
        goto err;
err:
    return ret;
}
