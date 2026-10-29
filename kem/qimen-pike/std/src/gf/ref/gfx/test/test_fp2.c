#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "test_utils.h"

// Benchmark and test parameters
static int BENCH_LOOPS = 100000; // Number of iterations per bench
static int TEST_LOOPS = 100000;  // Number of iterations per test

bool
fp2_test(void)
{ // Tests for the GF(p^2) arithmetic
    bool OK = true;
    int n, passed;
    fp2_t a, b, c, d, e, f;

    printf("\n-------------------------------------------------------------------------------------"
           "-------------------\n\n");
    printf("Testing arithmetic over GF(p^2): \n\n");

    // Addition in GF(p^2)
    passed = 1;
    for (n = 0; n < TEST_LOOPS; n++) {
        fp2_random_test(&a);
        fp2_random_test(&b);
        fp2_random_test(&c);
        fp2_random_test(&d);

        fp2_add(&d, &a, &b);
        fp2_add(&e, &d, &c); // e = (a+b)+c
        fp2_add(&d, &b, &c);
        fp2_add(&f, &d, &a); // f = a+(b+c)
        if (fp2_is_equal(&e, &f) == 0) {
            passed = 0;
            break;
        }

        fp2_add(&d, &a, &b); // d = a+b
        fp2_add(&e, &b, &a); // e = b+a
        if (fp2_is_equal(&d, &e) == 0) {
            passed = 0;
            break;
        }

        fp2_set_zero(&b);
        fp2_add(&d, &a, &b); // d = a+0
        if (fp2_is_equal(&d, &a) == 0) {
            passed = 0;
            break;
        }

        fp2_neg(&d, &a);
        fp2_add(&e, &a, &d); // e = a+(-a)
        if (fp2_is_zero(&e) == 0) {
            passed = 0;
            break;
        }
    }
    if (passed == 1)
        printf("  GF(p^2) addition tests ............................................ PASSED");
    else {
        printf("  GF(p^2) addition tests... FAILED");
        printf("\n");
        return false;
    }
    printf("\n");

    // Subtraction in GF(p^2)
    passed = 1;
    for (n = 0; n < TEST_LOOPS; n++) {
        fp2_random_test(&a);
        fp2_random_test(&b);
        fp2_random_test(&c);
        fp2_random_test(&d);

        fp2_sub(&d, &a, &b);
        fp2_sub(&e, &d, &c); // e = (a-b)-c
        fp2_add(&d, &b, &c);
        fp2_sub(&f, &a, &d); // f = a-(b+c)
        if (fp2_is_equal(&e, &f) == 0) {
            passed = 0;
            break;
        }

        fp2_sub(&d, &a, &b); // d = a-b
        fp2_sub(&e, &b, &a);
        fp2_neg(&e, &e); // e = -(b-a)
        if (fp2_is_equal(&d, &e) == 0) {
            passed = 0;
            break;
        }

        fp2_set_zero(&b);
        fp2_sub(&d, &a, &b); // d = a-0
        if (fp2_is_equal(&d, &a) == 0) {
            passed = 0;
            break;
        }

        fp2_sub(&e, &a, &a); // e = a+(-a)
        if (fp2_is_zero(&e) == 0) {
            passed = 0;
            break;
        }
    }
    if (passed == 1)
        printf("  GF(p^2) subtraction tests ......................................... PASSED");
    else {
        printf("  GF(p^2) subtraction tests... FAILED");
        printf("\n");
        return false;
    }
    printf("\n");

    // Multiplication in GF(p^2)
    passed = 1;
    for (n = 0; n < TEST_LOOPS; n++) {
        fp2_random_test(&a);
        fp2_random_test(&b);
        fp2_random_test(&c);

        fp2_mul(&d, &a, &b);
        fp2_mul(&e, &d, &c); // e = (a*b)*c
        fp2_mul(&d, &b, &c);
        fp2_mul(&f, &d, &a); // f = a*(b*c)
        if (fp2_is_equal(&e, &f) == 0) {
            passed = 0;
            break;
        }

        fp2_add(&d, &b, &c);
        fp2_mul(&e, &a, &d); // e = a*(b+c)
        fp2_mul(&d, &a, &b);
        fp2_mul(&f, &a, &c);
        fp2_add(&f, &d, &f); // f = a*b+a*c
        if (fp2_is_equal(&e, &f) == 0) {
            passed = 0;
            break;
        }

        fp2_mul(&d, &a, &b); // d = a*b
        fp2_mul(&e, &b, &a); // e = b*a
        if (fp2_is_equal(&d, &e) == 0) {
            passed = 0;
            break;
        }

        fp2_set_one(&b);
        fp2_mul(&d, &a, &b); // d = a*1
        if (fp2_is_equal(&a, &d) == 0) {
            passed = 0;
            break;
        }

        fp2_set_zero(&b);
        fp2_mul(&d, &a, &b); // d = a*0
        if (fp2_is_zero(&d) == 0) {
            passed = 0;
            break;
        }
    }
    if (passed == 1)
        printf("  GF(p^2) multiplication tests ...................................... PASSED");
    else {
        printf("  GF(p^2) multiplication tests... FAILED");
        printf("\n");
        return false;
    }
    printf("\n");

    // Squaring in GF(p^2)
    passed = 1;
    for (n = 0; n < TEST_LOOPS; n++) {
        fp2_random_test(&a);

        fp2_sqr(&b, &a);     // b = a^2
        fp2_mul(&c, &a, &a); // c = a*a
        if (fp2_is_equal(&b, &c) == 0) {
            passed = 0;
            break;
        }

        fp2_set_zero(&a);
        fp2_sqr(&d, &a); // d = 0^2
        if (fp2_is_zero(&d) == 0) {
            passed = 0;
            break;
        }
    }
    if (passed == 1)
        printf("  GF(p^2) squaring tests............................................. PASSED");
    else {
        printf("  GF(p^2) squaring tests... FAILED");
        printf("\n");
        return false;
    }
    printf("\n");

    // Inversion in GF(p^2)
    passed = 1;
    for (n = 0; n < TEST_LOOPS; n++) {
        fp2_random_test(&a);

        fp2_set_one(&d);
        fp2_copy(&b, &a);
        fp2_inv(&a);
        fp2_mul(&c, &a, &b); // c = a*a^-1
        if (fp2_is_equal(&c, &d) == 0) {
            passed = 0;
            break;
        }

        fp2_set_zero(&a);
        fp2_set_zero(&d);
        fp2_inv(&a); // c = 0^-1
        if (fp2_is_equal(&a, &d) == 0) {
            passed = 0;
            break;
        }
    }
    if (passed == 1)
        printf("  GF(p^2) inversion tests............................................ PASSED");
    else {
        printf("  GF(p^2) inversion tests... FAILED");
        printf("\n");
        return false;
    }
    printf("\n");

    // Square root and square detection in GF(p^2)
    passed = 1;
    for (n = 0; n < TEST_LOOPS; n++) {
        fp2_random_test(&a);

        fp2_sqr(&c, &a); // c = a^2
        if (fp2_is_square(&c) == 0) {
            passed = 0;
            break;
        }

        fp2_sqrt(&c); // c = a = sqrt(c)
        fp2_neg(&d, &c);
        if ((fp2_is_equal(&a, &c) == 0) && (fp2_is_equal(&a, &d) == 0)) {
            passed = 0;
            break;
        }
    }
    if (passed == 1)
        printf("  Square root, square tests.......................................... PASSED");
    else {
        printf("  Square root, square tests... FAILED");
        printf("\n");
        return false;
    }
    printf("\n");

    return OK;
}

bool
fp2_run(void)
{
    bool OK = true;
    int n, i;
    uint64_t cycles1, cycles2;
    fp2_t a, b;
    uint8_t tmp[FP_NBYTES];

    fp2_random_test(&a);
    fp2_random_test(&b);

    printf("\n-------------------------------------------------------------------------------------"
           "-------------------\n\n");
    printf("Benchmarking GF(p^2) field arithmetic: \n\n");

    // GF(p^2) addition
    uint64_t cycle_runs[20];

    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_add(&a, &a, &b);
            fp2_add(&b, &b, &a);
            fp2_add(&a, &a, &b);
            fp2_add(&b, &b, &a);
            fp2_add(&a, &a, &b);
            fp2_add(&b, &b, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &(b.re));
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  GF(p^2) addition runs in .......................................... %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / (6 * BENCH_LOOPS),
           tmp[0]);

    // GF(p^2) subtraction
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_sub(&a, &a, &b);
            fp2_sub(&b, &b, &a);
            fp2_sub(&a, &a, &b);
            fp2_sub(&b, &b, &a);
            fp2_sub(&a, &a, &b);
            fp2_sub(&b, &b, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &b.re);
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  GF(p^2) subtraction runs in ....................................... %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / (6 * BENCH_LOOPS),
           tmp[0]);

    // GF(p^2) multiplication
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_mul(&a, &a, &b);
            fp2_mul(&b, &b, &a);
            fp2_mul(&a, &a, &b);
            fp2_mul(&b, &b, &a);
            fp2_mul(&a, &a, &b);
            fp2_mul(&b, &b, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &b.re);
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  GF(p^2) multiplication runs in .................................... %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / (6 * BENCH_LOOPS),
           tmp[0]);

    // GF(p^2) squaring
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_sqr(&a, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &(a.re));
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  GF(p^2) squaring runs in .......................................... %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / (BENCH_LOOPS),
           tmp[0]);

    // GF(p^2) inversion
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_inv(&a);
            fp2_add(&a, &b, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &(a.re));
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  GF(p^2) inversion runs in ......................................... %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / BENCH_LOOPS,
           tmp[0]);

    // GF(p^2) sqrt
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_sqrt(&a);
            fp2_add(&a, &b, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &(a.re));
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  GF(p^2) sqrt runs in .............................................. %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / BENCH_LOOPS,
           tmp[0]);

    // GF(p^2) is_square
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (n = 0; n < BENCH_LOOPS; n++) {
            fp2_is_square(&a);
            fp2_add(&a, &b, &a);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    fp_encode(tmp, &(a.re));
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  Square checking runs in ........................................... %" PRIu64
           " cycles, (%u ignore me)\n",
           cycle_runs[4] / BENCH_LOOPS,
           tmp[0]);

    return OK;
}

int
main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("Please enter an argument: 'test' or 'bench' and <reps>\n");
        exit(1);
    }
    if (!strcmp(argv[1], "test")) {
        TEST_LOOPS = atoi(argv[2]);
        return !fp2_test();
    } else if (!strcmp(argv[1], "bench")) {
        BENCH_LOOPS = atoi(argv[2]);
        return !fp2_run();
    } else {
        exit(1);
    }
}
