#include <bench.h>
#include <assert.h>
#include <stdio.h>

// TODO: minimal include here...
#include <curve_extras.h>
#include <ec.h>

/******************************
Util functions
******************************/

static int BENCH_LOOPS = 500; // Number of iterations per bench

int
cmp_u64(const void *v1, const void *v2)
{
    uint64_t x1 = *(const uint64_t *)v1;
    uint64_t x2 = *(const uint64_t *)v2;
    if (x1 < x2) {
        return -1;
    } else if (x1 == x2) {
        return 0;
    } else {
        return 1;
    }
}

/******************************
Test functions
******************************/

int
inner_test_generated_basis(ec_basis_t *basis, ec_curve_t *curve, unsigned int n, bool new)
{
    int i;
    int PASSED = 1;

    ec_point_t P, Q;
    copy_point(&P, &basis->P);
    copy_point(&Q, &basis->Q);

    // Double points to get point of order 2
    for (i = 0; i < n - 1; i++) {
        xDBL_A24(&P, &P, &curve->A24);
        xDBL_A24(&Q, &Q, &curve->A24);
    }
    if (ec_is_zero(&P)) {
        printf("Point P generated does not have full order, new = %d\n", new);
        PASSED = 0;
    }
    if (ec_is_zero(&Q)) {
        printf("Point Q generated does not have full order, new = %d\n", new);
        PASSED = 0;
    }
    if (is_point_equal(&P, &Q)) {
        printf("Points P, Q are linearly dependent, new = %d\n", new);
        PASSED = 0;
    }
    // Only guaranteed on the new algorithm
    if (new && !fp2_is_zero(&Q.x)) {
        printf("Points Q is not above the Montgomery point, new = %d\n", new);
        PASSED = 0;
    }

    // This should give the identity
    xDBL_A24(&P, &P, &curve->A24);
    xDBL_A24(&Q, &Q, &curve->A24);
    if (!ec_is_zero(&P)) {
        printf("Point P generated does not have order exactly 2^n, new = %d\n", new);
        PASSED = 0;
    }
    if (!ec_is_zero(&Q)) {
        printf("Point Q generated does not have order exactly 2^n, new = %d\n", new);
        PASSED = 0;
    }

    if (PASSED == 0) {
        printf("Test failed with n = %d\n", n);
    }

    return PASSED;
}

int
inner_test_hint_basis(ec_basis_t *basis, ec_basis_t *basis_hint)
{
    int PASSED = 1;

    if (!is_point_equal(&basis->P, &basis_hint->P)) {
        printf("The points P do not match using the hint\n");
        PASSED = 0;
    }

    if (!is_point_equal(&basis->Q, &basis_hint->Q)) {
        printf("The points Q do not match using the hint\n");
        PASSED = 0;
    }

    if (!is_point_equal(&basis->PmQ, &basis_hint->PmQ)) {
        printf("The points PmQ do not match using the hint\n");
        PASSED = 0;
    }

    if (PASSED == 0) {
        printf("Test failed");
    }

    return PASSED;
}

/******************************
Test wrapper functions
******************************/

int
test_basis_generation(unsigned int n, bool new)
{
    ec_basis_t basis;
    ec_curve_t curve;

    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    // Generate a basis
    if (new) {
        ec_curve_to_basis_2f(&basis, &curve, n);
    } else {
        ec_curve_to_basis_2(&basis, &curve, n);
    }

    return inner_test_generated_basis(&basis, &curve, n, new);
}

int
test_basis_generation_with_hints(unsigned int n, bool new)
{
    ec_basis_t basis, basis_hint;
    ec_curve_t curve;
    ec_curve_init(&curve);

    int hint[2];

    int check_1, check_2;

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    // Generate a basis with hints
    if (new) {
        ec_curve_to_basis_2f_to_hint(&basis, &curve, n, hint);
    } else {
        ec_curve_to_basis_2_to_hint(&basis, &curve, n, hint);
    }

    // Ensure the basis from the hint is good
    check_1 = inner_test_generated_basis(&basis, &curve, n, new);

    // Generate a basis using hints
    if (new) {
        ec_curve_to_basis_2f_from_hint(&basis_hint, &curve, n, hint);
    } else {
        ec_curve_to_basis_2_from_hint(&basis_hint, &curve, n, hint);
    }

    // These two bases should be the same
    check_2 = inner_test_hint_basis(&basis, &basis_hint);

    return check_1 && check_2;
}

int
test_complete_basis_generation(unsigned int n)
{
    // First just grab a good basis and try completing from either one
    ec_basis_t basis, basis_1, basis_2, basis_3;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    ec_curve_to_basis_2f(&basis, &curve, n);

    // Try completing from all three points we have access to
    ec_complete_basis_2f(&basis_1, &curve, &basis.P, n);
    ec_complete_basis_2f(&basis_2, &curve, &basis.Q, n);
    ec_complete_basis_2f(&basis_3, &curve, &basis.PmQ, n);

    // Now just check all the bases
    int check_1 = inner_test_generated_basis(&basis_1, &curve, n, 1);
    if (check_1 != 1) {
        printf("Failed for the point P in the basis");
    }
    int check_2 = inner_test_generated_basis(&basis_1, &curve, n, 1);
    if (check_2 != 1) {
        printf("Failed for the point Q in the basis");
    }
    int check_3 = inner_test_generated_basis(&basis_1, &curve, n, 1);
    if (check_3 != 1) {
        printf("Failed for the point PmQ in the basis");
    }

    return check_1 && check_2 && check_3;
}

void
bench_old_basis_generation(unsigned int n)
{
    int i, j;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[20];

    ec_basis_t basis;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    // Full even torsion generation without hints
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (j = 0; j < BENCH_LOOPS; j++) {
            ec_curve_to_basis_2(&basis, &curve, n);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  2^%d torsion generation takes .................................... %lu cycles\n",
           n,
           cycle_runs[4] / (BENCH_LOOPS));
}

void
bench_new_basis_generation(unsigned int n)
{
    int i, j;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[20];

    ec_basis_t basis;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    // Full even torsion generation without hints
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (j = 0; j < BENCH_LOOPS; j++) {
            ec_curve_to_basis_2f(&basis, &curve, n);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  2^%d torsion generation takes .................................... %lu cycles\n",
           n,
           cycle_runs[4] / (BENCH_LOOPS));
}

void
bench_old_basis_generation_from_hint(unsigned int n)
{
    int i, j;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[20];

    ec_basis_t basis;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    int hint[2];
    ec_curve_to_basis_2_to_hint(&basis, &curve, n, hint);

    // Full even torsion generation without hints
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (j = 0; j < BENCH_LOOPS; j++) {
            ec_curve_to_basis_2_from_hint(&basis, &curve, n, hint);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  2^%d torsion generation takes .................................... %lu cycles\n",
           n,
           cycle_runs[4] / (BENCH_LOOPS));
}

void
bench_new_basis_generation_from_hint(unsigned int n)
{
    int i, j;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[20];

    ec_basis_t basis;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);

    int hint[2];
    ec_curve_to_basis_2f_to_hint(&basis, &curve, n, hint);

    // Full even torsion generation without hints
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (j = 0; j < BENCH_LOOPS; j++) {
            ec_curve_to_basis_2f_from_hint(&basis, &curve, n, hint);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  2^%d torsion generation takes .................................... %lu cycles\n",
           n,
           cycle_runs[4] / (BENCH_LOOPS));
}

void
bench_old_basis_completion()
{
    int i, j;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[20];

    ec_basis_t basis, basis_1, basis_2, basis_3;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);
    ec_curve_to_basis_2(&basis, &curve, TORSION_PLUS_EVEN_POWER);

    // Full even torsion generation without hints
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (j = 0; j < BENCH_LOOPS; j++) {
            ec_complete_basis_2(&basis_1, &curve, &basis.P);
            ec_complete_basis_2(&basis_2, &curve, &basis.Q);
            ec_complete_basis_2(&basis_3, &curve, &basis.PmQ);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  2^%lu torsion completion takes .................................... %lu cycles\n",
           TORSION_PLUS_EVEN_POWER,
           cycle_runs[4] / (3 * BENCH_LOOPS));
}

void
bench_new_basis_completion(unsigned int n)
{
    int i, j;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[20];

    ec_basis_t basis, basis_1, basis_2, basis_3;
    ec_curve_t curve;
    ec_curve_init(&curve);

    // Set a supersingular elliptic curve
    // E : y^2 = x^3 + 6*x^2 + x
    fp2_set_small(&(curve.A), 6);
    fp2_set_one(&(curve.C));
    ec_curve_normalize_A24(&curve);
    ec_curve_to_basis_2f(&basis, &curve, n);

    // Full even torsion generation without hints
    for (i = 0; i < 20; i++) {
        cycles1 = cpucycles();
        for (j = 0; j < BENCH_LOOPS; j++) {
            ec_complete_basis_2f(&basis_1, &curve, &basis.P, n);
            ec_complete_basis_2f(&basis_2, &curve, &basis.Q, n);
            ec_complete_basis_2f(&basis_3, &curve, &basis.PmQ, n);
        }
        cycles2 = cpucycles();
        cycle_runs[i] = cycles2 - cycles1;
    }
    qsort(cycle_runs + 10, 10, sizeof cycle_runs[0], cmp_u64);
    printf("  2^%d torsion completion takes .................................... %lu cycles\n",
           n,
           cycle_runs[4] / (3 * BENCH_LOOPS));
}

void
test_basis(bool new)
{
    // Test full order
    printf("Testing full torsion generation:\n");
    test_basis_generation(TORSION_PLUS_EVEN_POWER, new);
    test_basis_generation_with_hints(TORSION_PLUS_EVEN_POWER, new);

    // Test partial order
    printf("Testing partial torsion generation:\n");
    test_basis_generation(128, new);
    test_basis_generation_with_hints(128, new);

    if (new) {
        test_complete_basis_generation(TORSION_PLUS_EVEN_POWER);
        test_complete_basis_generation(123);
        test_complete_basis_generation(2);
    }
}

void
bench_basis(bool new)
{
    printf("\n-------------------------------------------------------------------------------------"
           "-------------------\n\n");

    if (new) {
        printf("Benchmarking E[2^n] basis generation with new method: \n\n");
        bench_new_basis_generation(TORSION_PLUS_EVEN_POWER);
        bench_new_basis_generation(128);
    } else {
        printf("Benchmarking E[2^n] basis generation with old method: \n\n");
        bench_old_basis_generation(TORSION_PLUS_EVEN_POWER);
        bench_old_basis_generation(128);
    }

    if (new) {
        printf("\nBenchmarking E[2^n] basis completion with new method: \n\n");
        bench_new_basis_completion(TORSION_PLUS_EVEN_POWER);
        bench_new_basis_completion(128);
    } else {
        printf("\nBenchmarking E[2^n] basis completion with old method: \n\n");
        bench_old_basis_completion();
    }

    if (new) {
        printf("\nBenchmarking E[2^n] basis generation with hint and new method: \n\n");
        bench_new_basis_generation_from_hint(TORSION_PLUS_EVEN_POWER);
        bench_new_basis_generation_from_hint(128);
    } else {
        printf("\nBenchmarking E[2^n] basis generation with hint and old method: \n\n");
        bench_old_basis_generation_from_hint(TORSION_PLUS_EVEN_POWER);
        bench_old_basis_generation_from_hint(128);
    }
}

int
main(void)
{
    test_basis(0);
    test_basis(1);
    if(test_complete_basis_generation(TORSION_PLUS_EVEN_POWER)) {
        printf("complete_basis_generation : success\n");
        printf("torsion_plus_even_power : %lu\n", TORSION_PLUS_EVEN_POWER);
    }
    /*
        bench_basis(0);
        bench_basis(1);
    */
    return 0;
}
