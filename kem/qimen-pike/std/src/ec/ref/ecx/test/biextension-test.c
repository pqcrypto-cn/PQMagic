
#include <tutil.h>
#include <ec_params.h>
#include "ec.h"
#include "fp.h"
#include "intbig.h"
#include <stdio.h>
#include <curve_extras.h>
#include <biextension.h>
#include <endomorphism_action.h>
#include <torsion_constants.h>

int
compare_words(digit_t *a, digit_t *b, unsigned int nwords)
{ // Comparing "nword" elements, a=b? : (1) a>b, (0) a=b, (-1) a<b
  // SECURITY NOTE: this function does not have constant-time execution. TO BE USED FOR TESTING
  // ONLY.
    int i;

    for (i = nwords - 1; i >= 0; i--) {
        if (a[i] > b[i])
            return 1;
        else if (a[i] < b[i])
            return -1;
    }

    return 0;
}

int dlog_2_test() {
    ec_curve_t E0 = CURVE_E0;
    ec_basis_t even_basis = BASIS_EVEN;
    ibz_t a, b, c, d;
    digit_t x[NWORDS_ORDER] = {0}, y[NWORDS_ORDER] = {0};
    ibz_init(&a); ibz_init(&b);
    ibz_init(&c); ibz_init(&d);
    ibz_rand_interval(&a, &ibz_const_zero, &TORSION_PLUS_2POWER);
    ibz_rand_interval(&b, &ibz_const_zero, &TORSION_PLUS_2POWER);

    ibz_to_digits(x, &a);
    ibz_to_digits(y, &b);

    ibz_copy_digits(&a, x, NWORDS_ORDER);
    ibz_copy_digits(&b, y, NWORDS_ORDER);

    ec_point_t R = {0}, S = {0};
    digit_t z[NWORDS_ORDER] = {0}, w[NWORDS_ORDER] = {0};
    ec_biscalar_mul(&R, &E0, x, y, &even_basis);

    ec_dlog_2(z ,w, &even_basis, &R, &E0);
    ec_biscalar_mul(&S, &E0, z, w, &even_basis);
    
    if (!is_point_equal(&S, &R)) {
        point_print("R : ", R);
        point_print("S : ", S);
        printf("dlog_2_test failed\n");
        return 1;
    }

    ibz_finalize(&a); ibz_finalize(&b);
    return 0;
}

int main (int argc, char* argv[]) {
    int test_num = 1;
    if (argc > 1) {
        test_num = atoi(argv[1]);
    }
    for (int i = 0; i < test_num; i++){
        if (dlog_2_test())
            return 1;
    }
    return 0;
}