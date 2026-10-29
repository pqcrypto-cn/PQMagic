#include <intbig.h>
#include <pike_hash.h>
#include <rng.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

// #define DEBUG_VERBOSE

#ifdef DEBUG_VERBOSE
#define DEBUG_STR_PRINTF(x) printf("%s\n", (x));
#define DEBUG_STR_FUN_INT_MP(op, arg1, arg2) gmp_printf("%s,%lx,%Zx\n", (op), (arg1), (arg2));
#define DEBUG_STR_FUN_3(op, arg1, arg2, arg3)                                                      \
    gmp_printf("%s,%Zx,%Zx,%Zx\n", (op), (arg1), (arg2), (arg3));
#define DEBUG_STR_FUN_INT_MP2(op, arg1, arg2, arg3)                                                \
    if ((arg1) >= 0)                                                                               \
        gmp_printf("%s,%lx,%Zx,%Zx\n", (op), (arg1), (arg2), (arg3));                              \
    else                                                                                           \
        gmp_printf("%s,-%lx,%Zx,%Zx\n", (op), (-arg1), (arg2), (arg3));
#define DEBUG_STR_FUN_INT_MP_INT(op, arg1, arg2, arg3)                                             \
    gmp_printf("%s,%lx,%Zx,%lx\n", (op), (arg1), (arg2), (arg3));
#define DEBUG_STR_FUN_4(op, arg1, arg2, arg3, arg4)                                                \
    gmp_printf("%s,%Zx,%Zx,%Zx,%Zx\n", (op), (arg1), (arg2), (arg3), (arg4));
#else
#define DEBUG_STR_PRINTF(x)
#define DEBUG_STR_FUN_INT_MP(op, arg1, arg2)
#define DEBUG_STR_FUN_3(op, arg1, arg2, arg3)
#define DEBUG_STR_FUN_INT_MP2(op, arg1, arg2, arg3)
#define DEBUG_STR_FUN_INT_MP_INT(op, arg1, arg2, arg3)
#define DEBUG_STR_FUN_4(op, arg1, arg2, arg3, arg4)
#endif

/** @defgroup ibz_t Constants
 * @{
 */

const __mpz_struct ibz_const_zero[1] = {
    {
     ._mp_alloc = 0,
     ._mp_size = 0,
     ._mp_d = (mp_limb_t[]){ 0 },
     }
};

const __mpz_struct ibz_const_one[1] = {
    {
     ._mp_alloc = 0,
     ._mp_size = 1,
     ._mp_d = (mp_limb_t[]){ 1 },
     }
};

const __mpz_struct ibz_const_two[1] = {
    {
     ._mp_alloc = 0,
     ._mp_size = 1,
     ._mp_d = (mp_limb_t[]){ 2 },
     }
};

const __mpz_struct ibz_const_three[1] = {
    {
     ._mp_alloc = 0,
     ._mp_size = 1,
     ._mp_d = (mp_limb_t[]){ 3 },
     }
};

const __mpz_struct ibz_const_five[1] = {
    {
     ._mp_alloc = 0,
     ._mp_size = 1,
     ._mp_d = (mp_limb_t[]){ 5 },
     }
};

const __mpz_struct ibz_const_seven[1] = {
    {
     ._mp_alloc = 0,
     ._mp_size = 1,
     ._mp_d = (mp_limb_t[]){ 7 },
     }
};


/* constructors/destructors (possibly no-ops) */

/** @defgroup ibz_t Constructors and Destructors
 * @{
 */

void
ibz_init(ibz_t *x)
{
    mpz_init(*x);
}

void
ibq_init(ibq_t *x)
{
    mpq_init(*x);
}

void
ibz_vec_2_init(ibz_vec_2_t *vec)
{
    ibz_init(&((*vec)[0]));
    ibz_init(&((*vec)[1]));
}

void
ibz_finalize(ibz_t *x)
{
    mpz_clear(*x);
}

void
ibz_secure_finalize(ibz_t *x)
{
    typedef void (*setui_t)(mpz_t, unsigned long int);
    static volatile setui_t setui_fun = mpz_set_ui;
    setui_fun(*x, 0);
    mpz_clear(*x);
}

void
ibq_finalize(ibq_t *x)
{
    mpq_clear(*x);
}

void
ibq_secure_finalize(ibq_t *x)
{
    typedef void (*setui_t)(mpq_t, unsigned long int, unsigned long int);
    static volatile setui_t setui_fun = mpq_set_ui;
    setui_fun(*x, 0, 0);
    mpq_clear(*x);
}

void
ibz_vec_2_finalize(ibz_vec_2_t *vec)
{
    ibz_finalize(&((*vec)[0]));
    ibz_finalize(&((*vec)[1]));
}

void
ibz_vec_2_secure_finalize(ibz_vec_2_t *vec)
{
    ibz_secure_finalize(&((*vec)[0]));
    ibz_secure_finalize(&((*vec)[1]));
}

/** @}
 */

/** @defgroup ibz_za Basic integer arithmetic
 * @{
 */

/** @brief sum=a+b
 */
void
ibz_add(ibz_t *sum, const ibz_t *a, const ibz_t *b)
{
#ifdef DEBUG_VERBOSE
    ibz_t a_cp, b_cp;
    ibz_init(&a_cp);
    ibz_init(&b_cp);
    ibz_copy(&a_cp, a);
    ibz_copy(&b_cp, b);
#endif
    mpz_add(*sum, *a, *b);
#ifdef DEBUG_VERBOSE
    DEBUG_STR_FUN_3("ibz_add", *sum, a_cp, b_cp);
    ibz_finalize(&a_cp);
    ibz_finalize(&b_cp);
#endif
}

/** @brief diff=a-b
 */
void
ibz_sub(ibz_t *diff, const ibz_t *a, const ibz_t *b)
{
#ifdef DEBUG_VERBOSE
    ibz_t a_cp, b_cp;
    ibz_init(&a_cp);
    ibz_init(&b_cp);
    ibz_copy(&a_cp, a);
    ibz_copy(&b_cp, b);
#endif
    mpz_sub(*diff, *a, *b);

#ifdef DEBUG_VERBOSE
    DEBUG_STR_FUN_3("ibz_sub", *diff, a_cp, b_cp);
    ibz_finalize(&a_cp);
    ibz_finalize(&b_cp);
#endif
}

/** @brief prod=a*b
 */
void
ibz_mul(ibz_t *prod, const ibz_t *a, const ibz_t *b)
{
#ifdef DEBUG_VERBOSE
    ibz_t a_cp, b_cp;
    ibz_init(&a_cp);
    ibz_init(&b_cp);
    ibz_copy(&a_cp, a);
    ibz_copy(&b_cp, b);
#endif
    mpz_mul(*prod, *a, *b);
#ifdef DEBUG_VERBOSE
    DEBUG_STR_FUN_3("ibz_mul", *prod, a_cp, b_cp);
    ibz_finalize(&a_cp);
    ibz_finalize(&b_cp);
#endif
}

/** @brief prod=a*2^exp
 */
void
ibz_mul_2exp(ibz_t *prod, const ibz_t *a, uint64_t exp)
{
#ifdef DEBUG_VERBOSE
    ibz_t a_cp;
    ibz_init(&a_cp);
    ibz_copy(&a_cp, a);
#endif
    mpz_mul_2exp(*prod, *a, exp);
#ifdef DEBUG_VERBOSE
    gmp_printf("ibz_mul_2exp,%Zx,%Zx,%lx\n", *prod, a_cp, exp);
    ibz_finalize(&a_cp);
#endif
}

/** @brief neg=-a
 */
void
ibz_neg(ibz_t *neg, const ibz_t *a)
{
    mpz_neg(*neg, *a);
}

/** @brief abs=|a|
 */
void
ibz_abs(ibz_t *abs, const ibz_t *a)
{
    mpz_abs(*abs, *a);
}

/** @brief Euclidean division of a by b
 *
 * Computes quotient, remainder so that remainder+quotient*b = a where 0<=|remainder|<|b|
 * The quotient is rounded towards zero.
 */
void
ibz_div(ibz_t *quotient, ibz_t *remainder, const ibz_t *a, const ibz_t *b)
{
#ifdef DEBUG_VERBOSE
    ibz_t a_cp, b_cp;
    ibz_init(&a_cp);
    ibz_init(&b_cp);
    ibz_copy(&a_cp, a);
    ibz_copy(&b_cp, b);
#endif
    mpz_tdiv_qr(*quotient, *remainder, *a, *b);
#ifdef DEBUG_VERBOSE
    DEBUG_STR_FUN_4("ibz_div", *quotient, *remainder, a_cp, b_cp);
    ibz_finalize(&a_cp);
    ibz_finalize(&b_cp);
#endif
}

/** @brief Euclidean division of a by b
 *
 * Computes quotient, remainder so that remainder+quotient*b = a where 0<=|remainder|<|b|
 * The quotient is rounded towards minus infinity.
 */
void
ibz_div_floor(ibz_t *q, ibz_t *r, const ibz_t *n, const ibz_t *d)
{
    mpz_fdiv_qr(*q, *r, *n, *d);
}

/** @brief Euclidean division of a by 2^exp
 *
 * Computes a right shift of abs(a) by exp bits, then sets sign(quotient) to sign(a)
 */
void
ibz_div_2exp(ibz_t *quotient, const ibz_t *a, uint64_t exp)
{
#ifdef DEBUG_VERBOSE
    ibz_t a_cp;
    ibz_init(&a_cp);
    ibz_copy(&a_cp, a);
#endif
    mpz_tdiv_q_2exp(*quotient, *a, exp);
#ifdef DEBUG_VERBOSE
    gmp_printf("ibz_div_2exp,%Zx,%Zx,%lx\n", *quotient, a_cp, exp);
    ibz_finalize(&a_cp);
#endif
}

/** @brief r = a mod b
 *
 * Assumes valid inputs
 * The sign of the divisor is ignored, the result is always non-negative
 */
void
ibz_mod(ibz_t *r, const ibz_t *a, const ibz_t *b)
{
    mpz_mod(*r, *a, *b);
}

unsigned long int
ibz_mod_ui(const mpz_t *n, unsigned long int d)
{
    return mpz_fdiv_ui(*n, d);
}

/** @brief Test if a = 0 mod b
 */
int
ibz_divides(const ibz_t *a, const ibz_t *b)
{
    return mpz_divisible_p(*a, *b);
}

/** @brief pow=x^e
 *
 * Assumes valid inputs
 */
void
ibz_pow(ibz_t *pow, const ibz_t *x, int64_t e)
{
    mpz_pow_ui(*pow, *x, (unsigned long int)e);
}

/** @brief pow=(x^e) mod m
 */
void
ibz_pow_mod(ibz_t *pow, const ibz_t *x, const ibz_t *e, const ibz_t *m)
{
    mpz_powm(*pow, *x, *e, *m);
    DEBUG_STR_FUN_4("ibz_pow_mod", *pow, *x, *e, *m);
}

/** @brief Compare a and b
 *
 * @returns a positive value if a > b, zero if a = b, and a negative value if a < b
 */
int
ibz_cmp(const ibz_t *a, const ibz_t *b)
{
    int ret = mpz_cmp(*a, *b);
    DEBUG_STR_FUN_INT_MP2("ibz_cmp", ret, *a, *b);
    return ret;
}

/** @brief Test if x is 0
 *
 * @returns 1 if x=0, 0 otherwise
 */
int
ibz_is_zero(const ibz_t *x)
{
    int ret = !mpz_cmp_ui(*x, 0);
    DEBUG_STR_FUN_INT_MP("ibz_is_zero", ret, *x);
    return ret;
}

/** @brief Test if x is 1
 *
 * @returns 1 if x=1, 0 otherwise
 */
int
ibz_is_one(const ibz_t *x)
{
    int ret = !mpz_cmp_ui(*x, 1);
    DEBUG_STR_FUN_INT_MP("ibz_is_one", ret, *x);
    return ret;
}

/** @brief Test if x is even
 *
 * @returns 1 if x is even, 0 otherwise
 */
int
ibz_is_even(const ibz_t *x)
{
    int ret = !mpz_tstbit(*x, 0);
    DEBUG_STR_FUN_INT_MP("ibz_is_even", ret, *x);
    return ret;
}

/** @brief set i to value x
 */
void
ibz_set(ibz_t *i, int64_t x)
{
    mpz_set_si(*i, (signed long int)x);
}

/** @brief set i to integer ontained in string when read as number in base
 *
 * Base should be 10 or 16, and the number should be written without ponctuation or whitespaces
 *
 * Case for base 16 does not matter
 *
 * @returns  1 if the string could be converted to an integer, 0 otherwise
 */
int
ibz_set_from_str(ibz_t *i, const char *str, int base)
{
    return (1 + mpz_set_str(*i, str, base));
}

/** @brief Copy value into target
 */
void
ibz_copy(ibz_t *target, const ibz_t *value)
{
    mpz_set(*target, *value);
}

/** @brief Exchange values of a and b
 */
void
ibz_swap(ibz_t *a, ibz_t *b)
{
    mpz_swap(*a, *b);
}

/** @brief get long equal to the lowest bits of i
 */
int64_t
ibz_get(const ibz_t *i)
{
    return (int64_t)mpz_get_si(*i);
}

int ibz_rand_interval_with_state(ibz_t *rand, const ibz_t *a, const ibz_t *b, pike_xof_ctx_t *state) {
    mpz_t tmp, bmina;
    mpz_init(bmina);
    mpz_sub(bmina, *b, *a);
    
    size_t len_bits = mpz_sizeinbase(bmina, 2);
    size_t len_bytes = (len_bits + 7) / 8;
    size_t sizeof_limb = sizeof(mp_limb_t);
    size_t sizeof_limb_bits = sizeof_limb * 8;
    size_t len_limbs = (len_bytes + sizeof_limb - 1) / sizeof_limb;

    size_t remaining_limb_bits = len_bits % sizeof_limb_bits;
    mp_limb_t mask = remaining_limb_bits == 0 ? (mp_limb_t)-1 : ((mp_limb_t)-1) >> (sizeof_limb_bits - remaining_limb_bits);
    mp_limb_t r[len_limbs];
    
    do {
        pike_xof_stream_squeeze(state, (unsigned char*)r, len_bytes);

        r[len_limbs - 1] &= mask;
        mpz_roinit_n(tmp, r, len_limbs);
        if (mpz_cmp(tmp, bmina) <= 0)
            break;
    } while (1);

    mpz_add(*rand, tmp, *a);
    mpz_clear(bmina);
    return 1;
}

/** @brief generate random value in [a, b] with rejection sampling
 *  @returns 0 if random generation failed, 1 if it succeeded
 */
int
ibz_rand_interval(ibz_t *rand, const ibz_t *a, const ibz_t *b)
{
    // TODO: do it with a hash stream?
    int randret;
    int ret = 1;
    mpz_t tmp;
    mpz_t bmina;
    mpz_init(bmina);
    mpz_sub(bmina, *b, *a);

    size_t len_bits = mpz_sizeinbase(bmina, 2);
    size_t len_bytes = (len_bits + 7) / 8;
    size_t sizeof_limb = sizeof(mp_limb_t);
    size_t sizeof_limb_bits = sizeof_limb * 8;
    size_t len_limbs = (len_bytes + sizeof_limb - 1) / sizeof_limb;

    mp_limb_t mask = ((mp_limb_t)-1) >> (sizeof_limb_bits - (len_bits % sizeof_limb_bits));
    mp_limb_t r[len_limbs];

    do {
        randret = randombytes((unsigned char *)r, len_bytes);
        if (randret != 0) {
            ret = 0;
            goto err;
        }
#ifdef TARGET_BIG_ENDIAN
        for (int i = 0; i < len_limbs; ++i)
            r[i] = BSWAP_DIGIT(r[i]);
#endif
        r[len_limbs - 1] &= mask;
        mpz_roinit_n(tmp, r, len_limbs);
        if (mpz_cmp(tmp, bmina) <= 0)
            break;
    } while (1);

    mpz_add(*rand, tmp, *a);
err:
    mpz_clear(bmina);
    return ret;
}

int
ibz_rand_interval_i(ibz_t *rand, int64_t a, int64_t b)
{
    int ret = 1;
    mpz_t a_big, b_big;
    mpz_init_set_si(a_big, a);
    mpz_init_set_si(b_big, b);
    ret = ibz_rand_interval(rand, &a_big, &b_big);
    mpz_clear(a_big);
    mpz_clear(b_big);
    return ret;
}

int
ibz_rand_interval_minm_m(ibz_t *rand, int64_t m)
{
    int ret = 1;
    ret = ibz_rand_interval_i(rand, 0, 2 * m);
    if (ret != 1)
        goto err;
    mpz_sub_ui(*rand, *rand, (unsigned long int)m);
err:
    return ret;
}

/** @brief Bitsize of a.
 *
 *  @returns Bitsize of a.
 *
 */
int
ibz_bitsize(const ibz_t *a)
{
    return (int)mpz_sizeinbase(*a, 2);
}

/* etc....*/

/** @}
 */

/** @defgroup ibz_qa Basic fraction arithmetic
 * @{
 */

/** @brief sum=a+b
 */
void
ibq_add(ibq_t *sum, const ibq_t *a, const ibq_t *b)
{
    mpq_add(*sum, *a, *b);
}

/** @brief diff=a-b
 */
void
ibq_sub(ibq_t *diff, const ibq_t *a, const ibq_t *b)
{
    mpq_sub(*diff, *a, *b);
}

/** @brief neg=-x
 */
void
ibq_neg(ibq_t *neg, const ibq_t *x)
{
    mpq_neg(*neg, *x);
}

/** @brief abs=|x|
 */
void
ibq_abs(ibq_t *abs, const ibq_t *x)
{
    mpq_abs(*abs, *x);
}

/** @brief prod=a*b
 */
void
ibq_mul(ibq_t *prod, const ibq_t *a, const ibq_t *b)
{
    mpq_mul(*prod, *a, *b);
}

/** @brief inv=1/x
 *
 * @returns 0 if x is 0, 1 if inverse exists and was computed
 */
int
ibq_inv(ibq_t *inv, const ibq_t *x)
{
    if (mpq_cmp_ui(*x, 0, 1)) {
        mpq_inv(*inv, *x);
        return 1;
    } else {
        return 0;
    }
}

/** @brief quot = a/b
 * @param quot Output a/b
 * @param a
 * @param b must not be 0
 */
void
ibq_div(ibq_t *quot, const ibq_t *a, const ibq_t *b)
{
    mpq_div(*quot, *a, *b);
}

/** @brief Compare a and b
 *
 * @returns a positive value if a > b, zero if a = b, and a negative value if a < b
 */
int
ibq_cmp(const ibq_t *a, const ibq_t *b)
{
    return mpq_cmp(*a, *b);
}

/** @brief Test if x is 0
 *
 * @returns 1 if x=0, 0 otherwise
 */
int
ibq_is_zero(const ibq_t *x)
{
    return !mpq_cmp_ui(*x, 0, 1);
}

/** @brief Test if x is 1
 *
 * @returns 1 if x=1, 0 otherwise
 */
int
ibq_is_one(const ibq_t *x)
{
    return !mpq_cmp_ui(*x, 1, 1);
}

/** @brief Set q to a/b if b not 0
 *
 * @returns 1 if b not 0 and q is set, 0 otherwise
 */
int
ibq_set(ibq_t *q, const ibz_t *a, const ibz_t *b)
{
    if (mpz_cmp_si(*b, 0)) {
        mpq_set_num(*q, *a);
        mpq_set_den(*q, *b);
        mpq_canonicalize(*q);
        return 1;
    } else {
        return 0;
    }
}

/** @brief Copy value into target
 */
void
ibq_copy(ibq_t *target, const ibq_t *value)
{
    mpq_set(*target, *value);
}

/** @brief Exchange values of a and b
 */
void
ibq_swap(ibq_t *a, ibq_t *b)
{
    mpq_swap(*a, *b);
}

/** @brief Copy dig array to target, given digits and the length of the dig array
 *
 *  @param target Target ibz_t element
 *  @param dig array of digits
 *  @param dig_len length of the digits array
 */
void
ibz_copy_digits(ibz_t *target, const digit_t *dig, int dig_len)
{
    mpz_t tmp, tmp2;
    assert(sizeof(mp_limb_t) <= sizeof(digit_t));
    if (sizeof(mp_limb_t) == sizeof(digit_t)) {
        mpz_roinit_n(tmp, (const mp_limb_t *)dig, dig_len);
        mpz_set(*target, tmp);
    } else {
        // type size mismatch, we populate the mpz_t with gmp's public interface taking 'unsigned
        // long int'
        mpz_init(tmp);
        mpz_init(tmp2);
        int sizeof_uli = sizeof(unsigned long int);
        int sizeof_digit_t = sizeof(digit_t);
        int uli_for_digs = (sizeof_digit_t + sizeof_uli - 1) / sizeof_uli;
        mpz_set_ui(tmp, 0);
        for (int i = 0; i < dig_len; ++i) {
            digit_t d = dig[i];
            for (int j = 0; j < uli_for_digs; ++j) {
                mpz_set_ui(tmp2, (unsigned long int)d);
                mpz_mul_2exp(tmp2, tmp2, j * sizeof_uli * 8 + i * sizeof_digit_t * 8);
                mpz_add(tmp, tmp, tmp2);
                d >>= (sizeof_uli * 8);
            }
        }
        mpz_set(*target, tmp);
        mpz_clear(tmp);
        mpz_clear(tmp2);
    }
}

/** @brief Copy an ibz_t to target digit_t array.
 *  Restrictions: ibz >= 0 and target must hold sufficient elements to hold ibz
 *
 *  @param target Target digit_t array
 *  @param ibz ibz source ibz_t element
 */
void
ibz_to_digits(digit_t *target, const ibz_t *ibz)
{
    assert(sizeof(mp_limb_t) <= sizeof(digit_t));
    size_t ibz_limbs = mpz_size(*ibz);
    if (ibz_limbs == 0) {
        target[0] = 0;
    } else {
        if (sizeof(mp_limb_t) == sizeof(digit_t)) {
            const mp_limb_t *limbs = mpz_limbs_read(*ibz);
            for (int i = 0; i < ibz_limbs; ++i) {
                target[i] = limbs[i];
            }
        } else {
            mpz_t tmp;
            mpz_init_set(tmp, *ibz);
            int sizeof_digit_t = sizeof(digit_t);
            int sizeof_limb = sizeof(mp_limb_t);
            int digit_len = (ibz_limbs * sizeof_limb + sizeof_digit_t - 1) / sizeof_digit_t;
            for (int i = 0; i < digit_len; ++i) {
                target[i] = 0;
                for (int j = 0; j < (sizeof_digit_t + sizeof_limb - 1) / sizeof_limb; ++j) {
                    target[i] |= ((digit_t)mpz_getlimbn(tmp, j)) << (j * 8 * sizeof_limb);
                }
                mpz_div_2exp(tmp, tmp, sizeof_digit_t * 8);
            }
            mpz_clear(tmp);
        }
    }
}

/** @brief Denominator of x
 */
void
ibq_denom(ibz_t *d, const ibq_t *x)
{
    mpq_get_den(*d, *x);
}

/** @brief Numerator of x
 */
void
ibq_num(ibz_t *n, const ibq_t *x)
{
    mpq_get_num(*n, *x);
}

/** @brief Checks if x is an integer
 *
 * @returns 1 if yes, 0 if not
 */
int
ibq_is_ibz(const ibq_t *q)
{
    mpz_t num, den;
    int ret;
    mpz_init(num);
    mpz_init(den);

    mpq_get_num(num, *q);
    mpq_get_den(den, *q);

    ret = (mpz_divisible_p(num, den) == 0 ? 0 : 1);

    mpz_clear(num);
    mpz_clear(den);
    return ret;
}

/**
 * @brief Converts a fraction q to an integer y, if q is an integer.
 *
 * @returns 1 if z is an integer, 0 if not
 */
int
ibq_to_ibz(ibz_t *z, const ibq_t *q)
{
    mpz_t num, den;
    int ret;
    mpz_init(num);
    mpz_init(den);

    mpq_get_num(num, *q);
    mpq_get_den(den, *q);

    ret = (mpz_divisible_p(num, den) == 0 ? 0 : 1);

    if (!ret)
        goto err;

    mpz_divexact(*z, num, den);

err:
    mpz_clear(num);
    mpz_clear(den);
    return ret;
}

/** @}
 */

/** @defgroup ibz_n Number theory functions
 * @{
 */

/**
 * @brief Probabilistic primality test
 *
 * @param n The number to test
 * @param reps Number of Miller-Rabin repetitions. The more, the slower and the less likely are
 * false positives
 * @return 1 if probably prime, 0 if certainly not prime, 2 if certainly prime
 *
 * Using GMP's implementation:
 *
 * From GMP's documentation: "This function performs some trial divisions, a Baillie-PSW probable
 * prime test, then reps-24 Miller-Rabin probabilistic primality tests."
 */
int
ibz_probab_prime(const ibz_t *n, int reps)
{
    int ret = mpz_probab_prime_p(*n, reps);
    DEBUG_STR_FUN_INT_MP_INT("ibz_probab_prime", ret, *n, reps);
    return ret;
}

/**
 * @brief Greatest common divisor
 *
 * @param gcd Output: Set to the gcd of a and b
 * @param a
 * @param b
 */
void
ibz_gcd(ibz_t *gcd, const ibz_t *a, const ibz_t *b)
{
    mpz_gcd(*gcd, *a, *b);
}

/**
 * @brief GCD and Bézout coefficients u, v such that ua + bv = gcd
 *
 * @param gcd Output: Set to the gcd of a and b
 * @param u Output: integer such that ua+bv=gcd
 * @param v Output: Integer such that ua+bv=gcd
 * @param a
 * @param b
 */
void
ibz_xgcd(ibz_t *gcd, ibz_t *u, ibz_t *v, const ibz_t *a, const ibz_t *b)
{
    mpz_gcdext(*gcd, *u, *v, *a, *b);
}

/**
 * @brief GCD, Bézout coefficients u, v such that ua + bv = gcd, and annihilators s, t such that sa
 * + bt = 0
 *
 * @param gcd Output: Set to the gcd of a and b
 * @param s Output: integer such that sa+bt=0
 * @param t Output: Integer such that sa+bt=0
 * @param u Output: integer such that ua+bv=gcd
 * @param v Output: Integer such that ua+bv=gcd
 * @param a
 * @param b
 */
void
ibz_xgcd_ann(ibz_t *gcd, ibz_t *s, ibz_t *t, ibz_t *u, ibz_t *v, const ibz_t *a, const ibz_t *b)
{
    ibz_t thrash;
    ibz_init(&thrash);
    ibz_xgcd(gcd, u, v, a, b);
    ibz_div(s, &thrash, b, gcd);
    ibz_neg(t, a);
    ibz_div(t, &thrash, t, gcd);
    ibz_finalize(&thrash);
}

/**
 * @brief Modular inverse
 *
 * @param inv Output: Set to the integer in [0,mod[ such that a*inv = 1 mod (mod) if it exists
 * @param a
 * @param mod
 * @returns 1 if inverse exists and was computed, 0 otherwise
 */
int
ibz_invmod(ibz_t *inv, const ibz_t *a, const ibz_t *mod)
{
    return (mpz_invert(*inv, *a, *mod) ? 1 : 0);
}

/**
 * @brief Calculates CRT with a system of two congruences, using Extended Euclidean.
 *
 * @param crt Output: Set so that crt = a mod (mod_a), crt = b mod (mod_b)
 * @param a
 * @param b
 * @param mod_a
 * @param mod_b
 */
void
ibz_crt(ibz_t *crt, const ibz_t *a, const ibz_t *b, const ibz_t *mod_a, const ibz_t *mod_b)
{
    mpz_t tmp, u, v;
    mpz_init(tmp);
    mpz_init(u);
    mpz_init(v);
    mpz_gcdext(tmp, u, v, *mod_a, *mod_b);

    mpz_mul(tmp, *a, v);
    mpz_mul(tmp, tmp, *mod_b);

    mpz_mul(u, *b, u);
    mpz_mul(u, u, *mod_a);

    mpz_add(tmp, tmp, u);

    mpz_mul(v, *mod_a, *mod_b);

    mpz_mod(*crt, tmp, v);

    mpz_clear(tmp);
    mpz_clear(u);
    mpz_clear(v);
}

/**
 * @brief Kronecker symbol of a mod b
 *
 * @returns Kronecker symbol of a mod b
 * @param a
 * @param b
 *
 * Uses GMP's implementation
 */
int
ibz_kronecker(const ibz_t *a, const ibz_t *b)
{
    return mpz_kronecker(*a, *b);
}

/**
 * @brief Jacobi symbol of a mod odd
 *
 * @returns jacobi symbol of a mod odd
 * @param a
 * @param odd assumed odd
 *
 * Uses GMP's implementation
 *
 * If output is -1, a is a not a square mod odd
 */
int
ibz_jacobi(const ibz_t *a, const ibz_t *odd)
{
    return mpz_jacobi(*a, *odd);
}

/**
 * @brief Legendre symbol of a mod p
 *
 * @returns Legendre symbol of a mod p
 * @param a
 * @param p assumed prime
 *
 * Uses GMP's implementation
 *
 * If output is 1, a is a square mod p, if -1, not. If 0, it is divisible by p
 */
int
ibz_legendre(const ibz_t *a, const ibz_t *p)
{
    return mpz_legendre(*a, *p);
}

/**
 * @brief Integer square root of a perfect square
 *
 * @returns 1 if an integer square root of a exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a integer square root of a if any exist
 * @param a number of which an integer square root is searched
 */
int
ibz_sqrt(ibz_t *sqrt, const ibz_t *a)
{
    if (mpz_perfect_square_p(*a)) {
        mpz_sqrt(*sqrt, *a);
        return 1;
    } else {
        return 0;
    }
}

/**
 * @brief Floor of Integer square root
 *
 * @param sqrt Output: Set to the floor of an integer square root
 * @param a number of which a floor of an integer square root is searched
 */
void
ibz_sqrt_floor(ibz_t *sqrt, const ibz_t *a)
{
    mpz_sqrt(*sqrt, *a);
}

/**
 * @brief Square root modulo a prime
 *
 * We handle two special cases separately:
 * - p mod 4 == 3
 * - p mod 8 == 5
 *
 * Otherwise (if p mod 8 == 1), we apply the Shanks-Tonelli algorithm
 * to find the square root.
 *
 * @returns 1 if square root of a mod p exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a square root of a mod p if any exist
 * @param a number of which a square root mod p is searched
 * @param p assumed prime
 */
int
ibz_sqrt_mod_p(ibz_t *sqrt, const ibz_t *a, const ibz_t *p)
{
    // TODO: handle special cases, a = 0?

#ifndef NDEBUG
    assert(ibz_probab_prime(p, 100));
#endif

#ifdef DEBUG_VERBOSE
    ibz_t a_cp, p_cp;
    ibz_init(&a_cp);
    ibz_init(&p_cp);
    ibz_copy(&a_cp, a);
    ibz_copy(&p_cp, p);
#endif

    mpz_t amod, tmp, exp, a4, a2, n, q, z, qnr, x, y, b, pm1;
    mpz_init(amod);
    mpz_init(tmp);
    mpz_init(exp);
    mpz_init(a4);
    mpz_init(a2);
    mpz_init(n);
    mpz_init(q);
    mpz_init(z);
    mpz_init(qnr);
    mpz_init(x);
    mpz_init(y);
    mpz_init(b);
    mpz_init(pm1);

    int ret = 1;

    mpz_mod(amod, *a, *p);
    if (mpz_cmp_ui(amod, 0) < 0) {
        mpz_add(amod, *p, amod);
    }

    if (mpz_jacobi(amod, *p) != 1) {
        ret = 0;
        goto end;
    }

    mpz_sub_ui(pm1, *p, 1);

    if (mpz_mod_ui(tmp, *p, 4) == 3) {
        // p % 4 == 3
        mpz_add_ui(tmp, *p, 1);
        mpz_fdiv_q_2exp(tmp, tmp, 2);
        mpz_powm(*sqrt, amod, tmp, *p);
    } else if (mpz_mod_ui(tmp, *p, 8) == 5) {
        // p % 8 == 5
        mpz_sub_ui(tmp, *p, 1);
        mpz_fdiv_q_2exp(tmp, tmp, 2);
        mpz_powm(tmp, amod, tmp, *p); // a^{(p-1)/4} mod p
        if (!mpz_cmp_ui(tmp, 1)) {
            mpz_add_ui(tmp, *p, 3);
            mpz_fdiv_q_2exp(tmp, tmp, 3);
            mpz_powm(*sqrt, amod, tmp, *p); // a^{(p+3)/8} mod p
        } else {
            mpz_sub_ui(tmp, *p, 5);
            mpz_fdiv_q_2exp(tmp, tmp, 3); // (p - 5) / 8
            mpz_mul_2exp(a4, amod, 2);    // 4*a
            mpz_powm(tmp, a4, tmp, *p);

            mpz_mul_2exp(a2, amod, 1);
            mpz_mul(tmp, a2, tmp);
            mpz_mod(*sqrt, tmp, *p);
        }
    } else {
        // p % 8 == 1 -> Shanks-Tonelli
        int e = 0;
        mpz_sub_ui(q, *p, 1);
        while (mpz_tstbit(q, e) == 0)
            e++;
        mpz_fdiv_q_2exp(q, q, e);

        // 1. find generator - non-quadratic residue
        mpz_set_ui(n, 2);
        while (mpz_legendre(qnr, *p) != -1)
            mpz_add_ui(qnr, qnr, 1);
        mpz_powm(z, qnr, q, *p);

        // 2. Initialize
        mpz_set(y, z);
        int r = e;
        mpz_powm(y, amod, q, *p); // y = a^q mod p

        mpz_add_ui(tmp, q, 1); // tmp = (q + 1) / 2
        mpz_fdiv_q_2exp(tmp, tmp, 1);

        mpz_powm(x, amod, tmp, *p); // x = a^(q + 1)/2 mod p

        mpz_set_ui(exp, 1);
        mpz_mul_2exp(exp, exp, e - 2);

        for (int i = 0; i < e; ++i) {
            mpz_powm(b, y, exp, *p);

            if (!mpz_cmp(b, pm1)) {
                mpz_mul(x, x, z);
                mpz_mod(x, x, *p);

                mpz_mul(y, y, z);
                mpz_mul(y, y, z);
                mpz_mod(y, y, *p);
            }

            mpz_powm_ui(z, z, 2, *p);
            mpz_fdiv_q_2exp(exp, exp, 1);
        }

        mpz_set(*sqrt, x);
    }

#ifdef DEBUG_VERBOSE
    DEBUG_STR_FUN_3("ibz_sqrt_mod_p", *sqrt, a_cp, p_cp);
    ibz_finalize(&a_cp);
    ibz_finalize(&p_cp);
#endif

end:
    mpz_clear(amod);
    mpz_clear(tmp);
    mpz_clear(exp);
    mpz_clear(a4);
    mpz_clear(a2);
    mpz_clear(n);
    mpz_clear(q);
    mpz_clear(z);
    mpz_clear(qnr);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(b);
    mpz_clear(pm1);

    return ret;
}

/**
 * @brief Square root modulo a the double of a given prime
 *
 * If sqrt(a) mod p is odd -> outputs sqrt(a) (mod 2p)
 * Otherwise -> outputs sqrt(x) + p (mod 2p)
 *
 * @returns 1 if square root of a mod (2p) exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a square root of a mod (2p) if any exist
 * @param a number of which a square root mod (2p) is searched
 * @param p assumed prime
 */
int
ibz_sqrt_mod_2p(ibz_t *sqrt, const ibz_t *a, const ibz_t *p)
{
    int ret = 1;
    mpz_t sqrt_modp;
    mpz_init(sqrt_modp);

    ret = ibz_sqrt_mod_p(&sqrt_modp, a, p);
    if (ret == 0)
        goto err;

    if (mpz_tstbit(*a, 0) != mpz_tstbit(sqrt_modp, 0))
        mpz_add(*sqrt, sqrt_modp, *p);
    else
        mpz_set(*sqrt, sqrt_modp);

    DEBUG_STR_FUN_3("ibz_sqrt_mod_2p", *sqrt, *a, *p);
err:
    mpz_clear(sqrt_modp);
    return ret;
}

/**
 * @brief Square root modulo 2power
 * outputs sqrt(a) (mod 2power)
 *
 * @returns 1 if square root exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a square root if any exist
 * @param a number of which a square root is searched
 * @param e assumed power
 */
int ibz_sqrt_mod_2e(ibz_t *sqrt, const ibz_t *a, int e)
{
    ibz_t x_squared, N, x;
    ibz_init(&x_squared);
    ibz_init(&x);
    ibz_init(&N);


    ibz_set(&N, 8); // 8 = 2^3
    ibz_set(&x, 1);

    // Compute sqrt_mod (sqrt_mod = sqrt(n) mod 2^e)
    for (int i = 4; i <= e; i++) {
        // N <<= 1
        ibz_mul_2exp(&N, &N, 1);

        // Compute (x^2 - n) % N 
        ibz_mul(&x_squared, &x, &x);
        ibz_sub(&x_squared, &x_squared, a);
        ibz_mod(&x_squared, &x_squared, &N);

        if (!ibz_is_zero(&x_squared)) {
            // x += N / 4 
            ibz_t quarter_N;
            ibz_init(&quarter_N);
            ibz_div_2exp(&quarter_N, &N, 2);
            ibz_add(&x, &x, &quarter_N);
            ibz_finalize(&quarter_N);
        }

    }

    // 将结果赋给 sqrt
    ibz_copy(sqrt, &x);

    ibz_finalize(&x_squared);
    ibz_finalize(&x);
    ibz_finalize(&N);

    return 0;
}
